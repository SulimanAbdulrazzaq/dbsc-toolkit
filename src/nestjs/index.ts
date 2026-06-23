import {
  Injectable,
  Module,
  Inject,
  ForbiddenException,
  InternalServerErrorException,
  UnauthorizedException,
  type DynamicModule,
  type NestModule,
  type MiddlewareConsumer,
  type CanActivate,
  type ExecutionContext,
} from "@nestjs/common";
import type { Request, Response } from "express";
import {
  verifyBoundProof,
  noBindingReason,
  guardNativeProof,
  freshProofActive,
  challengeCookieName,
  FRESH_PROOF_CHALLENGE_TTL_MS,
  readSessionResponseHeader,
  buildChallengeHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  DbscVerificationError,
  type RequireProofOptions,
  type CookieScope,
} from "../core/index.js";
import {
  runDpopGuard,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "../core/dpop/index.js";
import {
  dbsc,
  createDbsc,
  DBSC_INTERNAL,
  type DbscExpressOptions,
  type DbscInternal,
  type DbscKit,
  type BindOptions,
} from "../express/index.js";

export { bindSession } from "../express/index.js";
export type { DbscExpressOptions as DbscNestOptions, BindOptions } from "../express/index.js";

/** DI token for the DBSC options passed to `DbscModule.forRoot()`. */
export const DBSC_OPTIONS = Symbol("dbsc-toolkit.nestjs.options");

/** Injectable wrapper around the Express kit's `bind()` — call it in your login controller. */
@Injectable()
export class DbscService {
  private readonly kit: DbscKit;
  constructor(@Inject(DBSC_OPTIONS) opts: DbscExpressOptions) {
    this.kit = createDbsc(opts);
  }
  /** Start a binding for an explicit session id. */
  bind(res: Response, sessionId: string, opts: BindOptions): Promise<string> {
    return this.kit.bind(res, sessionId, opts);
  }
}

/**
 * Registers DBSC on a NestJS app (Express platform). It mounts the protocol
 * middleware for every route and exposes `DbscService`:
 *
 *   @Module({ imports: [DbscModule.forRoot({ storage })] })
 *   export class AppModule {}
 */
@Module({})
export class DbscModule implements NestModule {
  constructor(@Inject(DBSC_OPTIONS) private readonly opts: DbscExpressOptions) {}

  static forRoot(opts: DbscExpressOptions): DynamicModule {
    return {
      module: DbscModule,
      global: true,
      providers: [{ provide: DBSC_OPTIONS, useValue: opts }, DbscService],
      exports: [DBSC_OPTIONS, DbscService],
    };
  }

  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(dbsc(this.opts)).forRoutes("*");
  }
}

async function runNativeFreshProof(
  req: Request,
  res: Response,
  sessionId: string,
  storage: NonNullable<RequireProofOptions["storage"]>,
  internal: DbscInternal | undefined,
): Promise<void> {
  const scope: { secure: boolean; cookieScope?: CookieScope; cookieDomain?: string } = {
    secure: internal?.secure ?? true,
    ...(internal?.cookieScope !== undefined && { cookieScope: internal.cookieScope }),
    ...(internal?.cookieDomain !== undefined && { cookieDomain: internal.cookieDomain }),
  };
  const cookieName = challengeCookieName(scope);
  const responseHeader = readSessionResponseHeader(
    req.headers as Record<string, string | string[] | undefined>,
  );
  const expectedJti = (req.cookies as Record<string, string> | undefined)?.[cookieName];

  const result = await guardNativeProof(
    { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
    storage,
  );

  if (result.kind === "pass") return;
  if (result.kind === "reject") {
    throw new ForbiddenException({ error: result.error, code: result.code });
  }
  // Pre-set the challenge header + cookie on res, then throw 403 — Nest's filter
  // keeps headers already written.
  const header = buildChallengeHeader(result.jti, sessionId);
  res.setHeader(CHALLENGE_HEADER, header);
  res.setHeader(LEGACY_CHALLENGE_HEADER, header);
  res.cookie(cookieName, result.jti, {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "lax",
    path: "/",
    maxAge: FRESH_PROOF_CHALLENGE_TTL_MS,
    ...(scope.cookieDomain !== undefined && { domain: scope.cookieDomain }),
  });
  throw new ForbiddenException();
}

async function runProof(req: Request, res: Response, opts: RequireProofOptions): Promise<void> {
  const dbscLocals = res.locals.dbsc;
  const tier = dbscLocals?.tier ?? "none";
  const skipped = dbscLocals?.skipped ?? [];
  if (!dbscLocals?.sessionId || tier === "none") {
    throw new ForbiddenException({ error: "device-bound session required", currentTier: "none", reason: noBindingReason(skipped), skipped });
  }

  const internal = (res.locals as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as DbscInternal | undefined;
  const storage = opts.storage ?? internal?.storage;
  if (!storage) {
    throw new InternalServerErrorException("requireProof: storage unavailable — import DbscModule.forRoot(...)");
  }

  if (
    freshProofActive({
      tier,
      boundEnabled: internal?.boundEnabled,
      freshProof: opts.freshProof,
      allowDbscWithoutProof: opts.allowDbscWithoutProof,
    })
  ) {
    await runNativeFreshProof(req, res, dbscLocals.sessionId, storage, internal);
    return;
  }

  const allowDbscWithoutProof =
    opts.allowDbscWithoutProof ?? (internal?.boundEnabled === false ? true : undefined);
  if (tier === "dbsc" && allowDbscWithoutProof) return;

  let bodyBytes: Uint8Array;
  const raw = req.body as unknown;
  if (raw instanceof Buffer) bodyBytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  else if (raw instanceof Uint8Array) bodyBytes = raw;
  else if (typeof raw === "string") bodyBytes = new TextEncoder().encode(raw);
  else bodyBytes = new Uint8Array(0);

  try {
    await verifyBoundProof(
      {
        sessionId: dbscLocals.sessionId,
        proofHeader: req.headers["x-dbsc-bound-proof"] as string | undefined,
        method: req.method,
        path: req.path,
        signBody: true,
        bodyBytes,
        ...(opts.timestampWindowMs !== undefined && { timestampWindowMs: opts.timestampWindowMs }),
        ...(internal?.replayCache !== undefined && { replayCache: internal.replayCache }),
      },
      storage,
    );
  } catch (err) {
    if (err instanceof DbscVerificationError) {
      throw new ForbiddenException({ error: err.message, code: err.code });
    }
    throw err;
  }
}

/**
 * Zero-config route guard. Requires a bound device + a per-request proof:
 *
 *   @UseGuards(DbscGuard)
 *   @Post("payment")
 *   pay() { ... }
 *
 * POST bodies are body-hashed, so a guarded POST must deliver raw bytes (set
 * `rawBody: true` in `NestFactory.create` and disable the JSON parser on that
 * route, or use a raw-body middleware). GET routes need no parser.
 */
@Injectable()
export class DbscGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    await runProof(http.getRequest<Request>(), http.getResponse<Response>(), {});
    return true;
  }
}

/** Builds a guard with options baked in (e.g. a storage override or timestamp window). */
export function createDbscGuard(opts: RequireProofOptions): new () => CanActivate {
  @Injectable()
  class ConfiguredDbscGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const http = context.switchToHttp();
      await runProof(http.getRequest<Request>(), http.getResponse<Response>(), opts);
      return true;
    }
  }
  return ConfiguredDbscGuard;
}

async function runDpop(
  req: Request,
  res: Response,
  opts: RequireDpopOptions<Request>,
): Promise<void> {
  const internal = (res.locals as Record<PropertyKey, unknown>)[DBSC_INTERNAL] as
    | DbscInternal
    | undefined;
  const replayCache = opts.replayCache ?? internal?.replayCache;
  const url = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  const boundJkt = opts.getBoundJkt ? await opts.getBoundJkt(req) : undefined;

  const outcome = await runDpopGuard({
    proof: req.headers["dpop"] as string | undefined,
    authorization: req.headers["authorization"] as string | undefined,
    method: req.method,
    url,
    boundJkt,
    replayCache,
    opts: {
      ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
      ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
    },
  });

  if (!outcome.ok) {
    res.setHeader("WWW-Authenticate", DPOP_WWW_AUTHENTICATE);
    throw new UnauthorizedException({ error: "invalid_dpop_proof", code: outcome.error?.code });
  }
}

/**
 * DPoP (RFC 9449) route guard for NestJS (Express platform). Build it with the
 * token-binding hook, then attach with `@UseGuards`:
 *
 *   @UseGuards(createDbscDpopGuard({ getBoundJkt }))
 *   @Get("resource")
 *   resource() { ... }
 *
 * On failure throws a 401 carrying `WWW-Authenticate: DPoP`.
 */
export function createDbscDpopGuard(
  opts: RequireDpopOptions<Request> = {},
): new () => CanActivate {
  @Injectable()
  class ConfiguredDbscDpopGuard implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const http = context.switchToHttp();
      await runDpop(http.getRequest<Request>(), http.getResponse<Response>(), opts);
      return true;
    }
  }
  return ConfiguredDbscDpopGuard;
}
