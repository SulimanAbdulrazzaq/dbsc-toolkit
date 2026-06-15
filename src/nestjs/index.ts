import {
  Injectable,
  Module,
  Inject,
  ForbiddenException,
  InternalServerErrorException,
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
  DbscVerificationError,
  type RequireProofOptions,
} from "../core/index.js";
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
