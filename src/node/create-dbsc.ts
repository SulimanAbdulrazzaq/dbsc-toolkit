import type { IncomingMessage, ServerResponse } from "node:http";
import { defaultSecure } from "../core/kit.js";
import {
  withKitBinding,
  checkKitSetup,
  clientScriptTag,
  deriveSessionId,
  resolveLoginBinding,
  validatePathPatterns,
  splitProtectOptions,
  isProtected,
  signPrefixes,
  type ProtectOptions,
  type KitSessionBinding,
  type ClientScriptOptions,
  type RequireProofOptions,
} from "../core/index.js";
import {
  dbsc,
  bindSession,
  getDbscSession,
  deviceHintFor,
  type DbscNodeOptions,
  type DbscNodeHandler,
  type DbscNodeSession,
} from "./index.js";
import { requireProof, type NodeProofGuard } from "./require-proof.js";
import { requireDpop, type NodeDpopGuard } from "./require-dpop.js";
import { readClientAsset } from "./client-assets.js";
import type { RequireDpopOptions } from "../core/dpop/index.js";

export interface CreateDbscOptions extends DbscNodeOptions, KitSessionBinding<IncomingMessage> {
  /** Mount path for the browser SDK (`dist/client`). Default "/dbsc-client". `false` skips it. */
  clientPath?: string | false;
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  /**
   * The request, for the no-sessionId (JWT) path: the kit reads or sets a
   * per-device cookie on it so each browser binds independently.
   */
  req?: IncomingMessage;
  /** Manual per-device value; overrides the device cookie. */
  deviceHint?: string;
  /** Namespace to scope derived ids. */
  namespace?: string;
}

export interface DbscKit {
  /** The dbsc handler — run it first in your request pipeline. Returns true when it answered a protocol route. */
  handler(): DbscNodeHandler;
  /** Read the resolved session off a request the handler has processed. */
  getSession(req: IncomingMessage): DbscNodeSession | undefined;
  /** Start a binding. Pass a sessionId, or omit it (and pass `req`) to derive one from `userId`. */
  bind(res: ServerResponse, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: ServerResponse, opts: BindOptions): Promise<string>;
  /**
   * The route guard — requires a bound device + a per-request proof. Uses the
   * kit's `expectSessionId` / `expectUserId` unless the call passes its own.
   */
  requireProof(opts?: RequireProofOptions<IncomingMessage>): NodeProofGuard;
  /** The `<script>` tag that loads the browser side, served by `handler()`. */
  clientScript(opts?: ClientScriptOptions): string;
  /** DPoP (RFC 9449) route guard for token-bound API calls. Optional layer. */
  requireDpop(opts?: RequireDpopOptions<IncomingMessage>): NodeDpopGuard;
  /**
   * `requireProof()` for every request under the given paths. Patterns:
   * `"/api/*"` (everything under `/api/`), `"/account"` (the path and its
   * children), `"*"` (everything). `clientScript()` signs these by default.
   */
  protect(patterns: string[], opts?: ProtectOptions<IncomingMessage>): NodeProofGuard;
}

/**
 * Builds a configured DBSC kit for raw `node:http`. There is no `install()`
 * because raw http has no router — wire `handler()` at the top of your request
 * listener and branch on its boolean return.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? defaultSecure();
  const cookieScope = opts.cookieScope;
  const cookieDomain = opts.cookieDomain;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const handler = dbsc(opts);
  const binding: KitSessionBinding<IncomingMessage> = {
    ...(opts.expectSessionId !== undefined && { expectSessionId: opts.expectSessionId }),
    ...(opts.expectUserId !== undefined && { expectUserId: opts.expectUserId }),
  };
  checkKitSetup({ storage: opts.storage, ...binding });
  const protectedPatterns: string[] = [];

  const scope = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };

  async function bind(res: ServerResponse, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    let sessionId: string;
    if (typeof a === "string") {
      sessionId = a;
    } else {
      const deviceHint =
        bindOpts.deviceHint ?? (bindOpts.req ? deviceHintFor(bindOpts.req, res, scope) : undefined);
      sessionId = await deriveSessionId({
        userId: bindOpts.userId,
        ...(deviceHint !== undefined && { deviceHint }),
        ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
      });
    }
    await bindSession(res, sessionId, opts.storage, {
      userId: bindOpts.userId,
      secure,
      ...(cookieScope !== undefined && { cookieScope }),
      ...(cookieDomain !== undefined && { cookieDomain }),
      registrationPath,
      ...(opts.registrationCookieTtl !== undefined && { registrationCookieTtl: opts.registrationCookieTtl }),
      ...(opts.sessionTtl !== undefined && { sessionTtl: opts.sessionTtl }),
    });
    return sessionId;
  }

  const clientPath = opts.clientPath ?? "/dbsc-client";

  // The browser SDK first, then the protocol routes.
  const withClient: DbscNodeHandler =
    clientPath === false
      ? handler
      : async (req, res) => {
          if (req.method === "GET") {
            const asset = await readClientAsset(new URL(req.url ?? "/", "http://x").pathname, clientPath);
            if (asset) {
              res.setHeader("Content-Type", asset.contentType);
              res.end(asset.body);
              return true;
            }
          }
          return handler(req, res);
        };

  // bindOnLogin runs right after the protocol handler on every app request.
  const withLoginBinding: DbscNodeHandler = opts.bindOnLogin
    ? async (req, res) => {
        if (await withClient(req, res)) return true;
        const plan = await resolveLoginBinding(opts.bindOnLogin!, req, {
          storage: opts.storage,
          ...(binding.expectSessionId !== undefined && { expectSessionId: binding.expectSessionId }),
          deriveSessionId: (userId) => deriveSessionId({ userId, deviceHint: deviceHintFor(req, res, scope) }),
          currentSessionId: getDbscSession(req)?.sessionId ?? null,
          ...(opts.boundRegistrationWindowMs !== undefined && { windowMs: opts.boundRegistrationWindowMs }),
        });
        if (plan) await bind(res, plan.sessionId, { userId: plan.userId });
        return false;
      }
    : withClient;

  return {
    handler: () => withLoginBinding,
    getSession: getDbscSession,
    bind,
    requireProof: (o?: RequireProofOptions<IncomingMessage>) =>
      requireProof(withKitBinding(binding, o)),
    requireDpop,
    protect(patterns: string[], o: ProtectOptions<IncomingMessage> = {}): NodeProofGuard {
      validatePathPatterns(patterns);
      protectedPatterns.push(...patterns);
      const { guard, filter } = splitProtectOptions(o);
      const check = requireProof(withKitBinding(binding, guard));
      return async (req, res) => {
        const pathname = new URL(req.url ?? "/", "http://x").pathname;
        if (!isProtected(pathname, req.method ?? "GET", patterns, filter)) return true;
        return check(req, res);
      };
    },
    clientScript: (o?: ClientScriptOptions) => {
      const sign = signPrefixes(protectedPatterns);
      return clientScriptTag(clientPath === false ? "/dbsc-client" : clientPath, {
        ...(protectedPatterns.length > 0 && sign !== undefined && { sign }),
        ...o,
      });
    },
  };
}
