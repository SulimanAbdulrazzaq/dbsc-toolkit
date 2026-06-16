import type { IncomingMessage, ServerResponse } from "node:http";
import { type RequireProofOptions } from "../core/index.js";
import {
  dbsc,
  bindSession,
  getDbscSession,
  type DbscNodeOptions,
  type DbscNodeHandler,
  type DbscNodeSession,
} from "./index.js";
import { requireProof, type NodeProofGuard } from "./require-proof.js";
import { requireDpop, type NodeDpopGuard } from "./require-dpop.js";
import type { RequireDpopOptions } from "../core/dpop/index.js";

export interface CreateDbscOptions extends DbscNodeOptions {
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  namespace?: string;
}

export interface DbscKit {
  /** The dbsc handler — run it first in your request pipeline. Returns true when it answered a protocol route. */
  handler(): DbscNodeHandler;
  /** Read the resolved session off a request the handler has processed. */
  getSession(req: IncomingMessage): DbscNodeSession | undefined;
  /** Start a binding for an explicit session id (e.g. your server-session id). */
  bind(res: ServerResponse, sessionId: string, opts: BindOptions): Promise<string>;
  /** The route guard — requires a bound device + a per-request proof. */
  requireProof(opts?: RequireProofOptions): NodeProofGuard;
  /** DPoP (RFC 9449) route guard for token-bound API calls. Optional layer. */
  requireDpop(opts?: RequireDpopOptions<IncomingMessage>): NodeDpopGuard;
}

/**
 * Builds a configured DBSC kit for raw `node:http`. There is no `install()`
 * because raw http has no router — wire `handler()` at the top of your request
 * listener and branch on its boolean return.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? true;
  const cookieScope = opts.cookieScope;
  const cookieDomain = opts.cookieDomain;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const handler = dbsc(opts);

  async function bind(res: ServerResponse, sessionId: string, bindOpts: BindOptions): Promise<string> {
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

  return {
    handler: () => handler,
    getSession: getDbscSession,
    bind,
    requireProof,
    requireDpop,
  };
}
