import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import { deriveSessionId } from "../core/index.js";
import {
  createDbscMiddleware,
  bindSession,
  getDbscSession,
  type DbscNextOptions,
  type DbscSessionInfo,
} from "./index.js";
import { requireProof, type RequireProofSession, type RequireProofResult } from "./require-proof.js";

export interface CreateDbscOptions extends DbscNextOptions {
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
}

export interface BindOptions {
  userId: string;
  /** Distinct value per device for separate bindings. */
  deviceHint?: string;
  /** Namespace to scope derived ids. */
  namespace?: string;
}

export interface DbscKit {
  /** The Edge middleware for `middleware.ts`. */
  middleware(): (req: NextRequest) => Promise<NextResponse>;
  /** Start a binding. Pass a sessionId, or omit it to derive one from `userId`. */
  bind(res: NextResponse, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: NextResponse, opts: BindOptions): Promise<string>;
  /** Read the DBSC session inside a route handler. */
  getSession(req: NextRequest, res?: NextResponse): Promise<DbscSessionInfo>;
  /** The route guard. Storage is taken from the kit config. */
  requireProof(req: NextRequest, session: RequireProofSession): Promise<RequireProofResult>;
}

/**
 * Builds a configured DBSC kit for Next.js. There is no `install()` — Next has
 * no app object; export `middleware()` from `middleware.ts` and call the rest
 * inside route handlers.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? true;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const mw = createDbscMiddleware(opts);

  async function bind(res: NextResponse, a: string | BindOptions, b?: BindOptions): Promise<string> {
    const bindOpts = typeof a === "string" ? (b as BindOptions) : a;
    const sessionId =
      typeof a === "string"
        ? a
        : await deriveSessionId({
            userId: bindOpts.userId,
            ...(bindOpts.deviceHint !== undefined && { deviceHint: bindOpts.deviceHint }),
            ...(bindOpts.namespace !== undefined && { namespace: bindOpts.namespace }),
          });
    await bindSession(res, sessionId, opts.storage, {
      userId: bindOpts.userId,
      secure,
      registrationPath,
      ...(opts.registrationCookieTtl !== undefined && {
        registrationCookieTtl: opts.registrationCookieTtl,
      }),
      ...(opts.sessionTtl !== undefined && { sessionTtl: opts.sessionTtl }),
    });
    return sessionId;
  }

  return {
    middleware: () => mw,
    bind,
    getSession: (req: NextRequest, res?: NextResponse) =>
      getDbscSession(req, opts.storage, {
        ...(opts.boundCookieTtl !== undefined && { boundCookieTtl: opts.boundCookieTtl }),
        ...(opts.refreshGraceMs !== undefined && { refreshGraceMs: opts.refreshGraceMs }),
        ...(res !== undefined && { res }),
        secure,
      }),
    requireProof: (req: NextRequest, session: RequireProofSession) =>
      requireProof(req, session, { storage: opts.storage }),
  };
}
