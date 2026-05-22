import express, { type Express, type Response, type RequestHandler } from "express";
import { fileURLToPath } from "node:url";
import { deriveSessionId, type RequireProofOptions } from "../core/index.js";
import { dbsc, bindSession, type DbscExpressOptions } from "./index.js";
import { requireProof } from "./require-proof.js";

export interface CreateDbscOptions extends DbscExpressOptions {
  /** Mount path for the static client SDK. Default "/dbsc-client". `false` skips it. */
  clientPath?: string | false;
  /** Default session TTL (ms) for `bind()`. */
  sessionTtl?: number;
  /** Let `install()` set `trust proxy`. Default true. */
  trustProxy?: boolean;
}

export interface BindOptions {
  userId: string;
  /** Distinct value per device for separate bindings (the "active sessions" pattern). */
  deviceHint?: string;
  /** Namespace to scope derived ids. */
  namespace?: string;
}

export interface DbscKit {
  /** Mount the whole DBSC surface on the app: middleware, bound-route JSON, client SDK. */
  install(app: Express): Express;
  /** The raw `dbsc()` middleware, for manual mounting. */
  middleware(): RequestHandler;
  /** Start a binding. Pass a sessionId, or omit it to derive one from `userId` (JWT apps). */
  bind(res: Response, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: Response, opts: BindOptions): Promise<string>;
  /** The route guard — requires a bound device + a per-request proof. */
  requireProof(opts?: RequireProofOptions): RequestHandler;
}

/**
 * Builds a configured DBSC kit. Storage, `secure`, TTLs, rate limiter and
 * telemetry are set once here; `install()`, `bind()` and `requireProof()` all
 * read this config — nothing is re-passed.
 */
export function createDbsc(opts: CreateDbscOptions): DbscKit {
  const secure = opts.secure ?? true;
  const clientPath = opts.clientPath ?? "/dbsc-client";
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const boundRegistrationPath = opts.boundRegistrationPath ?? "/dbsc-bound/registration";
  const boundRefreshPath = opts.boundRefreshPath ?? "/dbsc-bound/refresh";
  const middleware = dbsc(opts);

  async function bind(res: Response, a: string | BindOptions, b?: BindOptions): Promise<string> {
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
    middleware: () => middleware,
    install(app: Express): Express {
      if (opts.trustProxy !== false) app.set("trust proxy", true);
      const json = express.json();
      app.use(boundRegistrationPath, json);
      app.use(boundRefreshPath, json);
      app.use(middleware);
      if (clientPath !== false) {
        const clientDir = fileURLToPath(new URL("../client/", import.meta.url));
        app.use(clientPath, express.static(clientDir));
      }
      return app;
    },
    bind,
    requireProof,
  };
}
