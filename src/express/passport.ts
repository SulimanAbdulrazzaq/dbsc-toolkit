import type { Request } from "express";
import type { KitSessionBinding } from "../core/index.js";

/** The parts of express-session + Passport this preset reads. */
interface SessionRequest {
  sessionID?: string;
  user?: unknown;
  session?: Record<string, unknown> & { dbscLoginAt?: number };
}

export interface PassportPresetOptions {
  /** Picks the user id from `req.user`. Default: `user.id`. */
  userId?: (user: unknown) => string | null | undefined;
}

function defaultUserId(user: unknown): string | null {
  const id = (user as { id?: unknown } | null | undefined)?.id;
  return id === undefined || id === null ? null : String(id);
}

/**
 * Settings for apps on express-session + Passport. Spread into `createDbsc()`
 * and the login route needs no DBSC code at all:
 *
 *   const dbsc = createDbsc({ storage, ...passportSession() });
 *   app.use(session(...));
 *   app.use(passport.session());
 *   dbsc.install(app);               // after the session middleware
 *
 * The binding uses `req.sessionID` (Passport regenerates it on login) and
 * starts on the first request that carries the new login. The login time is
 * recorded in the session as `dbscLoginAt` the first time the kit sees it.
 */
export function passportSession(opts: PassportPresetOptions = {}): KitSessionBinding<Request> {
  const pickUser = opts.userId ?? defaultUserId;
  const read = (req: Request): SessionRequest => req as unknown as SessionRequest;
  return {
    expectSessionId: (req) => read(req).sessionID ?? null,
    bindOnLogin: {
      userId: (req) => {
        const user = read(req).user;
        return user === undefined || user === null ? null : pickUser(user);
      },
      loginAt: (req) => {
        const r = read(req);
        if (!r.session || r.user === undefined || r.user === null) return null;
        // Passport regenerates the session on login, so a session without
        // the stamp is a login the kit has not seen yet.
        r.session.dbscLoginAt ??= Date.now();
        return r.session.dbscLoginAt;
      },
    },
  };
}
