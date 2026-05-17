import type { Context, MiddlewareHandler } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import {
  handleRegistration,
  handleRefresh,
  issueChallenge,
  buildChallengeHeader,
  readSessionResponseHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  NoopRateLimiter,
  emit,
  DbscProtocolError,
  DbscVerificationError,
  type DbscOptions,
  type ProtectionTier,
} from "../core/index.js";

const BOUND_COOKIE = "__Host-dbsc-session";
const REGISTRATION_COOKIE = "__Host-dbsc-reg";
const CHALLENGE_COOKIE = "__Host-dbsc-challenge";

const DEFAULT_BOUND_TTL = 10 * 60;

export interface DbscHonoOptions extends DbscOptions {
  secure?: boolean;
}

declare module "hono" {
  interface ContextVariableMap {
    dbscSessionId: string | null;
    dbscTier: ProtectionTier;
  }
}

export function dbsc(opts: DbscHonoOptions): MiddlewareHandler {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL * 1000,
    rateLimiter = new NoopRateLimiter(),
    onEvent,
    secure = true,
  } = opts;

  const cookieOpts = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
  };

  return async (c: Context, next) => {
    const url = new URL(c.req.url);
    const ip = c.req.header("x-forwarded-for") ?? "unknown";

    if (c.req.method === "POST" && url.pathname === registrationPath) {
      const sessionId = getCookie(c, REGISTRATION_COOKIE);
      const expectedJti = getCookie(c, CHALLENGE_COOKIE);

      if (!sessionId || !expectedJti) {
        return c.json({ error: "missing session or challenge cookie" }, 400);
      }

      const allowed = await rateLimiter.checkRegistration(ip);
      if (!allowed) return c.json({ error: "rate limited" }, 429);

      try {
        const respHdr = c.req.header("secure-session-response") ?? c.req.header("sec-session-response");
        await handleRegistration(
          {
            sessionId,
            secSessionResponseHeader: respHdr,
            expectedJti,
          },
          storage,
        );

        emit(onEvent, {
          type: "registration",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          algorithm: "ES256",
          ip,
        });

        setCookie(c, BOUND_COOKIE, sessionId, {
          ...cookieOpts,
          maxAge: boundCookieTtl / 1000,
        });
        deleteCookie(c, CHALLENGE_COOKIE);
        return c.json(
          {
            session_identifier: sessionId,
            refresh_url: refreshPath,
            scope: { include_site: true },
            credentials: [
              {
                type: "cookie",
                name: BOUND_COOKIE,
                attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(boundCookieTtl / 1000)}`,
              },
            ],
          },
          200,
        );
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          return c.json({ error: err.message }, 400);
        }
        throw err;
      }
    }

    if (c.req.method === "POST" && url.pathname === refreshPath) {
      const sessionIdHeader = c.req.header("sec-secure-session-id");
      const sessionId = sessionIdHeader ?? getCookie(c, BOUND_COOKIE);

      if (!sessionId) return c.body(null, 403);

      const allowed = await rateLimiter.checkRefresh(ip, sessionId);
      if (!allowed) return c.json({ error: "rate limited" }, 429);

      const responseHeader = c.req.header("secure-session-response") ?? c.req.header("sec-session-response");

      if (!responseHeader) {
        const challenge = await issueChallenge(sessionId, storage);
        c.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        c.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        setCookie(c, CHALLENGE_COOKIE, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
        return c.body(null, 403);
      }

      const expectedJti = getCookie(c, CHALLENGE_COOKIE);
      if (!expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        c.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        c.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        setCookie(c, CHALLENGE_COOKIE, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
        return c.body(null, 403);
      }

      try {
        await handleRefresh({ sessionId, secSessionResponseHeader: responseHeader, expectedJti }, storage);

        emit(onEvent, {
          type: "refresh",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          ip,
        });

        setCookie(c, BOUND_COOKIE, sessionId, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
        deleteCookie(c, CHALLENGE_COOKIE);
        return c.json(
          {
            session_identifier: sessionId,
            refresh_url: refreshPath,
            scope: { include_site: true },
            credentials: [
              {
                type: "cookie",
                name: BOUND_COOKIE,
                attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(boundCookieTtl / 1000)}`,
              },
            ],
          },
          200,
        );
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          return c.json({ error: err.message }, 401);
        }
        throw err;
      }
    }

    const sessionId = getCookie(c, BOUND_COOKIE) ?? null;
    c.set("dbscSessionId", sessionId);
    c.set("dbscTier", "none");

    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl;
        if (session.tier === "dbsc" && Date.now() > staleAfter) {
          c.set("dbscTier", "none");
        } else {
          c.set("dbscTier", session.tier);
        }
      }
    }

    await next();
  };
}
