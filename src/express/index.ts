import type { Request, Response, NextFunction, RequestHandler } from "express";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import {
  handleRegistration,
  handleRefresh,
  issueChallenge,
  buildRegistrationHeader,
  buildChallengeHeader,
  readSessionResponseHeader,
  REGISTRATION_HEADER,
  CHALLENGE_HEADER,
  LEGACY_REGISTRATION_HEADER,
  LEGACY_CHALLENGE_HEADER,
  NoopRateLimiter,
  emit,
  DbscProtocolError,
  DbscVerificationError,
  ErrorCodes,
  type DbscOptions,
  type Session,
  type ProtectionTier,
} from "../core/index.js";

const cookieNames = (secure: boolean) => ({
  bound: secure ? "__Host-dbsc-session" : "dbsc-session",
  reg: secure ? "__Host-dbsc-reg" : "dbsc-reg",
  challenge: secure ? "__Host-dbsc-challenge" : "dbsc-challenge",
});

const DEFAULT_BOUND_TTL = 10 * 60 * 1000;
const DEFAULT_REG_TTL = 24 * 60 * 60 * 1000;

export interface DbscExpressOptions extends DbscOptions {
  secure?: boolean;
}

export interface DbscLocals {
  sessionId: string | null;
  tier: ProtectionTier;
  revoke: () => Promise<void>;
  requireBound: () => void;
}

declare global {
  namespace Express {
    interface Locals {
      dbsc: DbscLocals;
    }
  }
}

function cookieOpts(ttlMs: number, secure: boolean) {
  return {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    maxAge: ttlMs / 1000,
    path: "/",
  };
}

function serializeCookie(name: string, value: string, opts: ReturnType<typeof cookieOpts>): string {
  const parts = [`${name}=${value}`];
  parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  const sameSite = opts.sameSite.charAt(0).toUpperCase() + opts.sameSite.slice(1);
  parts.push(`SameSite=${sameSite}`);
  parts.push(`Max-Age=${opts.maxAge}`);
  parts.push(`Path=${opts.path}`);
  return parts.join("; ");
}

export function dbsc(opts: DbscExpressOptions): RequestHandler {
  const {
    storage,
    fallback = "webauthn",
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL,
    registrationCookieTtl = DEFAULT_REG_TTL,
    rateLimiter = new NoopRateLimiter(),
    onEvent,
    secure = true,
  } = opts;

  const hmacSecret = nodeRandomBytes(32);
  const COOKIES = cookieNames(secure);

  async function handleRegistrationRoute(req: Request, res: Response): Promise<void> {
    const ip = req.ip ?? "unknown";
    const allowed = await rateLimiter.checkRegistration(ip);
    if (!allowed) {
      res.status(429).json({ error: "rate limited" });
      return;
    }

    const sessionId = req.cookies?.[COOKIES.reg] as string | undefined;
    const expectedJti = req.cookies?.[COOKIES.challenge] as string | undefined;

    if (!sessionId || !expectedJti) {
      res.status(400).json({ error: "missing session or challenge cookie" });
      return;
    }

    try {
      await handleRegistration(
        {
          sessionId,
          secSessionResponseHeader: readSessionResponseHeader(req.headers as Record<string, string | string[] | undefined>),
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

      res.setHeader("Set-Cookie", [
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, secure)),
        serializeCookie(COOKIES.challenge, "", { ...cookieOpts(0, secure), maxAge: 0 }),
      ]);
      res.setHeader("Content-Type", "application/json");
      res.status(200).json({
        session_identifier: sessionId,
        refresh_url: refreshPath,
        scope: { include_site: true },
        credentials: [
          {
            type: "cookie",
            name: COOKIES.bound,
            attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(boundCookieTtl / 1000)}`,
          },
        ],
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);

      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, {
          type: "verification_failure",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          reason: err.code,
          ip,
        });
        res.status(400).json({ error: err.message });
        return;
      }
      throw err;
    }
  }

  async function handleRefreshRoute(req: Request, res: Response): Promise<void> {
    const ip = req.ip ?? "unknown";
    const sessionIdHeader = req.headers["sec-secure-session-id"];
    const sessionId = (Array.isArray(sessionIdHeader) ? sessionIdHeader[0] : sessionIdHeader)
      ?? (req.cookies?.[COOKIES.bound] as string | undefined);

    if (!sessionId) {
      res.status(403).end();
      return;
    }

    const allowed = await rateLimiter.checkRefresh(ip, sessionId);
    if (!allowed) {
      res.status(429).json({ error: "rate limited" });
      return;
    }

    const responseHeader = readSessionResponseHeader(req.headers as Record<string, string | string[] | undefined>);

    if (!responseHeader) {
      const challenge = await issueChallenge(sessionId, storage);
      res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
      res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
      res.setHeader(
        "Set-Cookie",
        serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, secure)),
      );
      res.status(403).end();
      return;
    }

    const expectedJti = req.cookies?.[COOKIES.challenge] as string | undefined;
    if (!expectedJti) {
      const challenge = await issueChallenge(sessionId, storage);
      res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
      res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
      res.setHeader(
        "Set-Cookie",
        serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, secure)),
      );
      res.status(403).end();
      return;
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

      res.setHeader("Set-Cookie", [
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, secure)),
        serializeCookie(COOKIES.challenge, "", { ...cookieOpts(0, secure), maxAge: 0 }),
      ]);
      res.setHeader("Content-Type", "application/json");
      res.status(200).json({
        session_identifier: sessionId,
        refresh_url: refreshPath,
        scope: { include_site: true },
        credentials: [
          {
            type: "cookie",
            name: COOKIES.bound,
            attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(boundCookieTtl / 1000)}`,
          },
        ],
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);

      const stolenCheck = await storage.getBoundKey(sessionId);
      if (stolenCheck) {
        emit(onEvent, {
          type: "session_stolen",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          ip,
        });
      }

      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, {
          type: "verification_failure",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          reason: (err as DbscVerificationError).code,
          ip,
        });
        res.status(401).json({ error: err.message });
        return;
      }
      throw err;
    }
  }

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (req.method === "POST" && req.path === registrationPath) {
      await handleRegistrationRoute(req, res);
      return;
    }

    if (req.method === "POST" && req.path === refreshPath) {
      await handleRefreshRoute(req, res);
      return;
    }

    const sessionId = req.cookies?.[COOKIES.bound] as string | undefined;

    res.locals.dbsc = {
      sessionId: sessionId ?? null,
      tier: "none",
      revoke: async () => {
        if (sessionId) await storage.revokeSession(sessionId);
        res.setHeader("Set-Cookie", [
          serializeCookie(COOKIES.bound, "", { ...cookieOpts(0, secure), maxAge: 0 }),
        ]);
      },
      requireBound: () => {
        if (!sessionId) {
          res.status(401).json({ error: "authentication required" });
          throw new Error("unauthenticated");
        }
      },
    };

    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl;
        if (session.tier === "dbsc" && Date.now() > staleAfter) {
          res.locals.dbsc.tier = "none";
        } else {
          res.locals.dbsc.tier = session.tier;
        }
      }
    }

    next();
  };
}

