import type { Request, Response, NextFunction, RequestHandler } from "express";
import { randomBytes as nodeRandomBytes } from "node:crypto";
import {
  handleRegistration,
  handleRefresh,
  handleBoundRegistration,
  handleBoundRefresh,
  issueChallenge,
  buildRegistrationHeader,
  buildChallengeHeader,
  readSessionResponseHeader,
  parseSessionSkippedHeader,
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
  type StorageAdapter,
  type Session,
  type ProtectionTier,
  type SkippedEntry,
  type AutoBindResult,
} from "../core/index.js";

const cookieNames = (secure: boolean) => ({
  bound: secure ? "__Host-dbsc-session" : "dbsc-session",
  reg: secure ? "__Host-dbsc-reg" : "dbsc-reg",
  challenge: secure ? "__Host-dbsc-challenge" : "dbsc-challenge",
});

const DEFAULT_BOUND_TTL = 10 * 60 * 1000;
const DEFAULT_REG_TTL = 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL = 24 * 60 * 60 * 1000;

export interface DbscExpressOptions extends DbscOptions {
  secure?: boolean;
  boundStatePath?: string;
  boundChallengePath?: string;
  boundRegistrationPath?: string;
  boundRefreshPath?: string;
}

export interface DbscLocals {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
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

export interface BindSessionOptions {
  userId: string;
  secure?: boolean;
  registrationPath?: string;
  registrationCookieTtl?: number;
  sessionTtl?: number;
}

export async function bindSession(
  res: Response,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void> {
  const secure = opts.secure ?? true;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const regCookieTtl = opts.registrationCookieTtl ?? DEFAULT_REG_TTL;
  const sessionTtl = opts.sessionTtl ?? DEFAULT_SESSION_TTL;
  const COOKIES = cookieNames(secure);

  const existing = await storage.getSession(sessionId);
  const now = Date.now();
  if (!existing) {
    await storage.setSession({
      id: sessionId,
      userId: opts.userId,
      tier: "none",
      createdAt: now,
      expiresAt: now + sessionTtl,
      lastRefreshAt: 0,
    });
  }

  const challenge = await issueChallenge(sessionId, storage);
  const regHeader = buildRegistrationHeader({
    refreshPath: registrationPath,
    challenge: challenge.jti,
    cookieName: COOKIES.bound,
  });

  res.setHeader(REGISTRATION_HEADER, regHeader);
  res.setHeader(LEGACY_REGISTRATION_HEADER, regHeader);

  const prior = res.getHeader("Set-Cookie");
  const priorList: string[] = Array.isArray(prior)
    ? prior.map(String)
    : prior !== undefined
      ? [String(prior)]
      : [];
  res.setHeader("Set-Cookie", [
    ...priorList,
    serializeCookie(COOKIES.reg, sessionId, cookieOpts(regCookieTtl, secure)),
    serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, secure)),
  ]);
}

export function dbsc(opts: DbscExpressOptions): RequestHandler {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundStatePath = "/dbsc-bound/state",
    boundChallengePath = "/dbsc-bound/challenge",
    boundRegistrationPath = "/dbsc-bound/registration",
    boundRefreshPath = "/dbsc-bound/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL,
    registrationCookieTtl = DEFAULT_REG_TTL,
    rateLimiter = new NoopRateLimiter(),
    onEvent,
    autoBind,
    secure = true,
  } = opts;

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
      const origin = `${req.protocol}://${req.get("host")}`;
      res.status(200).json({
        session_identifier: sessionId,
        refresh_url: refreshPath,
        scope: {
          origin,
          include_site: true,
          scope_specification: [],
        },
        credentials: [
          {
            type: "cookie",
            name: COOKIES.bound,
            attributes: "Path=/; Secure; HttpOnly; SameSite=Lax",
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
      res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
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
      res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
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
      const origin = `${req.protocol}://${req.get("host")}`;
      res.status(200).json({
        session_identifier: sessionId,
        refresh_url: refreshPath,
        scope: {
          origin,
          include_site: true,
          scope_specification: [],
        },
        credentials: [
          {
            type: "cookie",
            name: COOKIES.bound,
            attributes: "Path=/; Secure; HttpOnly; SameSite=Lax",
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

  function readBoundSessionId(req: Request): string | undefined {
    return (req.cookies?.[COOKIES.bound]
      ?? req.cookies?.[COOKIES.reg]) as string | undefined;
  }

  async function handleBoundStateRoute(req: Request, res: Response): Promise<void> {
    const sessionId = readBoundSessionId(req);
    if (!sessionId) {
      res.status(200).json({ phase: "unbound", sessionId: null });
      return;
    }
    const session = await storage.getSession(sessionId);
    if (!session) {
      res.status(200).json({ phase: "unbound", sessionId: null });
      return;
    }
    const key = await storage.getBoundKey(sessionId);
    if (!key) {
      const challenge = await issueChallenge(sessionId, storage);
      res.status(200).json({
        phase: "needs-registration",
        sessionId,
        challenge: challenge.jti,
      });
      return;
    }
    res.status(200).json({
      phase: "bound",
      sessionId,
      tier: session.tier,
      refreshIntervalMs: boundCookieTtl,
    });
  }

  async function handleBoundChallengeRoute(req: Request, res: Response): Promise<void> {
    const sessionId = readBoundSessionId(req);
    if (!sessionId) {
      res.status(403).json({ error: "no session" });
      return;
    }
    const session = await storage.getSession(sessionId);
    if (!session) {
      res.status(403).json({ error: "no session" });
      return;
    }
    const challenge = await issueChallenge(sessionId, storage);
    res.status(200).json({ challenge: challenge.jti });
  }

  async function handleBoundRegistrationRoute(req: Request, res: Response): Promise<void> {
    const ip = req.ip ?? "unknown";
    const allowed = await rateLimiter.checkRegistration(ip);
    if (!allowed) {
      res.status(429).json({ error: "rate limited" });
      return;
    }

    const sessionId = readBoundSessionId(req);
    if (!sessionId) {
      res.status(400).json({ error: "missing session cookie" });
      return;
    }

    const body = (req.body ?? {}) as { publicKey?: JsonWebKey; signature?: string; challenge?: string };
    if (!body.publicKey || !body.signature || !body.challenge) {
      res.status(400).json({ error: "publicKey, signature, and challenge are required in JSON body" });
      return;
    }

    try {
      await handleBoundRegistration(
        {
          sessionId,
          publicKey: body.publicKey,
          signature: body.signature,
          expectedJti: body.challenge,
        },
        storage,
      );

      emit(onEvent, {
        type: "registration",
        sessionId,
        tier: "bound",
        timestamp: Date.now(),
        algorithm: "ES256",
        ip,
      });

      res.setHeader("Set-Cookie", [
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, secure)),
      ]);
      res.status(200).json({
        session_identifier: sessionId,
        refresh_url: boundRefreshPath,
        tier: "bound",
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, {
          type: "verification_failure",
          sessionId,
          tier: "bound",
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

  async function handleBoundRefreshRoute(req: Request, res: Response): Promise<void> {
    const ip = req.ip ?? "unknown";
    const sessionId = readBoundSessionId(req);
    if (!sessionId) {
      res.status(403).json({ error: "no session" });
      return;
    }

    const allowed = await rateLimiter.checkRefresh(ip, sessionId);
    if (!allowed) {
      res.status(429).json({ error: "rate limited" });
      return;
    }

    const body = (req.body ?? {}) as { challenge?: string; signature?: string; timestamp?: number };
    if (!body.challenge || !body.signature || typeof body.timestamp !== "number") {
      res.status(400).json({ error: "challenge, signature, and timestamp are required" });
      return;
    }

    try {
      await handleBoundRefresh(
        {
          sessionId,
          signature: body.signature,
          expectedJti: body.challenge,
          timestamp: body.timestamp,
        },
        storage,
      );

      emit(onEvent, {
        type: "refresh",
        sessionId,
        tier: "bound",
        timestamp: Date.now(),
        ip,
      });

      res.setHeader("Set-Cookie", [
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, secure)),
      ]);
      res.status(200).json({
        session_identifier: sessionId,
        refresh_url: boundRefreshPath,
        tier: "bound",
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);

      const keyStillThere = await storage.getBoundKey(sessionId);
      if (keyStillThere && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
        emit(onEvent, {
          type: "session_stolen",
          sessionId,
          tier: "bound",
          timestamp: Date.now(),
          ip,
        });
      }

      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, {
          type: "verification_failure",
          sessionId,
          tier: "bound",
          timestamp: Date.now(),
          reason: err.code,
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

    if (req.method === "GET" && req.path === boundStatePath) {
      await handleBoundStateRoute(req, res);
      return;
    }

    if (req.method === "GET" && req.path === boundChallengePath) {
      await handleBoundChallengeRoute(req, res);
      return;
    }

    if (req.method === "POST" && req.path === boundRegistrationPath) {
      await handleBoundRegistrationRoute(req, res);
      return;
    }

    if (req.method === "POST" && req.path === boundRefreshPath) {
      await handleBoundRefreshRoute(req, res);
      return;
    }

    const sessionId = req.cookies?.[COOKIES.bound] as string | undefined;
    const skipped = parseSessionSkippedHeader(req.headers as Record<string, string | string[] | undefined>);

    res.locals.dbsc = {
      sessionId: sessionId ?? null,
      tier: "none",
      skipped,
      revoke: async () => {
        if (sessionId) await storage.revokeSession(sessionId);
        res.setHeader("Set-Cookie", [
          serializeCookie(COOKIES.bound, "", { ...cookieOpts(0, secure), maxAge: 0 }),
        ]);
      },
    };

    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl;
        const refreshable = session.tier === "dbsc" || session.tier === "bound";
        if (refreshable && Date.now() > staleAfter) {
          res.locals.dbsc.tier = "none";
        } else {
          res.locals.dbsc.tier = session.tier;
        }
      }
    } else if (autoBind && !(req.cookies?.[COOKIES.reg])) {
      const result = await autoBind(req);
      if (result) {
        await bindSession(res, result.sessionId, storage, {
          userId: result.userId,
          secure,
          registrationPath,
          registrationCookieTtl,
        });
      }
    }

    next();
  };
}
