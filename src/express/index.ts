import type { Request, Response, NextFunction, RequestHandler } from "express";
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
  maybeEmitPolyfillMissing,
  parseCookieHeader,
  resolveCookieNames,
  cookieAttributesString,
  resolveCookieScope,
  DbscProtocolError,
  DbscVerificationError,
  ErrorCodes,
  type DbscOptions,
  type StorageAdapter,
  type ProofReplayCache,
  type ProtectionTier,
  type SkippedEntry,
  type CookieScope,
} from "../core/index.js";

export { requireBoundProof } from "./proof.js";
export type { RequireBoundProofOptions } from "./proof.js";
export { requireProof } from "./require-proof.js";
export { createDbsc } from "./create-dbsc.js";
export type { CreateDbscOptions, DbscKit, BindOptions } from "./create-dbsc.js";

/** Internal carrier so `requireProof()` can reach storage without re-passing it. */
export interface DbscInternal {
  storage: StorageAdapter;
  secure: boolean;
  /**
   * Whether the bound polyfill is enabled. When false, `requireProof()`
   * auto-relaxes: a native `dbsc`-tier session passes without a per-request
   * bound proof (there is no bound key to verify against).
   */
  boundEnabled: boolean;
  /** v2.8+: optional replay cache; undefined → no replay check (Noop). */
  replayCache?: ProofReplayCache;
}
export const DBSC_INTERNAL: unique symbol = Symbol("dbsc-toolkit.express.internal");

interface ScopeArgs {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

const cookieNames = (s: ScopeArgs) => resolveCookieNames(s);

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

function cookieOpts(ttlMs: number, scope: ScopeArgs) {
  const { domain } = resolveCookieScope(scope);
  return {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "lax" as const,
    maxAge: ttlMs / 1000,
    path: "/",
    ...(domain !== undefined && { domain }),
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
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  return parts.join("; ");
}

export interface BindSessionOptions {
  userId: string;
  /** Match the value passed to dbsc({ secure }). Defaults true. Mismatch = cookies the middleware cannot read. */
  secure?: boolean;
  /** Match the value passed to dbsc({ cookieScope }). Defaults "host". */
  cookieScope?: CookieScope;
  /** Match the value passed to dbsc({ cookieDomain }). Required for cookieScope: "site". */
  cookieDomain?: string;
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
  const scope: ScopeArgs = {
    secure,
    ...(opts.cookieScope !== undefined && { cookieScope: opts.cookieScope }),
    ...(opts.cookieDomain !== undefined && { cookieDomain: opts.cookieDomain }),
  };
  const COOKIES = cookieNames(scope);

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
    registrationPath,
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
    serializeCookie(COOKIES.reg, sessionId, cookieOpts(regCookieTtl, scope)),
    serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, scope)),
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
    bound = true,
    boundCookieTtl = DEFAULT_BOUND_TTL,
    refreshGraceMs = 30_000,
    registrationCookieTtl = DEFAULT_REG_TTL,
    rateLimiter = new NoopRateLimiter(),
    replayCache,
    onEvent,
    autoBind,
    secure = true,
    cookieScope,
    cookieDomain,
  } = opts;

  const scope: ScopeArgs = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };
  // Fail-fast: rejects "site" without domain, mismatched secure flag, etc.
  resolveCookieScope(scope);
  const cookieAttrs = cookieAttributesString(scope);
  const COOKIES = cookieNames(scope);
  // Per-middleware-instance dedup set for the polyfill_missing telemetry event.
  // Re-armed on process restart, which is fine: the signal is for ops alerting,
  // not for security enforcement.
  const polyfillMissingEmitted = new Set<string>();

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
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)),
        serializeCookie(COOKIES.challenge, "", { ...cookieOpts(0, scope), maxAge: 0 }),
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
            attributes: cookieAttrs,
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
        serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, scope)),
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
        serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, scope)),
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
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)),
        serializeCookie(COOKIES.challenge, "", { ...cookieOpts(0, scope), maxAge: 0 }),
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
            attributes: cookieAttrs,
          },
        ],
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);

      const stolenCheck = await storage.getBoundKey(sessionId);
      if (stolenCheck && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
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
        const challenge = await issueChallenge(sessionId, storage);
        res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.setHeader(
          "Set-Cookie",
          serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, scope)),
        );
        res.status(403).json({ error: err.message });
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
    res.setHeader("X-Server-Time", String(Date.now()));
    const skipped = parseSessionSkippedHeader(req.headers as Record<string, string | string[] | undefined>);
    const nativeSkipped = skipped.length ? skipped.map((s) => s.reason) : undefined;
    const sessionId = readBoundSessionId(req);
    if (!sessionId) {
      res.status(200).json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
      return;
    }
    const session = await storage.getSession(sessionId);
    if (!session) {
      res.status(200).json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
      return;
    }
    const nativeKey = await storage.getBoundKey(sessionId, "native");
    const boundKey = await storage.getBoundKey(sessionId, "bound");
    if (!nativeKey && !boundKey) {
      const challenge = await issueChallenge(sessionId, storage);
      res.status(200).json({
        phase: "needs-registration",
        sessionId,
        challenge: challenge.jti,
        ...(nativeSkipped && { nativeSkipped }),
      });
      return;
    }
    // v2.7: a native-bound (dbsc) session also needs a polyfill key so
    // requireProof() has something to verify on every request. Tell the
    // client to register one — the session stays tier="dbsc" throughout.
    if (nativeKey && !boundKey) {
      const challenge = await issueChallenge(sessionId, storage);
      res.status(200).json({
        phase: "needs-bound-registration",
        sessionId,
        tier: session.tier,
        challenge: challenge.jti,
        refreshIntervalMs: boundCookieTtl,
        ...(nativeSkipped && { nativeSkipped }),
      });
      return;
    }
    res.status(200).json({
      phase: "bound",
      sessionId,
      tier: session.tier,
      refreshIntervalMs: boundCookieTtl,
      ...(nativeSkipped && { nativeSkipped }),
    });
  }

  async function handleBoundChallengeRoute(req: Request, res: Response): Promise<void> {
    res.setHeader("X-Server-Time", String(Date.now()));
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
    res.setHeader("X-Server-Time", String(Date.now()));
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
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)),
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
    res.setHeader("X-Server-Time", String(Date.now()));
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
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)),
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
    if (!req.cookies) {
      req.cookies = parseCookieHeader(req.headers.cookie);
    }

    if (req.method === "POST" && req.path === registrationPath) {
      await handleRegistrationRoute(req, res);
      return;
    }

    if (req.method === "POST" && req.path === refreshPath) {
      await handleRefreshRoute(req, res);
      return;
    }

    // When the bound polyfill is disabled, the state route still answers so the
    // client SDK stands down cleanly (phase "unbound"); the other three bound
    // routes are simply not served.
    if (req.method === "GET" && req.path === boundStatePath) {
      if (bound) {
        await handleBoundStateRoute(req, res);
      } else {
        res.setHeader("X-Server-Time", String(Date.now()));
        res.status(200).json({ phase: "unbound", sessionId: null });
      }
      return;
    }

    if (bound) {
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
          serializeCookie(COOKIES.bound, "", { ...cookieOpts(0, scope), maxAge: 0 }),
        ]);
      },
    };
    (res.locals as Record<PropertyKey, unknown>)[DBSC_INTERNAL] = {
      storage,
      secure,
      boundEnabled: bound,
      ...(replayCache !== undefined && { replayCache }),
    } satisfies DbscInternal;

    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl + refreshGraceMs;
        const refreshable = session.tier === "dbsc" || session.tier === "bound";
        if (refreshable && Date.now() > staleAfter) {
          res.locals.dbsc.tier = "none";
        } else {
          res.locals.dbsc.tier = session.tier;
        }
        if (onEvent) {
          await maybeEmitPolyfillMissing({
            storage,
            session,
            ip: req.ip ?? "unknown",
            emitted: polyfillMissingEmitted,
            onEvent,
          });
        }
      }
    } else if (autoBind && !(req.cookies?.[COOKIES.reg])) {
      const result = await autoBind(req);
      if (result) {
        await bindSession(res, result.sessionId, storage, {
          userId: result.userId,
          secure,
          ...(cookieScope !== undefined && { cookieScope }),
          ...(cookieDomain !== undefined && { cookieDomain }),
          registrationPath,
          registrationCookieTtl,
        });
      }
    }

    next();
  };
}
