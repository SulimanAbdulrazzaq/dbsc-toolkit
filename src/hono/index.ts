import type { Context, MiddlewareHandler } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import {
  handleRegistration,
  handleRefresh,
  handleBoundRegistration,
  handleBoundRefresh,
  issueChallenge,
  buildRegistrationHeader,
  buildChallengeHeader,
  parseSessionSkippedHeader,
  REGISTRATION_HEADER,
  CHALLENGE_HEADER,
  LEGACY_REGISTRATION_HEADER,
  LEGACY_CHALLENGE_HEADER,
  NoopRateLimiter,
  emit,
  maybeEmitPolyfillMissing,
  resolveCookieNames,
  resolveCookieScope,
  cookieAttributesString,
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
  replayCache?: ProofReplayCache;
}
export const DBSC_INTERNAL: unique symbol = Symbol("dbsc-toolkit.hono.internal");

interface ScopeArgs {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

const cookieNames = (s: ScopeArgs) => resolveCookieNames(s);

const DEFAULT_BOUND_TTL_MS = 10 * 60 * 1000;
const DEFAULT_REG_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface DbscHonoOptions extends DbscOptions {
  secure?: boolean;
  boundStatePath?: string;
  boundChallengePath?: string;
  boundRegistrationPath?: string;
  boundRefreshPath?: string;
  /**
   * How the adapter derives the client IP used as the rate-limiter key.
   * Hono runs on many runtimes (Node, Bun, Deno, Cloudflare Workers,
   * Vercel) and each exposes the real client IP differently, so the
   * default is intentionally conservative — falls back to the literal
   * string `"unknown"` when no runtime-provided remote address is
   * available rather than silently trusting `X-Forwarded-For` (which a
   * client can spoof end-to-end on a misconfigured proxy chain, defeating
   * IP-keyed rate limiting).
   *
   * Pass a custom extractor for your runtime:
   * - Cloudflare Workers: `(c) => c.req.header("cf-connecting-ip") ?? "unknown"`
   * - Vercel: `(c) => c.req.header("x-real-ip") ?? "unknown"`
   * - Behind a known proxy that strips client-supplied XFF:
   *   `(c) => c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown"`
   *
   * Defaults to a best-effort runtime probe (`c.env.requestIP`, then
   * `c.req.raw.headers.get("cf-connecting-ip")`, then `"unknown"`).
   */
  ipExtractor?: (c: Context) => string;
}

export interface DbscHonoSession {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

declare module "hono" {
  interface ContextVariableMap {
    dbsc: DbscHonoSession;
  }
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
  c: Context,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void> {
  const secure = opts.secure ?? true;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const regCookieTtl = opts.registrationCookieTtl ?? DEFAULT_REG_TTL_MS;
  const sessionTtl = opts.sessionTtl ?? DEFAULT_SESSION_TTL_MS;
  const scope: ScopeArgs = {
    secure,
    ...(opts.cookieScope !== undefined && { cookieScope: opts.cookieScope }),
    ...(opts.cookieDomain !== undefined && { cookieDomain: opts.cookieDomain }),
  };
  const { domain } = resolveCookieScope(scope);

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

  const COOKIES = cookieNames(scope);
  const challenge = await issueChallenge(sessionId, storage);
  const regHeader = buildRegistrationHeader({
    registrationPath,
    challenge: challenge.jti,
    cookieName: COOKIES.bound,
  });

  c.header(REGISTRATION_HEADER, regHeader);
  c.header(LEGACY_REGISTRATION_HEADER, regHeader);

  const cookieBase = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
    ...(domain !== undefined && { domain }),
  };
  setCookie(c, COOKIES.reg, sessionId, { ...cookieBase, maxAge: regCookieTtl / 1000 });
  setCookie(c, COOKIES.challenge, challenge.jti, { ...cookieBase, maxAge: 5 * 60 });
}

export function dbsc(opts: DbscHonoOptions): MiddlewareHandler {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundStatePath = "/dbsc-bound/state",
    boundChallengePath = "/dbsc-bound/challenge",
    boundRegistrationPath = "/dbsc-bound/registration",
    boundRefreshPath = "/dbsc-bound/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL_MS,
    refreshGraceMs = 30_000,
    registrationCookieTtl = DEFAULT_REG_TTL_MS,
    rateLimiter = new NoopRateLimiter(),
    replayCache,
    onEvent,
    autoBind,
    secure = true,
    cookieScope,
    cookieDomain,
    ipExtractor = defaultIpExtractor,
  } = opts;

  const scope: ScopeArgs = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };
  const { domain } = resolveCookieScope(scope);
  const cookieAttrs = cookieAttributesString(scope);

  const cookieOpts = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
    ...(domain !== undefined && { domain }),
  };

  const COOKIES = cookieNames(scope);
  const polyfillMissingEmitted = new Set<string>();

  return async (c: Context, next) => {
    const url = new URL(c.req.url);
    const ip = ipExtractor(c);

    if (c.req.method === "POST" && url.pathname === registrationPath) {
      const sessionId = getCookie(c, COOKIES.reg);
      const expectedJti = getCookie(c, COOKIES.challenge);

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

        setCookie(c, COOKIES.bound, sessionId, {
          ...cookieOpts,
          maxAge: boundCookieTtl / 1000,
        });
        deleteCookie(c, COOKIES.challenge);
        return c.json(
          {
            session_identifier: sessionId,
            refresh_url: refreshPath,
            scope: {
              origin: url.origin,
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
      const sessionId = sessionIdHeader ?? getCookie(c, COOKIES.bound);

      if (!sessionId) return c.body(null, 403);

      const allowed = await rateLimiter.checkRefresh(ip, sessionId);
      if (!allowed) return c.json({ error: "rate limited" }, 429);

      const responseHeader = c.req.header("secure-session-response") ?? c.req.header("sec-session-response");

      if (!responseHeader) {
        const challenge = await issueChallenge(sessionId, storage);
        c.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        c.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        setCookie(c, COOKIES.challenge, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
        return c.body(null, 403);
      }

      const expectedJti = getCookie(c, COOKIES.challenge);
      if (!expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        c.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        c.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        setCookie(c, COOKIES.challenge, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
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

        setCookie(c, COOKIES.bound, sessionId, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
        deleteCookie(c, COOKIES.challenge);
        return c.json(
          {
            session_identifier: sessionId,
            refresh_url: refreshPath,
            scope: {
              origin: url.origin,
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
          },
          200,
        );
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);

        const stolenCheck = await storage.getBoundKey(sessionId);
        if (stolenCheck && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
          emit(onEvent, { type: "session_stolen", sessionId, tier: "dbsc", timestamp: Date.now(), ip });
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
          c.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
          c.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
          setCookie(c, COOKIES.challenge, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
          return c.json({ error: err.message }, 403);
        }
        throw err;
      }
    }

    const readBoundSessionId = (): string | undefined =>
      getCookie(c, COOKIES.bound) ?? getCookie(c, COOKIES.reg);

    if (c.req.method === "GET" && url.pathname === boundStatePath) {
      c.header("X-Server-Time", String(Date.now()));
      const skippedRaw: Record<string, string | undefined> = {
        "secure-session-skipped": c.req.header("secure-session-skipped"),
        "sec-session-skipped": c.req.header("sec-session-skipped"),
      };
      const skipped = parseSessionSkippedHeader(skippedRaw);
      const nativeSkipped = skipped.length ? skipped.map((s) => s.reason) : undefined;
      const sid = readBoundSessionId();
      if (!sid) return c.json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
      const session = await storage.getSession(sid);
      if (!session) return c.json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
      const nativeKey = await storage.getBoundKey(sid, "native");
      const boundKey = await storage.getBoundKey(sid, "bound");
      if (!nativeKey && !boundKey) {
        const challenge = await issueChallenge(sid, storage);
        return c.json({
          phase: "needs-registration",
          sessionId: sid,
          challenge: challenge.jti,
          ...(nativeSkipped && { nativeSkipped }),
        });
      }
      if (nativeKey && !boundKey) {
        const challenge = await issueChallenge(sid, storage);
        return c.json({
          phase: "needs-bound-registration",
          sessionId: sid,
          tier: session.tier,
          challenge: challenge.jti,
          refreshIntervalMs: boundCookieTtl,
          ...(nativeSkipped && { nativeSkipped }),
        });
      }
      return c.json({
        phase: "bound",
        sessionId: sid,
        tier: session.tier,
        refreshIntervalMs: boundCookieTtl,
        ...(nativeSkipped && { nativeSkipped }),
      });
    }

    if (c.req.method === "GET" && url.pathname === boundChallengePath) {
      c.header("X-Server-Time", String(Date.now()));
      const sid = readBoundSessionId();
      if (!sid) return c.json({ error: "no session" }, 403);
      const session = await storage.getSession(sid);
      if (!session) return c.json({ error: "no session" }, 403);
      const challenge = await issueChallenge(sid, storage);
      return c.json({ challenge: challenge.jti });
    }

    if (c.req.method === "POST" && url.pathname === boundRegistrationPath) {
      c.header("X-Server-Time", String(Date.now()));
      const allowed = await rateLimiter.checkRegistration(ip);
      if (!allowed) return c.json({ error: "rate limited" }, 429);

      const sid = readBoundSessionId();
      if (!sid) return c.json({ error: "missing session cookie" }, 400);

      let body: { publicKey?: JsonWebKey; signature?: string; challenge?: string };
      try {
        body = (await c.req.json()) ?? {};
      } catch {
        return c.json({ error: "body must be JSON" }, 400);
      }
      if (!body.publicKey || !body.signature || !body.challenge) {
        return c.json({ error: "publicKey, signature, and challenge are required" }, 400);
      }

      try {
        await handleBoundRegistration(
          { sessionId: sid, publicKey: body.publicKey, signature: body.signature, expectedJti: body.challenge },
          storage,
        );
        emit(onEvent, {
          type: "registration",
          sessionId: sid,
          tier: "bound",
          timestamp: Date.now(),
          algorithm: "ES256",
          ip,
        });
        setCookie(c, COOKIES.bound, sid, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
        return c.json({ session_identifier: sid, refresh_url: boundRefreshPath, tier: "bound" });
      } catch (err) {
        await rateLimiter.recordFailure(ip, sid);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, {
            type: "verification_failure",
            sessionId: sid,
            tier: "bound",
            timestamp: Date.now(),
            reason: err.code,
            ip,
          });
          return c.json({ error: err.message }, 400);
        }
        throw err;
      }
    }

    if (c.req.method === "POST" && url.pathname === boundRefreshPath) {
      c.header("X-Server-Time", String(Date.now()));
      const sid = readBoundSessionId();
      if (!sid) return c.json({ error: "no session" }, 403);

      const allowed = await rateLimiter.checkRefresh(ip, sid);
      if (!allowed) return c.json({ error: "rate limited" }, 429);

      let body: { challenge?: string; signature?: string; timestamp?: number };
      try {
        body = (await c.req.json()) ?? {};
      } catch {
        return c.json({ error: "body must be JSON" }, 400);
      }
      if (!body.challenge || !body.signature || typeof body.timestamp !== "number") {
        return c.json({ error: "challenge, signature, and timestamp are required" }, 400);
      }

      try {
        await handleBoundRefresh(
          { sessionId: sid, signature: body.signature, expectedJti: body.challenge, timestamp: body.timestamp },
          storage,
        );
        emit(onEvent, { type: "refresh", sessionId: sid, tier: "bound", timestamp: Date.now(), ip });
        setCookie(c, COOKIES.bound, sid, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
        return c.json({ session_identifier: sid, refresh_url: boundRefreshPath, tier: "bound" });
      } catch (err) {
        await rateLimiter.recordFailure(ip, sid);
        const keyStillThere = await storage.getBoundKey(sid);
        if (keyStillThere && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
          emit(onEvent, { type: "session_stolen", sessionId: sid, tier: "bound", timestamp: Date.now(), ip });
        }
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, {
            type: "verification_failure",
            sessionId: sid,
            tier: "bound",
            timestamp: Date.now(),
            reason: err.code,
            ip,
          });
          return c.json({ error: err.message }, 401);
        }
        throw err;
      }
    }

    const sessionId = getCookie(c, COOKIES.bound) ?? null;
    const skippedRaw: Record<string, string | undefined> = {
      "secure-session-skipped": c.req.header("secure-session-skipped"),
      "sec-session-skipped": c.req.header("sec-session-skipped"),
    };
    const skipped = parseSessionSkippedHeader(skippedRaw);

    let tier: ProtectionTier = "none";
    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl + refreshGraceMs;
        const refreshable = session.tier === "dbsc" || session.tier === "bound";
        if (refreshable && Date.now() > staleAfter) {
          tier = "none";
        } else {
          tier = session.tier;
        }
        if (onEvent) {
          await maybeEmitPolyfillMissing({
            storage,
            session,
            ip: ipExtractor(c),
            emitted: polyfillMissingEmitted,
            onEvent,
          });
        }
      }
    } else if (autoBind && !getCookie(c, COOKIES.reg)) {
      const result = await autoBind(c);
      if (result) {
        await bindSession(c, result.sessionId, storage, {
          userId: result.userId,
          secure,
          ...(cookieScope !== undefined && { cookieScope }),
          ...(cookieDomain !== undefined && { cookieDomain }),
          registrationPath,
          registrationCookieTtl,
        });
      }
    }

    const dbscSession: DbscHonoSession = {
      sessionId,
      tier,
      skipped,
      revoke: async () => {
        if (sessionId) await storage.revokeSession(sessionId);
        deleteCookie(c, COOKIES.bound, {
          path: "/",
          secure,
          sameSite: "Lax",
          ...(domain !== undefined && { domain }),
        });
      },
    };

    (dbscSession as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] = {
      storage,
      secure,
      ...(replayCache !== undefined && { replayCache }),
    } satisfies DbscInternal;
    c.set("dbsc", dbscSession);

    await next();
  };
}

/**
 * Best-effort client IP extraction for the platforms Hono commonly runs on.
 * Does NOT trust `X-Forwarded-For` — that header is set by the client on a
 * misconfigured proxy chain and would let an attacker rotate the
 * rate-limiter key by spoofing it. Apps deployed behind a known proxy that
 * strips client-supplied XFF should pass their own `ipExtractor`.
 */
function defaultIpExtractor(c: Context): string {
  // Cloudflare Workers — c.req.header("cf-connecting-ip") is the verified
  // edge-set client IP.
  const cf = c.req.header("cf-connecting-ip");
  if (cf) return cf;
  // Some runtimes expose the remote address on `c.env.requestIP` or on
  // the raw request socket. Try both.
  const env = (c.env as { requestIP?: unknown } | undefined) ?? undefined;
  if (env && typeof env.requestIP === "string") return env.requestIP;
  const raw = c.req.raw as unknown as { socket?: { remoteAddress?: string } };
  if (raw?.socket?.remoteAddress) return raw.socket.remoteAddress;
  return "unknown";
}
