import { randomBytes } from "node:crypto";
import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
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
export type {
  RequireBoundProofOptions,
  RequireBoundProofContext,
  RequireBoundProofResult,
} from "./proof.js";
export { requireProof } from "./require-proof.js";
export type { RequireProofSession, RequireProofResult } from "./require-proof.js";
export { requireDpop } from "./require-dpop.js";
export type { RequireDpopResult } from "./require-dpop.js";
export { createDbsc } from "./create-dbsc.js";
export type { CreateDbscOptions, DbscKit, BindOptions } from "./create-dbsc.js";

interface ScopeArgs {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

const cookieNames = (s: ScopeArgs) => resolveCookieNames(s);

const DEFAULT_BOUND_TTL_MS = 10 * 60 * 1000;
const DEFAULT_REG_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface DbscNextOptions extends DbscOptions {
  secure?: boolean;
  boundStatePath?: string;
  boundChallengePath?: string;
  boundRegistrationPath?: string;
  boundRefreshPath?: string;
}

function cookieBase(scope: ScopeArgs) {
  const { domain } = resolveCookieScope(scope);
  return {
    httpOnly: true,
    secure: scope.secure,
    sameSite: "lax" as const,
    path: "/",
    ...(domain !== undefined && { domain }),
  };
}

export interface BindSessionOptions {
  userId: string;
  /** Match the value passed to createDbscMiddleware({ secure }). Defaults true. Mismatch = cookies the middleware cannot read. */
  secure?: boolean;
  /** Match the value passed to createDbscMiddleware({ cookieScope }). Defaults "host". */
  cookieScope?: CookieScope;
  /** Match the value passed to createDbscMiddleware({ cookieDomain }). Required for cookieScope: "site". */
  cookieDomain?: string;
  registrationPath?: string;
  registrationCookieTtl?: number;
  sessionTtl?: number;
}

export async function bindSession(
  res: NextResponse,
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

  res.headers.set(REGISTRATION_HEADER, regHeader);
  res.headers.set(LEGACY_REGISTRATION_HEADER, regHeader);

  res.cookies.set(COOKIES.reg, sessionId, {
    ...cookieBase(scope),
    maxAge: regCookieTtl / 1000,
  });
  res.cookies.set(COOKIES.challenge, challenge.jti, {
    ...cookieBase(scope),
    maxAge: 5 * 60,
  });
}

export function createDbscMiddleware(opts: DbscNextOptions) {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundStatePath = "/dbsc-bound/state",
    boundChallengePath = "/dbsc-bound/challenge",
    boundRegistrationPath = "/dbsc-bound/registration",
    boundRefreshPath = "/dbsc-bound/refresh",
    bound = true,
    boundCookieTtl = DEFAULT_BOUND_TTL_MS,
    registrationCookieTtl = DEFAULT_REG_TTL_MS,
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
  // Fail-fast validation
  resolveCookieScope(scope);
  const cookieAttrs = cookieAttributesString(scope);
  const COOKIES = cookieNames(scope);

  return async function middleware(req: NextRequest): Promise<NextResponse> {
    const url = req.nextUrl.pathname;
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";

    if (req.method === "POST" && url === registrationPath) {
      const sessionId = req.cookies.get(COOKIES.reg)?.value;
      const expectedJti = req.cookies.get(COOKIES.challenge)?.value;

      if (!sessionId || !expectedJti) {
        return NextResponse.json({ error: "missing session or challenge cookie" }, { status: 400 });
      }

      const allowed = await rateLimiter.checkRegistration(ip);
      if (!allowed) {
        return NextResponse.json({ error: "rate limited" }, { status: 429 });
      }

      try {
        await handleRegistration(
          {
            sessionId,
            secSessionResponseHeader:
              req.headers.get("secure-session-response") ??
              req.headers.get("sec-session-response") ??
              undefined,
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

        const body = {
          session_identifier: sessionId,
          refresh_url: refreshPath,
          scope: {
            origin: req.nextUrl.origin,
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
        };
        const res = NextResponse.json(body, { status: 200 });
        res.cookies.set(COOKIES.bound, sessionId, {
          ...cookieBase(scope),
          maxAge: boundCookieTtl / 1000,
        });
        res.cookies.delete(COOKIES.challenge);
        return res;
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          return NextResponse.json({ error: err.message }, { status: 400 });
        }
        throw err;
      }
    }

    if (req.method === "POST" && url === refreshPath) {
      const sessionIdHeader = req.headers.get("sec-secure-session-id");
      const sessionId = sessionIdHeader ?? req.cookies.get(COOKIES.bound)?.value;

      if (!sessionId) {
        return new NextResponse(null, { status: 403 });
      }

      const allowed = await rateLimiter.checkRefresh(ip, sessionId);
      if (!allowed) {
        return NextResponse.json({ error: "rate limited" }, { status: 429 });
      }

      const responseHeader =
        req.headers.get("secure-session-response") ??
        req.headers.get("sec-session-response");

      if (!responseHeader) {
        const challenge = await issueChallenge(sessionId, storage);
        const res = new NextResponse(null, { status: 403 });
        res.headers.set(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.headers.set(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.cookies.set(COOKIES.challenge, challenge.jti, {
          ...cookieBase(scope),
          maxAge: 5 * 60,
        });
        return res;
      }

      const expectedJti = req.cookies.get(COOKIES.challenge)?.value;
      if (!expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        const res = new NextResponse(null, { status: 403 });
        res.headers.set(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.headers.set(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.cookies.set(COOKIES.challenge, challenge.jti, {
          ...cookieBase(scope),
          maxAge: 5 * 60,
        });
        return res;
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

        const body = {
          session_identifier: sessionId,
          refresh_url: refreshPath,
          scope: {
            origin: req.nextUrl.origin,
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
        };
        const res = NextResponse.json(body, { status: 200 });
        res.cookies.set(COOKIES.bound, sessionId, {
          ...cookieBase(scope),
          maxAge: boundCookieTtl / 1000,
        });
        res.cookies.delete(COOKIES.challenge);
        return res;
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
          const res = NextResponse.json({ error: err.message }, { status: 403 });
          res.headers.set(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
          res.headers.set(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
          res.cookies.set(COOKIES.challenge, challenge.jti, {
            ...cookieBase(scope),
            maxAge: 5 * 60,
          });
          return res;
        }
        throw err;
      }
    }

    const readBoundSessionId = (): string | undefined =>
      req.cookies.get(COOKIES.bound)?.value ?? req.cookies.get(COOKIES.reg)?.value;

    if (req.method === "GET" && url === boundStatePath) {
      if (!bound) {
        const res = NextResponse.json({ phase: "unbound", sessionId: null });
        res.headers.set("X-Server-Time", String(Date.now()));
        return res;
      }
      const sid = readBoundSessionId();
      const xServerTime = String(Date.now());
      const skippedRaw: Record<string, string | undefined> = {
        "secure-session-skipped": req.headers.get("secure-session-skipped") ?? undefined,
        "sec-session-skipped": req.headers.get("sec-session-skipped") ?? undefined,
      };
      const skipped = parseSessionSkippedHeader(skippedRaw);
      const nativeSkipped = skipped.length ? skipped.map((s) => s.reason) : undefined;
      if (!sid) {
        const res = NextResponse.json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
        res.headers.set("X-Server-Time", xServerTime);
        return res;
      }
      const session = await storage.getSession(sid);
      if (!session) {
        const res = NextResponse.json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
        res.headers.set("X-Server-Time", xServerTime);
        return res;
      }
      const nativeKey = await storage.getBoundKey(sid, "native");
      const boundKey = await storage.getBoundKey(sid, "bound");
      if (!nativeKey && !boundKey) {
        const challenge = await issueChallenge(sid, storage);
        const res = NextResponse.json({
          phase: "needs-registration",
          sessionId: sid,
          challenge: challenge.jti,
          ...(nativeSkipped && { nativeSkipped }),
        });
        res.headers.set("X-Server-Time", xServerTime);
        return res;
      }
      if (nativeKey && !boundKey) {
        const challenge = await issueChallenge(sid, storage);
        const res = NextResponse.json({
          phase: "needs-bound-registration",
          sessionId: sid,
          tier: session.tier,
          challenge: challenge.jti,
          refreshIntervalMs: boundCookieTtl,
          ...(nativeSkipped && { nativeSkipped }),
        });
        res.headers.set("X-Server-Time", xServerTime);
        return res;
      }
      const res = NextResponse.json({
        phase: "bound",
        sessionId: sid,
        tier: session.tier,
        refreshIntervalMs: boundCookieTtl,
        ...(nativeSkipped && { nativeSkipped }),
      });
      res.headers.set("X-Server-Time", xServerTime);
      return res;
    }

    if (bound && req.method === "GET" && url === boundChallengePath) {
      const xServerTime = String(Date.now());
      const sid = readBoundSessionId();
      if (!sid) {
        const r = NextResponse.json({ error: "no session" }, { status: 403 });
        r.headers.set("X-Server-Time", xServerTime);
        return r;
      }
      const session = await storage.getSession(sid);
      if (!session) {
        const r = NextResponse.json({ error: "no session" }, { status: 403 });
        r.headers.set("X-Server-Time", xServerTime);
        return r;
      }
      const challenge = await issueChallenge(sid, storage);
      const r = NextResponse.json({ challenge: challenge.jti });
      r.headers.set("X-Server-Time", xServerTime);
      return r;
    }

    if (bound && req.method === "POST" && url === boundRegistrationPath) {
      const xServerTime = String(Date.now());
      const withTime = (r: NextResponse): NextResponse => {
        r.headers.set("X-Server-Time", xServerTime);
        return r;
      };
      const allowed = await rateLimiter.checkRegistration(ip);
      if (!allowed) return withTime(NextResponse.json({ error: "rate limited" }, { status: 429 }));

      const sid = readBoundSessionId();
      if (!sid) return withTime(NextResponse.json({ error: "missing session cookie" }, { status: 400 }));

      let body: { publicKey?: JsonWebKey; signature?: string; challenge?: string };
      try {
        body = (await req.json()) ?? {};
      } catch {
        return withTime(NextResponse.json({ error: "body must be JSON" }, { status: 400 }));
      }
      if (!body.publicKey || !body.signature || !body.challenge) {
        return withTime(
          NextResponse.json({ error: "publicKey, signature, and challenge are required" }, { status: 400 }),
        );
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
        const res = NextResponse.json({
          session_identifier: sid,
          refresh_url: boundRefreshPath,
          tier: "bound",
        });
        res.cookies.set(COOKIES.bound, sid, { ...cookieBase(scope), maxAge: boundCookieTtl / 1000 });
        return withTime(res);
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
          return withTime(NextResponse.json({ error: err.message }, { status: 400 }));
        }
        throw err;
      }
    }

    if (bound && req.method === "POST" && url === boundRefreshPath) {
      const xServerTime = String(Date.now());
      const sid = readBoundSessionId();
      if (!sid) {
        const res = NextResponse.json({ error: "no session" }, { status: 403 });
        res.headers.set("X-Server-Time", xServerTime);
        return res;
      }

      const allowed = await rateLimiter.checkRefresh(ip, sid);
      if (!allowed) return NextResponse.json({ error: "rate limited" }, { status: 429 });

      let body: { challenge?: string; signature?: string; timestamp?: number };
      try {
        body = (await req.json()) ?? {};
      } catch {
        return NextResponse.json({ error: "body must be JSON" }, { status: 400 });
      }
      if (!body.challenge || !body.signature || typeof body.timestamp !== "number") {
        return NextResponse.json({ error: "challenge, signature, and timestamp are required" }, { status: 400 });
      }

      try {
        await handleBoundRefresh(
          { sessionId: sid, signature: body.signature, expectedJti: body.challenge, timestamp: body.timestamp },
          storage,
        );
        emit(onEvent, { type: "refresh", sessionId: sid, tier: "bound", timestamp: Date.now(), ip });
        const res = NextResponse.json({
          session_identifier: sid,
          refresh_url: boundRefreshPath,
          tier: "bound",
        });
        res.cookies.set(COOKIES.bound, sid, { ...cookieBase(scope), maxAge: boundCookieTtl / 1000 });
        res.headers.set("X-Server-Time", xServerTime);
        return res;
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
          return NextResponse.json({ error: err.message }, { status: 401 });
        }
        throw err;
      }
    }

    if (autoBind && !req.cookies.get(COOKIES.bound)?.value && !req.cookies.get(COOKIES.reg)?.value) {
      const result = await autoBind(req);
      if (result) {
        const res = NextResponse.next();
        await bindSession(res, result.sessionId, storage, {
          userId: result.userId,
          secure,
          ...(cookieScope !== undefined && { cookieScope }),
          ...(cookieDomain !== undefined && { cookieDomain }),
          registrationPath,
          registrationCookieTtl,
        });
        return res;
      }
    }

    return NextResponse.next();
  };
}

export interface DbscSessionInfo {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

// Module-level dedup for the polyfill_missing event on Next.js. The middleware
// is invoked from `middleware.ts` which is itself instantiated per
// edge-runtime — restarts re-arm the set, which is fine.
const polyfillMissingEmitted = new Set<string>();

export async function getDbscSession(
  req: NextRequest,
  storage: DbscOptions["storage"],
  opts: {
    boundCookieTtl?: number;
    refreshGraceMs?: number;
    res?: NextResponse;
    secure?: boolean;
    cookieScope?: CookieScope;
    cookieDomain?: string;
    /** Internal — the kit threads this through so polyfill_missing can fire. */
    onEvent?: DbscOptions["onEvent"];
  } = {},
): Promise<DbscSessionInfo> {
  const skippedRaw: Record<string, string | undefined> = {
    "secure-session-skipped": req.headers.get("secure-session-skipped") ?? undefined,
    "sec-session-skipped": req.headers.get("sec-session-skipped") ?? undefined,
  };
  const skipped = parseSessionSkippedHeader(skippedRaw);

  const secure = opts.secure ?? true;
  const scope: ScopeArgs = {
    secure,
    ...(opts.cookieScope !== undefined && { cookieScope: opts.cookieScope }),
    ...(opts.cookieDomain !== undefined && { cookieDomain: opts.cookieDomain }),
  };
  const COOKIES = cookieNames(scope);
  const sessionId = req.cookies.get(COOKIES.bound)?.value ?? null;

  const revoke = async () => {
    if (sessionId) await storage.revokeSession(sessionId);
    if (opts.res) {
      opts.res.cookies.delete(COOKIES.bound);
    }
  };

  if (!sessionId) return { sessionId: null, tier: "none", skipped, revoke };

  const session = await storage.getSession(sessionId);
  if (!session) return { sessionId: null, tier: "none", skipped, revoke };

  const boundCookieTtl = opts.boundCookieTtl ?? DEFAULT_BOUND_TTL_MS;
  const refreshGraceMs = opts.refreshGraceMs ?? 30_000;
  const staleAfter = session.lastRefreshAt + boundCookieTtl + refreshGraceMs;
  const refreshable = session.tier === "dbsc" || session.tier === "bound";
  if (refreshable && Date.now() > staleAfter) {
    return { sessionId, tier: "none", skipped, revoke };
  }

  if (opts.onEvent) {
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";
    await maybeEmitPolyfillMissing({
      storage,
      session,
      ip,
      emitted: polyfillMissingEmitted,
      onEvent: opts.onEvent,
    });
  }

  return { sessionId, tier: session.tier, skipped, revoke };
}
