import type { Handle, RequestEvent } from "@sveltejs/kit";
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

export { requireProof } from "./require-proof.js";

/** Internal carrier so `requireProof()` can reach storage without re-passing it. */
export interface DbscInternal {
  storage: StorageAdapter;
  secure: boolean;
  boundEnabled: boolean;
  replayCache?: ProofReplayCache;
}
export const DBSC_INTERNAL: unique symbol = Symbol("dbsc-toolkit.sveltekit.internal");

interface ScopeArgs {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

const cookieNames = (s: ScopeArgs) => resolveCookieNames(s);

const DEFAULT_BOUND_TTL = 10 * 60 * 1000;
const DEFAULT_REG_TTL = 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL = 24 * 60 * 60 * 1000;

export interface DbscSvelteKitOptions extends DbscOptions {
  secure?: boolean;
  boundStatePath?: string;
  boundChallengePath?: string;
  boundRegistrationPath?: string;
  boundRefreshPath?: string;
}

export interface DbscSvelteKitSession {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

function serializeCookie(name: string, value: string, scope: ScopeArgs, maxAgeSec: number): string {
  const { domain } = resolveCookieScope(scope);
  const parts = [`${name}=${value}`, "HttpOnly"];
  if (scope.secure) parts.push("Secure");
  parts.push("SameSite=Lax", `Max-Age=${maxAgeSec}`, "Path=/");
  if (domain) parts.push(`Domain=${domain}`);
  return parts.join("; ");
}

function jsonResponse(
  status: number,
  body: unknown,
  extra?: { cookies?: string[]; headers?: Record<string, string> },
): Response {
  const headers = new Headers({ "content-type": "application/json" });
  for (const [k, v] of Object.entries(extra?.headers ?? {})) headers.set(k, v);
  for (const c of extra?.cookies ?? []) headers.append("set-cookie", c);
  return new Response(JSON.stringify(body), { status, headers });
}

function emptyResponse(status: number, extra?: { cookies?: string[]; headers?: Record<string, string> }): Response {
  const headers = new Headers();
  for (const [k, v] of Object.entries(extra?.headers ?? {})) headers.set(k, v);
  for (const c of extra?.cookies ?? []) headers.append("set-cookie", c);
  return new Response(null, { status, headers });
}

function clientIp(event: RequestEvent): string {
  try {
    return event.getClientAddress();
  } catch {
    return "unknown";
  }
}

export interface BindSessionOptions {
  userId: string;
  secure?: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
  registrationPath?: string;
  registrationCookieTtl?: number;
  sessionTtl?: number;
}

/**
 * Start a binding from a SvelteKit action or `+server` handler. Sets the
 * registration header + cookies on the event; return your own response after.
 */
export async function bindSession(
  event: RequestEvent,
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
  const { domain } = resolveCookieScope(scope);
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
  const regHeader = buildRegistrationHeader({ registrationPath, challenge: challenge.jti, cookieName: COOKIES.bound });
  event.setHeaders({ [REGISTRATION_HEADER]: regHeader, [LEGACY_REGISTRATION_HEADER]: regHeader });

  const base = { httpOnly: true, secure, sameSite: "lax" as const, path: "/", ...(domain !== undefined && { domain }) };
  event.cookies.set(COOKIES.reg, sessionId, { ...base, maxAge: regCookieTtl / 1000 });
  event.cookies.set(COOKIES.challenge, challenge.jti, { ...base, maxAge: 5 * 60 });
}

/**
 * SvelteKit `handle` hook. Add it to `src/hooks.server.ts`:
 *
 *   export const handle = dbscHandle({ storage });
 *
 * It answers the DBSC protocol routes itself and, for every other request,
 * resolves the session onto `event.locals.dbsc`.
 */
export function dbscHandle(opts: DbscSvelteKitOptions): Handle {
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
    rateLimiter = new NoopRateLimiter(),
    replayCache,
    onEvent,
    secure = true,
    cookieScope,
    cookieDomain,
  } = opts;

  const scope: ScopeArgs = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };
  resolveCookieScope(scope);
  const cookieAttrs = cookieAttributesString(scope);
  const COOKIES = cookieNames(scope);
  const polyfillMissingEmitted = new Set<string>();

  function configBody(sessionId: string, origin: string, refreshUrl: string) {
    return {
      session_identifier: sessionId,
      refresh_url: refreshUrl,
      scope: { origin, include_site: true, scope_specification: [] },
      credentials: [{ type: "cookie", name: COOKIES.bound, attributes: cookieAttrs }],
    };
  }

  function get(req: Request, name: string): string | undefined {
    return req.headers.get(name) ?? undefined;
  }
  function readBoundSessionId(event: RequestEvent): string | undefined {
    return event.cookies.get(COOKIES.bound) ?? event.cookies.get(COOKIES.reg);
  }
  function skippedFrom(req: Request): SkippedEntry[] {
    return parseSessionSkippedHeader({
      "secure-session-skipped": req.headers.get("secure-session-skipped") ?? undefined,
      "sec-session-skipped": req.headers.get("sec-session-skipped") ?? undefined,
    });
  }

  return async ({ event, resolve }) => {
    const { request, url } = event;
    const method = request.method;
    const ip = clientIp(event);

    if (method === "POST" && url.pathname === registrationPath) {
      const sessionId = event.cookies.get(COOKIES.reg);
      const expectedJti = event.cookies.get(COOKIES.challenge);
      if (!sessionId || !expectedJti) return jsonResponse(400, { error: "missing session or challenge cookie" });
      if (!(await rateLimiter.checkRegistration(ip))) return jsonResponse(429, { error: "rate limited" });
      try {
        await handleRegistration(
          { sessionId, secSessionResponseHeader: get(request, "secure-session-response") ?? get(request, "sec-session-response"), expectedJti },
          storage,
        );
        emit(onEvent, { type: "registration", sessionId, tier: "dbsc", timestamp: Date.now(), algorithm: "ES256", ip });
        return jsonResponse(200, configBody(sessionId, url.origin, refreshPath), {
          cookies: [
            serializeCookie(COOKIES.bound, sessionId, scope, boundCookieTtl / 1000),
            serializeCookie(COOKIES.challenge, "", scope, 0),
          ],
        });
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId, tier: "dbsc", timestamp: Date.now(), reason: (err as DbscVerificationError).code, ip });
          return jsonResponse(400, { error: err.message });
        }
        throw err;
      }
    }

    if (method === "POST" && url.pathname === refreshPath) {
      const sessionId = get(request, "sec-secure-session-id") ?? event.cookies.get(COOKIES.bound);
      if (!sessionId) return emptyResponse(403);
      if (!(await rateLimiter.checkRefresh(ip, sessionId))) return jsonResponse(429, { error: "rate limited" });

      const responseHeader = get(request, "secure-session-response") ?? get(request, "sec-session-response");
      const expectedJti = event.cookies.get(COOKIES.challenge);
      if (!responseHeader || !expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        return emptyResponse(403, {
          headers: { [CHALLENGE_HEADER]: buildChallengeHeader(challenge.jti, sessionId), [LEGACY_CHALLENGE_HEADER]: buildChallengeHeader(challenge.jti, sessionId) },
          cookies: [serializeCookie(COOKIES.challenge, challenge.jti, scope, 5 * 60)],
        });
      }
      try {
        await handleRefresh({ sessionId, secSessionResponseHeader: responseHeader, expectedJti }, storage);
        emit(onEvent, { type: "refresh", sessionId, tier: "dbsc", timestamp: Date.now(), ip });
        return jsonResponse(200, configBody(sessionId, url.origin, refreshPath), {
          cookies: [serializeCookie(COOKIES.bound, sessionId, scope, boundCookieTtl / 1000), serializeCookie(COOKIES.challenge, "", scope, 0)],
        });
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        const stolenCheck = await storage.getBoundKey(sessionId);
        if (stolenCheck && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
          emit(onEvent, { type: "session_stolen", sessionId, tier: "dbsc", timestamp: Date.now(), ip });
        }
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId, tier: "dbsc", timestamp: Date.now(), reason: (err as DbscVerificationError).code, ip });
          const challenge = await issueChallenge(sessionId, storage);
          return jsonResponse(403, { error: err.message }, {
            headers: { [CHALLENGE_HEADER]: buildChallengeHeader(challenge.jti, sessionId), [LEGACY_CHALLENGE_HEADER]: buildChallengeHeader(challenge.jti, sessionId) },
            cookies: [serializeCookie(COOKIES.challenge, challenge.jti, scope, 5 * 60)],
          });
        }
        throw err;
      }
    }

    if (method === "GET" && url.pathname === boundStatePath) {
      const headers = { "X-Server-Time": String(Date.now()) };
      if (!bound) return jsonResponse(200, { phase: "unbound", sessionId: null }, { headers });
      const skipped = skippedFrom(request);
      const nativeSkipped = skipped.length ? skipped.map((s) => s.reason) : undefined;
      const sid = readBoundSessionId(event);
      if (!sid) return jsonResponse(200, { phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) }, { headers });
      const session = await storage.getSession(sid);
      if (!session) return jsonResponse(200, { phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) }, { headers });
      const nativeKey = await storage.getBoundKey(sid, "native");
      const boundKey = await storage.getBoundKey(sid, "bound");
      if (!nativeKey && !boundKey) {
        const challenge = await issueChallenge(sid, storage);
        return jsonResponse(200, { phase: "needs-registration", sessionId: sid, challenge: challenge.jti, ...(nativeSkipped && { nativeSkipped }) }, { headers });
      }
      if (nativeKey && !boundKey) {
        const challenge = await issueChallenge(sid, storage);
        return jsonResponse(200, { phase: "needs-bound-registration", sessionId: sid, tier: session.tier, challenge: challenge.jti, refreshIntervalMs: boundCookieTtl, ...(nativeSkipped && { nativeSkipped }) }, { headers });
      }
      return jsonResponse(200, { phase: "bound", sessionId: sid, tier: session.tier, refreshIntervalMs: boundCookieTtl, ...(nativeSkipped && { nativeSkipped }) }, { headers });
    }

    if (bound && method === "GET" && url.pathname === boundChallengePath) {
      const headers = { "X-Server-Time": String(Date.now()) };
      const sid = readBoundSessionId(event);
      if (!sid) return jsonResponse(403, { error: "no session" }, { headers });
      const session = await storage.getSession(sid);
      if (!session) return jsonResponse(403, { error: "no session" }, { headers });
      const challenge = await issueChallenge(sid, storage);
      return jsonResponse(200, { challenge: challenge.jti }, { headers });
    }

    if (bound && method === "POST" && url.pathname === boundRegistrationPath) {
      const headers = { "X-Server-Time": String(Date.now()) };
      if (!(await rateLimiter.checkRegistration(ip))) return jsonResponse(429, { error: "rate limited" }, { headers });
      const sid = readBoundSessionId(event);
      if (!sid) return jsonResponse(400, { error: "missing session cookie" }, { headers });
      let body: { publicKey?: JsonWebKey; signature?: string; challenge?: string };
      try {
        body = (await request.json()) ?? {};
      } catch {
        return jsonResponse(400, { error: "body must be JSON" }, { headers });
      }
      if (!body.publicKey || !body.signature || !body.challenge) return jsonResponse(400, { error: "publicKey, signature, and challenge are required" }, { headers });
      try {
        await handleBoundRegistration({ sessionId: sid, publicKey: body.publicKey, signature: body.signature, expectedJti: body.challenge }, storage);
        emit(onEvent, { type: "registration", sessionId: sid, tier: "bound", timestamp: Date.now(), algorithm: "ES256", ip });
        return jsonResponse(200, { session_identifier: sid, refresh_url: boundRefreshPath, tier: "bound" }, { headers, cookies: [serializeCookie(COOKIES.bound, sid, scope, boundCookieTtl / 1000)] });
      } catch (err) {
        await rateLimiter.recordFailure(ip, sid);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId: sid, tier: "bound", timestamp: Date.now(), reason: err.code, ip });
          return jsonResponse(400, { error: err.message }, { headers });
        }
        throw err;
      }
    }

    if (bound && method === "POST" && url.pathname === boundRefreshPath) {
      const headers = { "X-Server-Time": String(Date.now()) };
      const sid = readBoundSessionId(event);
      if (!sid) return jsonResponse(403, { error: "no session" }, { headers });
      if (!(await rateLimiter.checkRefresh(ip, sid))) return jsonResponse(429, { error: "rate limited" }, { headers });
      let body: { challenge?: string; signature?: string; timestamp?: number };
      try {
        body = (await request.json()) ?? {};
      } catch {
        return jsonResponse(400, { error: "body must be JSON" }, { headers });
      }
      if (!body.challenge || !body.signature || typeof body.timestamp !== "number") return jsonResponse(400, { error: "challenge, signature, and timestamp are required" }, { headers });
      try {
        await handleBoundRefresh({ sessionId: sid, signature: body.signature, expectedJti: body.challenge, timestamp: body.timestamp }, storage);
        emit(onEvent, { type: "refresh", sessionId: sid, tier: "bound", timestamp: Date.now(), ip });
        return jsonResponse(200, { session_identifier: sid, refresh_url: boundRefreshPath, tier: "bound" }, { headers, cookies: [serializeCookie(COOKIES.bound, sid, scope, boundCookieTtl / 1000)] });
      } catch (err) {
        await rateLimiter.recordFailure(ip, sid);
        const keyStillThere = await storage.getBoundKey(sid);
        if (keyStillThere && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
          emit(onEvent, { type: "session_stolen", sessionId: sid, tier: "bound", timestamp: Date.now(), ip });
        }
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId: sid, tier: "bound", timestamp: Date.now(), reason: err.code, ip });
          return jsonResponse(401, { error: err.message }, { headers });
        }
        throw err;
      }
    }

    const sessionId = event.cookies.get(COOKIES.bound) ?? null;
    const skipped = skippedFrom(request);
    let tier: ProtectionTier = "none";
    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl + refreshGraceMs;
        const refreshable = session.tier === "dbsc" || session.tier === "bound";
        tier = refreshable && Date.now() > staleAfter ? "none" : session.tier;
        if (onEvent) {
          await maybeEmitPolyfillMissing({ storage, session, ip, emitted: polyfillMissingEmitted, onEvent });
        }
      }
    }

    const dbscSession: DbscSvelteKitSession = {
      sessionId,
      tier,
      skipped,
      revoke: async () => {
        if (sessionId) await storage.revokeSession(sessionId);
        event.cookies.delete(COOKIES.bound, { path: "/" });
      },
    };
    (dbscSession as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] = {
      storage,
      secure,
      boundEnabled: bound,
      ...(replayCache !== undefined && { replayCache }),
    } satisfies DbscInternal;
    (event.locals as Record<PropertyKey, unknown>).dbsc = dbscSession;

    return resolve(event);
  };
}
