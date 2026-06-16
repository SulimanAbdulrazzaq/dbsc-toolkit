import type { IncomingMessage, ServerResponse } from "node:http";
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

export { requireProof } from "./require-proof.js";
export { requireDpop } from "./require-dpop.js";
export type { NodeDpopGuard } from "./require-dpop.js";
export { createDbsc } from "./create-dbsc.js";
export type { CreateDbscOptions, DbscKit, BindOptions } from "./create-dbsc.js";

/** Internal carrier so `requireProof()` can reach storage without re-passing it. */
export interface DbscInternal {
  storage: StorageAdapter;
  secure: boolean;
  /** When false, `requireProof()` auto-relaxes the native dbsc tier. */
  boundEnabled: boolean;
  replayCache?: ProofReplayCache;
}
export const DBSC_INTERNAL: unique symbol = Symbol("dbsc-toolkit.node.internal");
const DBSC_SESSION: unique symbol = Symbol("dbsc-toolkit.node.session");

interface ScopeArgs {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

const cookieNames = (s: ScopeArgs) => resolveCookieNames(s);

const DEFAULT_BOUND_TTL = 10 * 60 * 1000;
const DEFAULT_REG_TTL = 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL = 24 * 60 * 60 * 1000;

export interface DbscNodeOptions extends DbscOptions {
  secure?: boolean;
  boundStatePath?: string;
  boundChallengePath?: string;
  boundRegistrationPath?: string;
  boundRefreshPath?: string;
}

export interface DbscNodeSession {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

/**
 * The dbsc handler for raw `node:http`. Call it first in your request
 * pipeline: it returns `true` when it has fully answered a DBSC protocol route
 * (the response is ended — stop), and `false` otherwise, having attached the
 * resolved session to the request. Read it back with `getDbscSession(req)`.
 */
export type DbscNodeHandler = (req: IncomingMessage, res: ServerResponse) => Promise<boolean>;

/** Reads the session the `dbsc()` handler attached to this request. */
export function getDbscSession(req: IncomingMessage): DbscNodeSession | undefined {
  return (req as unknown as Record<PropertyKey, unknown>)[DBSC_SESSION] as DbscNodeSession | undefined;
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
  const parts = [`${name}=${value}`, "HttpOnly"];
  if (opts.secure) parts.push("Secure");
  const sameSite = opts.sameSite.charAt(0).toUpperCase() + opts.sameSite.slice(1);
  parts.push(`SameSite=${sameSite}`);
  parts.push(`Max-Age=${opts.maxAge}`);
  parts.push(`Path=${opts.path}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  return parts.join("; ");
}

function appendSetCookie(res: ServerResponse, cookies: string | string[]): void {
  const add = Array.isArray(cookies) ? cookies : [cookies];
  const prior = res.getHeader("Set-Cookie");
  const priorList = Array.isArray(prior)
    ? prior.map(String)
    : prior !== undefined
      ? [String(prior)]
      : [];
  res.setHeader("Set-Cookie", [...priorList, ...add]);
}

function reqUrl(req: IncomingMessage): URL {
  return new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
}

function reqOrigin(req: IncomingMessage): string {
  const xfp = req.headers["x-forwarded-proto"];
  const proto =
    (Array.isArray(xfp) ? xfp[0] : xfp)?.split(",")[0]?.trim() ??
    ((req.socket as unknown as { encrypted?: boolean }).encrypted ? "https" : "http");
  return `${proto}://${req.headers.host ?? "localhost"}`;
}

function reqIp(req: IncomingMessage): string {
  return req.socket?.remoteAddress ?? "unknown";
}

function reqCookies(req: IncomingMessage): Record<string, string> {
  return parseCookieHeader(req.headers.cookie);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.setHeader("Content-Type", "application/json");
  res.statusCode = status;
  res.end(JSON.stringify(body));
}

function sendStatus(res: ServerResponse, status: number): void {
  res.statusCode = status;
  res.end();
}

/** Reads and JSON-parses the raw request body. Returns `{}` on empty/invalid. */
export async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const cached = (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"];
  let raw: Buffer;
  if (Buffer.isBuffer(cached)) {
    raw = cached;
  } else {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    raw = Buffer.concat(chunks);
    (req as unknown as Record<PropertyKey, unknown>)["__dbscRawBody"] = raw;
  }
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw.toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export interface BindSessionOptions {
  userId: string;
  /** Match the value passed to dbsc({ secure }). Defaults true. */
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
  res: ServerResponse,
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
  appendSetCookie(res, [
    serializeCookie(COOKIES.reg, sessionId, cookieOpts(regCookieTtl, scope)),
    serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, scope)),
  ]);
}

export function dbsc(opts: DbscNodeOptions): DbscNodeHandler {
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

  async function handleRegistrationRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const ip = reqIp(req);
    const allowed = await rateLimiter.checkRegistration(ip);
    if (!allowed) return sendJson(res, 429, { error: "rate limited" });

    const cookies = reqCookies(req);
    const sessionId = cookies[COOKIES.reg];
    const expectedJti = cookies[COOKIES.challenge];
    if (!sessionId || !expectedJti) {
      return sendJson(res, 400, { error: "missing session or challenge cookie" });
    }

    try {
      await handleRegistration(
        {
          sessionId,
          secSessionResponseHeader: readSessionResponseHeader(req.headers),
          expectedJti,
        },
        storage,
      );
      emit(onEvent, { type: "registration", sessionId, tier: "dbsc", timestamp: Date.now(), algorithm: "ES256", ip });
      appendSetCookie(res, [
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)),
        serializeCookie(COOKIES.challenge, "", { ...cookieOpts(0, scope), maxAge: 0 }),
      ]);
      sendJson(res, 200, configBody(sessionId, reqOrigin(req), refreshPath));
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, { type: "verification_failure", sessionId, tier: "dbsc", timestamp: Date.now(), reason: err.code, ip });
        return sendJson(res, 400, { error: err.message });
      }
      throw err;
    }
  }

  async function handleRefreshRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const ip = reqIp(req);
    const cookies = reqCookies(req);
    const idHeader = req.headers["sec-secure-session-id"];
    const sessionId = (Array.isArray(idHeader) ? idHeader[0] : idHeader) ?? cookies[COOKIES.bound];
    if (!sessionId) return sendStatus(res, 403);

    const allowed = await rateLimiter.checkRefresh(ip, sessionId);
    if (!allowed) return sendJson(res, 429, { error: "rate limited" });

    const responseHeader = readSessionResponseHeader(req.headers);
    const expectedJti = cookies[COOKIES.challenge];

    if (!responseHeader || !expectedJti) {
      const challenge = await issueChallenge(sessionId, storage);
      res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      appendSetCookie(res, serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, scope)));
      return sendStatus(res, 403);
    }

    try {
      await handleRefresh({ sessionId, secSessionResponseHeader: responseHeader, expectedJti }, storage);
      emit(onEvent, { type: "refresh", sessionId, tier: "dbsc", timestamp: Date.now(), ip });
      appendSetCookie(res, [
        serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)),
        serializeCookie(COOKIES.challenge, "", { ...cookieOpts(0, scope), maxAge: 0 }),
      ]);
      sendJson(res, 200, configBody(sessionId, reqOrigin(req), refreshPath));
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      const stolenCheck = await storage.getBoundKey(sessionId);
      if (stolenCheck && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
        emit(onEvent, { type: "session_stolen", sessionId, tier: "dbsc", timestamp: Date.now(), ip });
      }
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, { type: "verification_failure", sessionId, tier: "dbsc", timestamp: Date.now(), reason: (err as DbscVerificationError).code, ip });
        const challenge = await issueChallenge(sessionId, storage);
        res.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        appendSetCookie(res, serializeCookie(COOKIES.challenge, challenge.jti, cookieOpts(5 * 60 * 1000, scope)));
        return sendJson(res, 403, { error: err.message });
      }
      throw err;
    }
  }

  function readBoundSessionId(cookies: Record<string, string>): string | undefined {
    return cookies[COOKIES.bound] ?? cookies[COOKIES.reg];
  }

  async function handleBoundStateRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader("X-Server-Time", String(Date.now()));
    const skipped = parseSessionSkippedHeader(req.headers);
    const nativeSkipped = skipped.length ? skipped.map((s) => s.reason) : undefined;
    const sessionId = readBoundSessionId(reqCookies(req));
    if (!sessionId) return sendJson(res, 200, { phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
    const session = await storage.getSession(sessionId);
    if (!session) return sendJson(res, 200, { phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
    const nativeKey = await storage.getBoundKey(sessionId, "native");
    const boundKey = await storage.getBoundKey(sessionId, "bound");
    if (!nativeKey && !boundKey) {
      const challenge = await issueChallenge(sessionId, storage);
      return sendJson(res, 200, { phase: "needs-registration", sessionId, challenge: challenge.jti, ...(nativeSkipped && { nativeSkipped }) });
    }
    if (nativeKey && !boundKey) {
      const challenge = await issueChallenge(sessionId, storage);
      return sendJson(res, 200, {
        phase: "needs-bound-registration",
        sessionId,
        tier: session.tier,
        challenge: challenge.jti,
        refreshIntervalMs: boundCookieTtl,
        ...(nativeSkipped && { nativeSkipped }),
      });
    }
    sendJson(res, 200, { phase: "bound", sessionId, tier: session.tier, refreshIntervalMs: boundCookieTtl, ...(nativeSkipped && { nativeSkipped }) });
  }

  async function handleBoundChallengeRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader("X-Server-Time", String(Date.now()));
    const sessionId = readBoundSessionId(reqCookies(req));
    if (!sessionId) return sendJson(res, 403, { error: "no session" });
    const session = await storage.getSession(sessionId);
    if (!session) return sendJson(res, 403, { error: "no session" });
    const challenge = await issueChallenge(sessionId, storage);
    sendJson(res, 200, { challenge: challenge.jti });
  }

  async function handleBoundRegistrationRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader("X-Server-Time", String(Date.now()));
    const ip = reqIp(req);
    const allowed = await rateLimiter.checkRegistration(ip);
    if (!allowed) return sendJson(res, 429, { error: "rate limited" });

    const sessionId = readBoundSessionId(reqCookies(req));
    if (!sessionId) return sendJson(res, 400, { error: "missing session cookie" });

    const body = await readJsonBody(req) as { publicKey?: JsonWebKey; signature?: string; challenge?: string };
    if (!body.publicKey || !body.signature || !body.challenge) {
      return sendJson(res, 400, { error: "publicKey, signature, and challenge are required in JSON body" });
    }

    try {
      await handleBoundRegistration({ sessionId, publicKey: body.publicKey, signature: body.signature, expectedJti: body.challenge }, storage);
      emit(onEvent, { type: "registration", sessionId, tier: "bound", timestamp: Date.now(), algorithm: "ES256", ip });
      appendSetCookie(res, serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)));
      sendJson(res, 200, { session_identifier: sessionId, refresh_url: boundRefreshPath, tier: "bound" });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, { type: "verification_failure", sessionId, tier: "bound", timestamp: Date.now(), reason: err.code, ip });
        return sendJson(res, 400, { error: err.message });
      }
      throw err;
    }
  }

  async function handleBoundRefreshRoute(req: IncomingMessage, res: ServerResponse): Promise<void> {
    res.setHeader("X-Server-Time", String(Date.now()));
    const ip = reqIp(req);
    const sessionId = readBoundSessionId(reqCookies(req));
    if (!sessionId) return sendJson(res, 403, { error: "no session" });

    const allowed = await rateLimiter.checkRefresh(ip, sessionId);
    if (!allowed) return sendJson(res, 429, { error: "rate limited" });

    const body = await readJsonBody(req) as { challenge?: string; signature?: string; timestamp?: number };
    if (!body.challenge || !body.signature || typeof body.timestamp !== "number") {
      return sendJson(res, 400, { error: "challenge, signature, and timestamp are required" });
    }

    try {
      await handleBoundRefresh({ sessionId, signature: body.signature, expectedJti: body.challenge, timestamp: body.timestamp }, storage);
      emit(onEvent, { type: "refresh", sessionId, tier: "bound", timestamp: Date.now(), ip });
      appendSetCookie(res, serializeCookie(COOKIES.bound, sessionId, cookieOpts(boundCookieTtl, scope)));
      sendJson(res, 200, { session_identifier: sessionId, refresh_url: boundRefreshPath, tier: "bound" });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      const keyStillThere = await storage.getBoundKey(sessionId);
      if (keyStillThere && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
        emit(onEvent, { type: "session_stolen", sessionId, tier: "bound", timestamp: Date.now(), ip });
      }
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, { type: "verification_failure", sessionId, tier: "bound", timestamp: Date.now(), reason: err.code, ip });
        return sendJson(res, 401, { error: err.message });
      }
      throw err;
    }
  }

  return async (req: IncomingMessage, res: ServerResponse): Promise<boolean> => {
    const url = reqUrl(req);
    const method = req.method ?? "GET";

    if (method === "POST" && url.pathname === registrationPath) {
      await handleRegistrationRoute(req, res);
      return true;
    }
    if (method === "POST" && url.pathname === refreshPath) {
      await handleRefreshRoute(req, res);
      return true;
    }
    if (method === "GET" && url.pathname === boundStatePath) {
      if (bound) {
        await handleBoundStateRoute(req, res);
      } else {
        res.setHeader("X-Server-Time", String(Date.now()));
        sendJson(res, 200, { phase: "unbound", sessionId: null });
      }
      return true;
    }
    if (bound) {
      if (method === "GET" && url.pathname === boundChallengePath) {
        await handleBoundChallengeRoute(req, res);
        return true;
      }
      if (method === "POST" && url.pathname === boundRegistrationPath) {
        await handleBoundRegistrationRoute(req, res);
        return true;
      }
      if (method === "POST" && url.pathname === boundRefreshPath) {
        await handleBoundRefreshRoute(req, res);
        return true;
      }
    }

    const cookies = reqCookies(req);
    const sessionId = cookies[COOKIES.bound];
    const skipped = parseSessionSkippedHeader(req.headers);

    const session: DbscNodeSession = {
      sessionId: sessionId ?? null,
      tier: "none",
      skipped,
      revoke: async () => {
        if (sessionId) await storage.revokeSession(sessionId);
        appendSetCookie(res, serializeCookie(COOKIES.bound, "", { ...cookieOpts(0, scope), maxAge: 0 }));
      },
    };
    (session as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] = {
      storage,
      secure,
      boundEnabled: bound,
      ...(replayCache !== undefined && { replayCache }),
    } satisfies DbscInternal;

    if (sessionId) {
      const stored = await storage.getSession(sessionId);
      if (stored) {
        const staleAfter = stored.lastRefreshAt + boundCookieTtl + refreshGraceMs;
        const refreshable = stored.tier === "dbsc" || stored.tier === "bound";
        session.tier = refreshable && Date.now() > staleAfter ? "none" : stored.tier;
        if (onEvent) {
          await maybeEmitPolyfillMissing({ storage, session: stored, ip: reqIp(req), emitted: polyfillMissingEmitted, onEvent });
        }
      }
    } else if (autoBind && !cookies[COOKIES.reg]) {
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

    (req as unknown as Record<PropertyKey, unknown>)[DBSC_SESSION] = session;
    return false;
  };
}
