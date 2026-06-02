/**
 * The six DBSC protocol routes, mounted inside the `dbsc()` plugin via
 * `createAuthEndpoint`. This is what makes the plugin framework-agnostic: the
 * routes run through Better Auth's own router, so Express / Fastify / Hono /
 * Next.js all get them with zero per-framework setup.
 *
 * Each handler is a faithful port of the Express adapter's route logic
 * (`src/express/index.ts`), rewired from `req`/`res` to `ctx`:
 *   - read headers via `ctx.headers.get`, cookies via `ctx.getCookie`
 *   - write cookies via `ctx.setCookie`, headers via `ctx.setHeader`
 *   - non-2xx via `throw new APIError(STATUS, body)` (after setting any headers)
 *
 * The protocol/crypto itself is unchanged — these call the same core functions
 * (`handleRegistration`, `handleRefresh`, the bound handlers) the Express
 * adapter calls.
 *
 * Native routes (`/dbsc/registration`, `/dbsc/refresh`) are declared with NO
 * `body` schema: Chrome sends the JWS in a header with an empty body, and a
 * declared body schema would 415 the empty body. The bound routes take JSON
 * bodies and keep a schema.
 */
import { createAuthEndpoint, APIError } from "better-auth/api";
import {
  handleRegistration,
  handleRefresh,
  handleBoundRegistration,
  handleBoundRefresh,
  issueChallenge,
  buildChallengeHeader,
  readSessionResponseHeader,
  parseSessionSkippedHeader,
  emit,
  DbscVerificationError,
  DbscProtocolError,
  ErrorCodes,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  type StorageAdapter,
  type AnyTelemetryEvent,
} from "dbsc-toolkit";

import type { DbscCookies, CookieCtx } from "./cookies.js";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export interface RouteDeps {
  /** Builds the storage bridge from a request ctx (ctx.context.adapter + internalAdapter). */
  storageFromCtx: (ctx: any) => StorageAdapter;
  cookies: DbscCookies;
  basePath: string;
  boundCookieTtl: number;
  onEvent?: ((event: AnyTelemetryEvent) => void | Promise<void>) | undefined;
}

const REGISTRATION_PATH = "/dbsc/registration";
const REFRESH_PATH = "/dbsc/refresh";
const BOUND_STATE_PATH = "/dbsc-bound/state";
const BOUND_CHALLENGE_PATH = "/dbsc-bound/challenge";
const BOUND_REGISTER_PATH = "/dbsc-bound/registration";
const BOUND_REFRESH_PATH = "/dbsc-bound/refresh";

/** Read a request header off ctx (case-insensitive via Headers). */
function header(ctx: any, name: string): string | undefined {
  const h = ctx.headers;
  if (!h) return undefined;
  const v = typeof h.get === "function" ? h.get(name) : h[name];
  return v ?? undefined;
}

/** Build the JSON session-config body both registration and refresh return. */
function sessionConfig(sessionId: string, refreshUrl: string, boundName: string, attrs: string, origin: string) {
  return {
    session_identifier: sessionId,
    refresh_url: refreshUrl,
    scope: { origin, include_site: true, scope_specification: [] as unknown[] },
    credentials: [{ type: "cookie", name: boundName, attributes: attrs }],
  };
}

function originOf(ctx: any): string {
  try {
    const u = new URL(ctx.request?.url ?? "http://localhost");
    return `${u.protocol}//${u.host}`;
  } catch {
    return "http://localhost";
  }
}

export function buildDbscRoutes(deps: RouteDeps): Record<string, unknown> {
  const { storageFromCtx, cookies, basePath, boundCookieTtl, onEvent } = deps;
  const refreshUrl = `${basePath}${REFRESH_PATH}`;
  const boundRefreshUrl = `${basePath}${BOUND_REFRESH_PATH}`;

  // --- POST /dbsc/registration -------------------------------------------
  const dbscRegistration = createAuthEndpoint(
    REGISTRATION_PATH,
    { method: "POST" },
    async (ctx: any) => {
      const storage = storageFromCtx(ctx);
      const cctx = ctx as unknown as CookieCtx;
      const sessionId = cookies.readReg(cctx);
      const expectedJti = cookies.readChallenge(cctx);
      if (!sessionId || !expectedJti) {
        throw new APIError("BAD_REQUEST", { error: "missing session or challenge cookie" });
      }
      try {
        await handleRegistration(
          { sessionId, secSessionResponseHeader: header(ctx, "secure-session-response"), expectedJti },
          storage,
        );
        emit(onEvent, { type: "registration", sessionId, tier: "dbsc", timestamp: Date.now(), algorithm: "ES256", ip: "" });
        cookies.setBound(cctx, sessionId, boundCookieTtl);
        cookies.clearChallenge(cctx);
        return ctx.json(sessionConfig(sessionId, refreshUrl, cookies.names.bound, cookies.attributesString, originOf(ctx)));
      } catch (err) {
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId, tier: "dbsc", timestamp: Date.now(), reason: err.code, ip: "" });
          throw new APIError("BAD_REQUEST", { error: err.message });
        }
        throw err;
      }
    },
  );

  // --- POST /dbsc/refresh -------------------------------------------------
  const dbscRefresh = createAuthEndpoint(
    REFRESH_PATH,
    { method: "POST" },
    async (ctx: any) => {
      const storage = storageFromCtx(ctx);
      const cctx = ctx as unknown as CookieCtx;
      const sessionId = header(ctx, "sec-secure-session-id") ?? cookies.readBoundOrReg(cctx);
      if (!sessionId) throw new APIError("FORBIDDEN", { error: "no session" });

      const responseHeader = readSessionResponseHeader(headersRecord(ctx));
      const expectedJti = cookies.readChallenge(cctx);

      // No proof yet (or no challenge cookie): issue a challenge + 403 so Chrome
      // retries with the signed JWS. 403 is required — Chrome ignores 401 here.
      if (!responseHeader || !expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        ctx.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        ctx.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        cookies.setChallenge(cctx, challenge.jti, CHALLENGE_TTL_MS);
        throw new APIError("FORBIDDEN", { error: "challenge issued" });
      }

      try {
        await handleRefresh({ sessionId, secSessionResponseHeader: responseHeader, expectedJti }, storage);
        emit(onEvent, { type: "refresh", sessionId, tier: "dbsc", timestamp: Date.now(), ip: "" });
        cookies.setBound(cctx, sessionId, boundCookieTtl);
        cookies.clearChallenge(cctx);
        return ctx.json(sessionConfig(sessionId, refreshUrl, cookies.names.bound, cookies.attributesString, originOf(ctx)));
      } catch (err) {
        const stolen = await storage.getBoundKey(sessionId);
        if (stolen && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
          emit(onEvent, { type: "session_stolen", sessionId, tier: "dbsc", timestamp: Date.now(), ip: "" });
        }
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId, tier: "dbsc", timestamp: Date.now(), reason: (err as DbscVerificationError).code, ip: "" });
          const challenge = await issueChallenge(sessionId, storage);
          ctx.setHeader(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
          ctx.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
          cookies.setChallenge(cctx, challenge.jti, CHALLENGE_TTL_MS);
          throw new APIError("FORBIDDEN", { error: err.message });
        }
        throw err;
      }
    },
  );

  // --- GET /dbsc-bound/state ---------------------------------------------
  const dbscBoundState = createAuthEndpoint(
    BOUND_STATE_PATH,
    { method: "GET" },
    async (ctx: any) => {
      ctx.setHeader("X-Server-Time", String(Date.now()));
      const storage = storageFromCtx(ctx);
      const cctx = ctx as unknown as CookieCtx;
      const skipped = parseSessionSkippedHeader(headersRecord(ctx));
      const nativeSkipped = skipped.length ? skipped.map((s) => s.reason) : undefined;
      const sessionId = cookies.readBoundOrReg(cctx);
      if (!sessionId) return ctx.json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
      const session = await storage.getSession(sessionId);
      if (!session) return ctx.json({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
      const nativeKey = await storage.getBoundKey(sessionId, "native");
      const boundKey = await storage.getBoundKey(sessionId, "bound");
      if (!nativeKey && !boundKey) {
        const challenge = await issueChallenge(sessionId, storage);
        return ctx.json({ phase: "needs-registration", sessionId, challenge: challenge.jti, ...(nativeSkipped && { nativeSkipped }) });
      }
      if (nativeKey && !boundKey) {
        const challenge = await issueChallenge(sessionId, storage);
        return ctx.json({ phase: "needs-bound-registration", sessionId, tier: session.tier, challenge: challenge.jti, refreshIntervalMs: boundCookieTtl, ...(nativeSkipped && { nativeSkipped }) });
      }
      return ctx.json({ phase: "bound", sessionId, tier: session.tier, refreshIntervalMs: boundCookieTtl, ...(nativeSkipped && { nativeSkipped }) });
    },
  );

  // --- GET /dbsc-bound/challenge -----------------------------------------
  const dbscBoundChallenge = createAuthEndpoint(
    BOUND_CHALLENGE_PATH,
    { method: "GET" },
    async (ctx: any) => {
      ctx.setHeader("X-Server-Time", String(Date.now()));
      const storage = storageFromCtx(ctx);
      const cctx = ctx as unknown as CookieCtx;
      const sessionId = cookies.readBoundOrReg(cctx);
      if (!sessionId) throw new APIError("FORBIDDEN", { error: "no session" });
      const session = await storage.getSession(sessionId);
      if (!session) throw new APIError("FORBIDDEN", { error: "no session" });
      const challenge = await issueChallenge(sessionId, storage);
      return ctx.json({ challenge: challenge.jti });
    },
  );

  // --- POST /dbsc-bound/registration -------------------------------------
  const dbscBoundRegistration = createAuthEndpoint(
    BOUND_REGISTER_PATH,
    { method: "POST" },
    async (ctx: any) => {
      ctx.setHeader("X-Server-Time", String(Date.now()));
      const storage = storageFromCtx(ctx);
      const cctx = ctx as unknown as CookieCtx;
      const sessionId = cookies.readBoundOrReg(cctx);
      if (!sessionId) throw new APIError("BAD_REQUEST", { error: "missing session cookie" });
      const body = (ctx.body ?? {}) as { publicKey?: unknown; signature?: string; challenge?: string };
      if (!body.publicKey || !body.signature || !body.challenge) {
        throw new APIError("BAD_REQUEST", { error: "publicKey, signature, and challenge are required" });
      }
      const { publicKey, signature, challenge } = body as { publicKey: any; signature: string; challenge: string };
      try {
        await handleBoundRegistration({ sessionId, publicKey, signature, expectedJti: challenge }, storage);
        emit(onEvent, { type: "registration", sessionId, tier: "bound", timestamp: Date.now(), algorithm: "ES256", ip: "" });
        cookies.setBound(cctx, sessionId, boundCookieTtl);
        return ctx.json({ session_identifier: sessionId, refresh_url: boundRefreshUrl, tier: "bound" });
      } catch (err) {
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId, tier: "bound", timestamp: Date.now(), reason: err.code, ip: "" });
          throw new APIError("BAD_REQUEST", { error: err.message });
        }
        throw err;
      }
    },
  );

  // --- POST /dbsc-bound/refresh ------------------------------------------
  const dbscBoundRefresh = createAuthEndpoint(
    BOUND_REFRESH_PATH,
    { method: "POST" },
    async (ctx: any) => {
      ctx.setHeader("X-Server-Time", String(Date.now()));
      const storage = storageFromCtx(ctx);
      const cctx = ctx as unknown as CookieCtx;
      const sessionId = cookies.readBoundOrReg(cctx);
      if (!sessionId) throw new APIError("FORBIDDEN", { error: "no session" });
      const body = (ctx.body ?? {}) as { challenge?: string; signature?: string; timestamp?: number };
      if (!body.challenge || !body.signature || typeof body.timestamp !== "number") {
        throw new APIError("BAD_REQUEST", { error: "challenge, signature, and timestamp are required" });
      }
      const { challenge, signature, timestamp } = body as { challenge: string; signature: string; timestamp: number };
      try {
        await handleBoundRefresh({ sessionId, signature, expectedJti: challenge, timestamp }, storage);
        emit(onEvent, { type: "refresh", sessionId, tier: "bound", timestamp: Date.now(), ip: "" });
        cookies.setBound(cctx, sessionId, boundCookieTtl);
        return ctx.json({ session_identifier: sessionId, refresh_url: boundRefreshUrl, tier: "bound" });
      } catch (err) {
        const stolen = await storage.getBoundKey(sessionId);
        if (stolen && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
          emit(onEvent, { type: "session_stolen", sessionId, tier: "bound", timestamp: Date.now(), ip: "" });
        }
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          emit(onEvent, { type: "verification_failure", sessionId, tier: "bound", timestamp: Date.now(), reason: err.code, ip: "" });
          throw new APIError("UNAUTHORIZED", { error: err.message });
        }
        throw err;
      }
    },
  );

  return {
    dbscRegistration,
    dbscRefresh,
    dbscBoundState,
    dbscBoundChallenge,
    dbscBoundRegistration,
    dbscBoundRefresh,
  };
}

/** Build a plain headers record from ctx.headers (for core header parsers). */
function headersRecord(ctx: any): Record<string, string | string[] | undefined> {
  const h = ctx.headers;
  const out: Record<string, string | string[] | undefined> = {};
  if (h && typeof h.forEach === "function") {
    h.forEach((value: string, key: string) => { out[key.toLowerCase()] = value; });
  }
  return out;
}
