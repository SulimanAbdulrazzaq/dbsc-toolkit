/**
 * @dbsc-toolkit/better-auth
 *
 * DBSC (Device Bound Session Credentials) plugin for Better Auth.
 * Powered by dbsc-toolkit — hardware-bound sessions on Chromium 145+,
 * Web Crypto polyfill for Firefox/Safari/older Chromium.
 *
 * Usage:
 *   import { betterAuth } from "better-auth"
 *   import { dbsc } from "@dbsc-toolkit/better-auth"
 *
 *   export const auth = betterAuth({
 *     plugins: [dbsc()]
 *   })
 */
import {
  handleRegistration,
  handleRefresh,
  handleBoundRegistration,
  handleBoundRefresh,
  issueChallenge,
  buildRegistrationHeader,
  buildChallengeHeader,
  REGISTRATION_HEADER,
  CHALLENGE_HEADER,
  LEGACY_REGISTRATION_HEADER,
  LEGACY_CHALLENGE_HEADER,
  resolveCookieNames,
  type StorageAdapter,
  type AnyTelemetryEvent,
  type ProofReplayCache,
  type RateLimiter,
  NoopRateLimiter,
  NoopReplayCache,
  emit,
} from "dbsc-toolkit";
import { createAuthEndpoint } from "better-auth/api";

import { createBetterAuthStorageAdapter, type BetterAuthInternalAdapter } from "./adapter.js";
import { dbscSchema } from "./schema.js";

export interface DbscPluginOptions {
  /**
   * The base path where Better Auth is mounted. Default: "/api/auth".
   * Used to build the full registration path in the Secure-Session-Registration header.
   */
  basePath?: string;
  /** Cookie scope: "host" (default, __Host-) or "site" (__Secure- + Domain). */
  cookieScope?: "host" | "site";
  /** Required when cookieScope is "site". E.g. "example.com" */
  cookieDomain?: string;
  /** Bound cookie TTL in ms. Default: 600_000 (10 min) */
  sessionTtl?: number;
  /** Replay cache for per-request proofs. Default: NoopReplayCache */
  replayCache?: ProofReplayCache;
  /** Rate limiter for registration/refresh endpoints. Default: NoopRateLimiter */
  rateLimiter?: RateLimiter;
  /** Telemetry hook */
  onEvent?: (event: AnyTelemetryEvent) => void | Promise<void>;
}

// Plugin-relative paths — Better Auth prefixes these with basePath automatically
const REGISTRATION_PATH = "/dbsc/registration";
const REFRESH_PATH = "/dbsc/refresh";
const BOUND_STATE_PATH = "/dbsc-bound/state";
const BOUND_CHALLENGE_PATH = "/dbsc-bound/challenge";
const BOUND_REGISTRATION_PATH = "/dbsc-bound/registration";
const BOUND_REFRESH_PATH = "/dbsc-bound/refresh";

const DEFAULT_SESSION_TTL = 600_000;
const DEFAULT_BASE_PATH = "/api/auth";

export function dbsc(opts: DbscPluginOptions = {}): object {
  const {
    basePath = DEFAULT_BASE_PATH,
    cookieScope = "host",
    cookieDomain,
    sessionTtl = DEFAULT_SESSION_TTL,
    replayCache = new NoopReplayCache(),
    rateLimiter = new NoopRateLimiter(),
    onEvent,
  } = opts;

  const secure = true;
  const scopeOpts = cookieDomain
    ? { secure, cookieScope, cookieDomain }
    : { secure, cookieScope };
  const names = resolveCookieNames(scopeOpts);

  let storage: StorageAdapter | null = null;

  function getStorageFromCtx(ctx: any): StorageAdapter {
    if (!storage) {
      storage = createBetterAuthStorageAdapter(ctx.context.adapter, ctx.context.internalAdapter);
    }
    return storage;
  }

  function regCookieHeader(sessionId: string): string {
    return [
      `${names.reg}=${sessionId}`,
      "HttpOnly",
      "Path=/",
      "SameSite=Lax",
      `Max-Age=${Math.floor(sessionTtl / 1000)}`,
      ...(secure ? ["Secure"] : []),
      ...(cookieDomain ? [`Domain=${cookieDomain}`] : []),
    ].join("; ");
  }

  function sessionCookieHeader(sessionId: string): string {
    return [
      `${names.bound}=${sessionId}`,
      "HttpOnly",
      "Path=/",
      "SameSite=Lax",
      `Max-Age=${Math.floor(sessionTtl / 1000)}`,
      ...(secure ? ["Secure"] : []),
      ...(cookieDomain ? [`Domain=${cookieDomain}`] : []),
    ].join("; ");
  }

  function challengeCookieHeader(jti: string): string {
    return [
      `${names.challenge}=${jti}`,
      "HttpOnly",
      "Path=/",
      "SameSite=Lax",
      `Max-Age=300`,
      ...(secure ? ["Secure"] : []),
      ...(cookieDomain ? [`Domain=${cookieDomain}`] : []),
    ].join("; ");
  }

  function sessionConfig(sessionId: string) {
    return {
      session_identifier: sessionId,
      refresh_url: `${basePath}${REFRESH_PATH}`,
      scope: { include_site: cookieScope === "site" },
      credentials: [
        {
          type: "cookie",
          name: names.bound,
          attributes: [
            "Path=/",
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            `Max-Age=${Math.floor(sessionTtl / 1000)}`,
            ...(cookieDomain ? [`Domain=${cookieDomain}`] : []),
          ].join("; "),
        },
      ],
    };
  }

  return {
    id: "dbsc-toolkit",

    schema: dbscSchema,

    endpoints: {
      // Native DBSC: Chrome POSTs the TPM-signed JWS here after key generation.
      // Chrome sends an empty body — the JWS is in the Secure-Session-Response
      // header — so we list every content-type Chrome might attach (often none).
      dbscRegistration: createAuthEndpoint(
        REGISTRATION_PATH,
        {
          method: "POST",
          allowedMediaTypes: [
            "application/json",
            "application/x-www-form-urlencoded",
            "text/plain",
            "application/octet-stream",
            "",
          ],
        },
        async (ctx: any) => {
          const store = getStorageFromCtx(ctx);
          const cookies = parseCookies(ctx.request?.headers?.get?.("cookie") ?? "");
          const sessionId = cookies[names.reg] ?? "";
          const expectedJti = cookies[names.challenge] ?? "";
          if (!sessionId || !expectedJti) {
            return ctx.json({ error: "missing session or challenge cookie" }, { status: 400 });
          }

          const challenge = await store.getChallenge(expectedJti);
          if (!challenge) {
            return ctx.json({ error: "challenge not found" }, { status: 400 });
          }

          const responseHeader =
            ctx.request?.headers?.get?.("secure-session-response") ??
            ctx.request?.headers?.get?.("sec-session-response") ??
            undefined;

          try {
            const result = await handleRegistration(
              { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
              store,
            );

            emit(onEvent, {
              type: "registration",
              sessionId,
              tier: "dbsc",
              algorithm: result.boundKey.algorithm,
              ip: getIp(ctx),
              timestamp: Date.now(),
            });

            // Set the bound cookie and return the session config
            ctx.setHeader("Set-Cookie", sessionCookieHeader(sessionId));
            return ctx.json(sessionConfig(sessionId));
          } catch (err) {
            emit(onEvent, {
              type: "verification_failure",
              sessionId,
              tier: "none",
              reason: String(err),
              ip: getIp(ctx),
              timestamp: Date.now(),
            });
            return ctx.json({ error: "registration failed" }, { status: 400 });
          }
        },
      ),

      // Native DBSC: Chrome POSTs here when the bound cookie expires
      dbscRefresh: createAuthEndpoint(
        REFRESH_PATH,
        {
          method: "POST",
          allowedMediaTypes: [
            "application/json",
            "application/x-www-form-urlencoded",
            "text/plain",
            "application/octet-stream",
            "",
          ],
        },
        async (ctx: any) => {
          const store = getStorageFromCtx(ctx);
          const sessionId =
            ctx.request?.headers?.get?.("sec-secure-session-id") ??
            ctx.request?.headers?.get?.("secure-session-id") ??
            "";

          if (!sessionId) {
            const jti = await issueChallengeFor(store, "", sessionTtl);
            ctx.setHeader(CHALLENGE_HEADER, buildChallengeHeader(jti));
            ctx.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(jti));
            return ctx.json(null, { status: 403 });
          }

          const challenge = await store.getChallenge(sessionId);
          const responseHeader =
            ctx.request?.headers?.get?.("secure-session-response") ??
            ctx.request?.headers?.get?.("sec-session-response") ??
            undefined;

          if (!challenge || !responseHeader) {
            const jti = await issueChallengeFor(store, sessionId, sessionTtl);
            ctx.setHeader(CHALLENGE_HEADER, buildChallengeHeader(jti, sessionId));
            ctx.setHeader(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(jti, sessionId));
            return ctx.json(null, { status: 403 });
          }

          try {
            await handleRefresh(
              { sessionId, secSessionResponseHeader: responseHeader, expectedJti: challenge.jti },
              store,
            );

            emit(onEvent, {
              type: "refresh",
              sessionId,
              tier: "dbsc",
              ip: getIp(ctx),
              timestamp: Date.now(),
            });

            ctx.setHeader("Set-Cookie", sessionCookieHeader(sessionId));
            return ctx.json(sessionConfig(sessionId));
          } catch (err) {
            emit(onEvent, {
              type: "verification_failure",
              sessionId,
              tier: "none",
              reason: String(err),
              ip: getIp(ctx),
              timestamp: Date.now(),
            });
            return ctx.json({ error: "refresh failed" }, { status: 400 });
          }
        },
      ),

      // Polyfill: state check
      dbscBoundState: createAuthEndpoint(
        BOUND_STATE_PATH,
        { method: "GET" },
        async (ctx: any) => {
          const store = getStorageFromCtx(ctx);
          const cookies = parseCookies(ctx.request?.headers?.get?.("cookie") ?? "");
          const sessionId = cookies[names.bound] ?? "";
          if (!sessionId) return ctx.json({ phase: "unbound" });
          const session = await store.getSession(sessionId);
          if (!session) return ctx.json({ phase: "unbound" });
          const key = await store.getBoundKey(sessionId, "bound");
          return ctx.json({ phase: key ? "bound" : "unbound", tier: session.tier });
        },
      ),

      // Polyfill: issue challenge
      dbscBoundChallenge: createAuthEndpoint(
        BOUND_CHALLENGE_PATH,
        { method: "GET" },
        async (ctx: any) => {
          const store = getStorageFromCtx(ctx);
          const cookies = parseCookies(ctx.request?.headers?.get?.("cookie") ?? "");
          const sessionId = cookies[names.bound] ?? cookies[names.reg] ?? "";
          if (!sessionId) return ctx.json({ error: "no session" }, { status: 400 });
          const jti = await issueChallengeFor(store, sessionId, sessionTtl);
          return ctx.json({ challenge: jti, sessionId, serverTime: Date.now() });
        },
      ),

      // Polyfill: register the Web Crypto key
      dbscBoundRegistration: createAuthEndpoint(
        BOUND_REGISTRATION_PATH,
        { method: "POST", allowedMediaTypes: ["application/json"] },
        async (ctx: any) => {
          const store = getStorageFromCtx(ctx);
          const body = (await ctx.request?.json?.()) as Record<string, unknown>;
          const sessionId = String(body?.["sessionId"] ?? "");
          const publicKey = body?.["publicKey"] as JsonWebKey | undefined;
          const signature = String(body?.["signature"] ?? "");
          const expectedJti = String(body?.["challenge"] ?? "");
          if (!sessionId || !publicKey || !signature || !expectedJti) {
            return ctx.json({ error: "missing required fields" }, { status: 400 });
          }
          try {
            await handleBoundRegistration({ sessionId, publicKey, signature, expectedJti }, store);
            return ctx.json({ ok: true });
          } catch (err) {
            return ctx.json({ error: String(err) }, { status: 400 });
          }
        },
      ),

      // Polyfill: verify per-request proof
      dbscBoundRefresh: createAuthEndpoint(
        BOUND_REFRESH_PATH,
        { method: "POST", allowedMediaTypes: ["application/json"] },
        async (ctx: any) => {
          const store = getStorageFromCtx(ctx);
          const body = (await ctx.request?.json?.()) as Record<string, unknown>;
          const sessionId = String(body?.["sessionId"] ?? "");
          const signature = String(body?.["signature"] ?? "");
          const expectedJti = String(body?.["challenge"] ?? "");
          const timestamp = Number(body?.["timestamp"] ?? 0);
          if (!sessionId || !signature || !expectedJti || !timestamp) {
            return ctx.json({ error: "missing required fields" }, { status: 400 });
          }
          try {
            await handleBoundRefresh({ sessionId, signature, expectedJti, timestamp }, store);
            return ctx.json({ ok: true });
          } catch (err) {
            return ctx.json({ error: String(err) }, { status: 400 });
          }
        },
      ),
    },

    hooks: {
      after: [
        {
          // Fires after any endpoint whose response contains a token — sign-in,
          // sign-up, OAuth callback, magic link, passkey. Better Auth returns
          // { token, user } for all these paths.
          matcher: (ctx: any) => {
            const returned = ctx.context?.returned as Record<string, unknown> | undefined;
            const token = returned?.["token"];
            return typeof token === "string" && token.length > 0;
          },
          handler: async (ctx: any): Promise<{ headers: Headers }> => {
            const empty = { headers: new Headers() };
            const returned = ctx.context?.returned as Record<string, unknown> | undefined;
            const token = returned?.token as string | undefined;
            if (!token) return empty;

            const internalAdapter = ctx.context?.internalAdapter;
            if (!internalAdapter?.findSession) return empty;

            let sessionId: string | undefined;
            let userId: string | undefined;

            try {
              const result = await internalAdapter.findSession(token) as
                | { session?: { id?: string; userId?: string }; user?: { id?: string } }
                | null;
              sessionId = result?.session?.id;
              userId = result?.session?.userId ?? result?.user?.id;
            } catch {
              return empty;
            }

            if (!sessionId || !userId) return empty;

            const store = getStorageFromCtx(ctx);
            const now = Date.now();

            const existing = await store.getSession(sessionId);
            if (!existing) {
              await store.setSession({
                id: sessionId,
                userId,
                tier: "none",
                createdAt: now,
                expiresAt: now + sessionTtl,
                lastRefreshAt: now,
              });
            }

            const { jti } = await issueChallenge(sessionId, store, sessionTtl);

            const regHeader = buildRegistrationHeader({
              registrationPath: `${basePath}${REGISTRATION_PATH}`,
              challenge: jti,
              cookieName: names.bound,
            });

            // Return headers — Better Auth merges these into the response.
            // Three cookies:
            //   - __Host-dbsc-session: bound cookie Chrome watches
            //   - __Host-dbsc-reg: carries sessionId to /dbsc/registration
            //   - __Host-dbsc-challenge: carries jti to /dbsc/registration
            const headers = new Headers();
            headers.set(REGISTRATION_HEADER, regHeader);
            headers.set(LEGACY_REGISTRATION_HEADER, regHeader);
            headers.append("Set-Cookie", sessionCookieHeader(sessionId));
            headers.append("Set-Cookie", regCookieHeader(sessionId));
            headers.append("Set-Cookie", challengeCookieHeader(jti));

            return { headers };
          },
        },
      ],
    },
  } satisfies object;
}

// Helpers

async function issueChallengeFor(
  store: StorageAdapter,
  sessionId: string,
  ttlMs: number,
): Promise<string> {
  const challenge = await issueChallenge(sessionId, store, ttlMs);
  return challenge.jti;
}

function parseCookies(header: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    result[key] = value;
  }
  return result;
}

function getIp(ctx: any): string {
  return (
    ctx.request?.headers?.get?.("cf-connecting-ip") ??
    ctx.request?.headers?.get?.("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

