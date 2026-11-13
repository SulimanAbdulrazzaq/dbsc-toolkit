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
import type { BetterAuthPlugin } from "better-auth";
import {
  issueChallenge,
  startBinding,
  buildRegistrationHeader,
  REGISTRATION_HEADER,
  LEGACY_REGISTRATION_HEADER,
  resolveCookieNames,
  type StorageAdapter,
  type AnyTelemetryEvent,
} from "dbsc-toolkit";

import {
  verifyDpopProof,
  dpopConfirmation,
  jwkThumbprint,
  runDpopGuard,
  parseDpopAuthorization,
  DPOP_WWW_AUTHENTICATE,
  type RequireDpopOptions,
} from "dbsc-toolkit/dpop";
import { MemoryReplayCache } from "dbsc-toolkit/storage/memory";

import { createAuthEndpoint } from "better-auth/api";

import { createBetterAuthStorageAdapter } from "./adapter.js";
import { dbscSchema } from "./schema.js";
import { makeCookies } from "./cookies.js";
import { buildDbscRoutes } from "./routes.js";
import { buildInitScript } from "./init-script.js";

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
  /** Max-Age (ms) for the cookies the after-hook writes. Default: 600_000 (10 min). */
  cookieTtl?: number;
  /** @deprecated alias for cookieTtl — removed in a future major */
  sessionTtl?: number;
  /** Bound cookie lifetime / refresh cadence (ms) used by the protocol routes. Default: 600_000. */
  boundCookieTtl?: number;
  /**
   * How long after sign-in (or after Chrome's native registration) the
   * polyfill key may still register, in ms. Default 300000. See
   * `boundRegistrationWindowMs` in dbsc-toolkit.
   */
  boundRegistrationWindowMs?: number;
  /**
   * Mount the Web Crypto polyfill routes. Default true. Set false to run
   * native DBSC only (Chromium 145+): the bound endpoints are not mounted
   * (the state endpoint answers `unbound`), non-Chromium browsers stay
   * unbound, and a `requireProof` imported from `dbsc-toolkit/<framework>`
   * must run with `bound: false` so it auto-relaxes the native `dbsc` tier.
   */
  bound?: boolean;
  /** Path the polyfill SDK is served at, baked into the init shim. Default "/dbsc-client". */
  clientPath?: string;
  /**
   * Optional DPoP (RFC 9449) support for bearer-token-bound API calls, separate
   * from DBSC's cookie binding. Off by default — leaving it unset keeps the
   * plugin's behavior byte-for-byte unchanged. When enabled, bind an access
   * token to a device key at issue time with `dpopConfirmation(jwk)` (embed the
   * returned `{ jkt }` as the token's `cnf.jkt`) and guard the resource route
   * with `dbscDpop.guard({ getBoundJkt })`, re-exported below. The token-issuing
   * and resource endpoints live in your app — Better Auth issues session tokens,
   * not OAuth bearers, so the bearer lifecycle stays yours.
   */
  /**
   * @deprecated Has no effect: the plugin never read it. Pass `iatWindowMs`
   * and the other DPoP options to `dbscDpop.verify()` instead.
   */
  dpop?: {
    enabled?: boolean;
    /** Acceptable DPoP proof `iat` window in ms. Default 300000. */
    iatWindowMs?: number;
  };
  /** Telemetry hook */
  onEvent?: (event: AnyTelemetryEvent) => void | Promise<void>;
}

const REGISTRATION_PATH = "/dbsc/registration";
const DEFAULT_COOKIE_TTL = 600_000;
const DEFAULT_BASE_PATH = "/api/auth";

export function dbsc(opts: DbscPluginOptions = {}): BetterAuthPlugin {
  const {
    basePath = DEFAULT_BASE_PATH,
    cookieScope = "host",
    cookieDomain,
  } = opts;
  // cookieTtl is the canonical name; sessionTtl is a deprecated alias.
  const cookieTtl = opts.cookieTtl ?? opts.sessionTtl ?? DEFAULT_COOKIE_TTL;
  const boundCookieTtl = opts.boundCookieTtl ?? DEFAULT_COOKIE_TTL;
  const clientPath = opts.clientPath ?? "/dbsc-client";

  const secure = true;
  const scopeOpts = cookieDomain
    ? { secure, cookieScope, cookieDomain }
    : { secure, cookieScope };
  const names = resolveCookieNames(scopeOpts);

  function regCookieHeader(sessionId: string): string {
    return [
      `${names.reg}=${sessionId}`,
      "HttpOnly",
      "Path=/",
      "SameSite=Lax",
      `Max-Age=${Math.floor(cookieTtl / 1000)}`,
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
      // Same lifetime the protocol routes use when they re-issue it.
      `Max-Age=${Math.floor(boundCookieTtl / 1000)}`,
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

  // The DBSC protocol routes live INSIDE the plugin via createAuthEndpoint, so
  // they work on every Better Auth runtime (Express, Fastify, Hono, Next.js…)
  // with zero per-framework setup. Native routes are declared bodyless — Chrome
  // sends the JWS in a header with an empty body, like Better Auth's own
  // sign-out route.
  const cookies = makeCookies({ secure, cookieScope, cookieDomain });
  const storageFromCtx = (ctx: any): StorageAdapter =>
    createBetterAuthStorageAdapter(ctx.context.adapter, ctx.context.internalAdapter);

  const protocolRoutes = buildDbscRoutes({
    storageFromCtx,
    cookies,
    basePath,
    boundCookieTtl,
    ...(opts.boundRegistrationWindowMs !== undefined && { boundRegistrationWindowMs: opts.boundRegistrationWindowMs }),
    ...(opts.bound !== undefined && { bound: opts.bound }),
    ...(opts.onEvent !== undefined && { onEvent: opts.onEvent }),
  });

  // Serve the browser init shim from an endpoint so it works on every runtime.
  // Return a raw Response so the Content-Type is JS (ctx.json forces JSON).
  const initJs = buildInitScript({ basePath, clientPath });
  const dbscClientInit = createAuthEndpoint(
    `${clientPath}/init.js`,
    { method: "GET" },
    async (ctx: any) =>
      ctx.json(
        new Response(initJs, {
          status: 200,
          headers: {
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=300",
          },
        }),
      ),
  );

  // Chrome's DBSC registration/refresh POSTs are browser-initiated and carry
  // NO Origin header (the JWS rides a header, the body is empty). Better Auth's
  // CSRF guard 403s any cookie-bearing POST without an Origin, which would kill
  // the native flow and force every Chrome user onto the bound polyfill. Skip
  // the origin check for the DBSC protocol paths only (prefix-matched, relative
  // to basePath), merged with whatever the app already configured.
  const dbscSkipPaths = ["/dbsc/", "/dbsc-bound/"];

  return {
    id: "dbsc-toolkit",

    schema: dbscSchema,

    init(ctx: any) {
      // Better Auth derives `context.skipOriginCheck` from
      // advanced.disableOriginCheck at context-creation time, BEFORE plugin
      // init runs — so merging into options here would be ignored. Set the
      // derived `context.skipOriginCheck` directly (init's `context` return is
      // Object.assign'd onto the live context), merging with whatever's there.
      const current = ctx?.skipOriginCheck;
      let skipOriginCheck: boolean | string[];
      if (current === true) {
        skipOriginCheck = true; // app already skips everything
      } else if (Array.isArray(current)) {
        skipOriginCheck = [...new Set([...current, ...dbscSkipPaths])];
      } else {
        skipOriginCheck = dbscSkipPaths;
      }
      return { context: { skipOriginCheck } };
    },

    endpoints: {
      ...protocolRoutes,
      dbscClientInit,
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
            let sessionExpiresAt: number | undefined;

            try {
              const result = await internalAdapter.findSession(token) as
                | { session?: { id?: string; userId?: string; expiresAt?: Date | string | number }; user?: { id?: string } }
                | null;
              sessionId = result?.session?.id;
              userId = result?.session?.userId ?? result?.user?.id;
              const exp = result?.session?.expiresAt;
              if (exp !== undefined) sessionExpiresAt = new Date(exp).getTime();
            } catch {
              return empty;
            }

            if (!sessionId || !userId) return empty;

            const store = createBetterAuthStorageAdapter(
              ctx.context.adapter,
              ctx.context.internalAdapter,
            );
            // A fresh binding per sign-in: the registration window starts now,
            // and the row's expiry tracks the Better Auth session.
            const ttl =
              sessionExpiresAt !== undefined && Number.isFinite(sessionExpiresAt)
                ? Math.max(1, sessionExpiresAt - Date.now())
                : cookieTtl;
            await startBinding(store, { sessionId, userId, sessionTtlMs: ttl });

            const { jti } = await issueChallenge(sessionId, store, cookieTtl);

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
  } satisfies BetterAuthPlugin;
}

/**
 * Opt-in DPoP (RFC 9449) helper for binding bearer access tokens to a device
 * key, alongside DBSC's cookie binding. Use from your own token-issuing and
 * resource endpoints — Better Auth issues session tokens, not OAuth bearers, so
 * the token lifecycle stays in your app.
 *
 *   // at issue time, after the device key is registered:
 *   const { jkt } = await dbscDpop.bind(deviceJwk);
 *   const token = await signJwt({ sub, cnf: { jkt } });
 *
 *   // in the resource endpoint (any runtime with a standard Request):
 *   const denied = await dbscDpop.verify(request, { getBoundJkt });
 *   if (denied) return denied; // 401 + WWW-Authenticate: DPoP
 */
// Default jti replay store for dbscDpop.verify(); pass a RedisReplayCache when
// running more than one instance.
const defaultDpopReplayCache = new MemoryReplayCache();

/**
 * Returns an `expectSessionId` hook for `requireProof()` from
 * `dbsc-toolkit/<framework>` that resolves the Better Auth session of the
 * request. Without it, the guard accepts a stolen Better Auth cookie paired
 * with the attacker's own bound DBSC session.
 *
 *   app.get("/profile", requireProof({ expectSessionId: expectBetterAuthSession(auth) }), handler)
 *
 * Works with Express/Node requests, Fastify requests, Hono contexts, Next.js
 * requests and SvelteKit events.
 */
export function expectBetterAuthSession(auth: {
  api: { getSession(input: { headers: Headers }): Promise<{ session?: { id?: string } } | null> };
}): (req: unknown) => Promise<string | undefined> {
  return async (req) => {
    const result = await auth.api.getSession({ headers: requestHeaders(req) });
    return result?.session?.id;
  };
}

function requestHeaders(req: unknown): Headers {
  const r = req as {
    headers?: unknown;
    req?: { raw?: Request };
    request?: { headers?: unknown };
  };
  if (r?.headers instanceof Headers) return r.headers;
  if (r?.req?.raw instanceof Request) return r.req.raw.headers;
  if (r?.request?.headers instanceof Headers) return r.request.headers;
  const out = new Headers();
  const raw = (r?.headers ?? {}) as Record<string, string | string[] | undefined>;
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined) continue;
    for (const item of Array.isArray(v) ? v : [v]) out.append(k, item);
  }
  return out;
}

export const dbscDpop = {
  /** Returns `{ jkt }` to embed as the access token's `cnf.jkt`. */
  bind: dpopConfirmation,
  /** Low-level: the RFC 7638 thumbprint of a JWK. */
  thumbprint: jwkThumbprint,
  /** Low-level: verify a DPoP proof directly. */
  verifyProof: verifyDpopProof,
  /**
   * Verify the DPoP proof on a standard `Request`. Returns a 401 `Response` to
   * return from the handler on failure, or `undefined` when the proof is valid.
   */
  async verify(
    request: Request,
    opts: RequireDpopOptions<Request> = {},
  ): Promise<Response | undefined> {
    const boundJkt = opts.getBoundJkt ? await opts.getBoundJkt(request) : undefined;
    const outcome = await runDpopGuard({
      proof: request.headers.get("DPoP") ?? undefined,
      authorization: request.headers.get("Authorization") ?? undefined,
      method: request.method,
      url: request.url,
      boundJkt,
      replayCache: opts.replayCache ?? defaultDpopReplayCache,
      opts: {
        ...(opts.requireTokenBinding !== undefined && { requireTokenBinding: opts.requireTokenBinding }),
        ...(opts.iatWindowMs !== undefined && { iatWindowMs: opts.iatWindowMs }),
        ...(opts.origin !== undefined && { origin: opts.origin }),
      },
    });
    if (outcome.ok) return undefined;
    return new Response(
      JSON.stringify({ error: "invalid_dpop_proof", code: outcome.error?.code }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": DPOP_WWW_AUTHENTICATE,
        },
      },
    );
  },
};

// Re-export the bearer-token Authorization parser for convenience.
export { parseDpopAuthorization };

