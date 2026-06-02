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
  issueChallenge,
  buildRegistrationHeader,
  REGISTRATION_HEADER,
  LEGACY_REGISTRATION_HEADER,
  resolveCookieNames,
  type StorageAdapter,
  type AnyTelemetryEvent,
} from "dbsc-toolkit";

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
  /** Path the polyfill SDK is served at, baked into the init shim. Default "/dbsc-client". */
  clientPath?: string;
  /** Telemetry hook */
  onEvent?: (event: AnyTelemetryEvent) => void | Promise<void>;
}

const REGISTRATION_PATH = "/dbsc/registration";
const DEFAULT_COOKIE_TTL = 600_000;
const DEFAULT_BASE_PATH = "/api/auth";

export function dbsc(opts: DbscPluginOptions = {}): object {
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
      `Max-Age=${Math.floor(cookieTtl / 1000)}`,
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

  return {
    id: "dbsc-toolkit",

    schema: dbscSchema,

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

            const store = createBetterAuthStorageAdapter(
              ctx.context.adapter,
              ctx.context.internalAdapter,
            );
            const now = Date.now();

            const existing = await store.getSession(sessionId);
            if (!existing) {
              await store.setSession({
                id: sessionId,
                userId,
                tier: "none",
                createdAt: now,
                expiresAt: now + cookieTtl,
                lastRefreshAt: now,
              });
            }

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
  } satisfies object;
}

