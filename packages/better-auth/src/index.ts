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

import { createBetterAuthStorageAdapter } from "./adapter.js";
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
  /** Telemetry hook */
  onEvent?: (event: AnyTelemetryEvent) => void | Promise<void>;
}

const REGISTRATION_PATH = "/dbsc/registration";
const DEFAULT_SESSION_TTL = 600_000;
const DEFAULT_BASE_PATH = "/api/auth";

export function dbsc(opts: DbscPluginOptions = {}): object {
  const {
    basePath = DEFAULT_BASE_PATH,
    cookieScope = "host",
    cookieDomain,
    sessionTtl = DEFAULT_SESSION_TTL,
  } = opts;

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

  return {
    id: "dbsc-toolkit",

    schema: dbscSchema,

    // The DBSC protocol routes do NOT live inside the plugin — Better Auth's
    // createAuthEndpoint refuses POSTs without a body (responds 415), and
    // Chrome's registration request has the JWS in a header with no body.
    // Use mountDbscRoutes(app, auth) on your Hono/Express app instead.

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

