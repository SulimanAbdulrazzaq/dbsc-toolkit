/**
 * Client plugin for @dbsc-toolkit/better-auth.
 *
 * Provides TypeScript inference for the DBSC endpoints so your
 * Better Auth client knows about /dbsc/* and /dbsc-bound/* paths.
 *
 * Usage:
 *   import { createAuthClient } from "better-auth/client"
 *   import { dbscClient } from "@dbsc-toolkit/better-auth/client"
 *
 *   export const authClient = createAuthClient({
 *     plugins: [dbscClient()]
 *   })
 *
 * Then initialize the polyfill in your browser entry point:
 *   import { initBoundDbsc } from "dbsc-toolkit/client"
 *   initBoundDbsc({ baseUrl: "" })
 */

export function dbscClient() {
  return {
    id: "dbsc-toolkit",

    // Path → HTTP method map so Better Auth's client can infer the right fetch
    pathMethods: {
      "/dbsc/registration": "POST",
      "/dbsc/refresh": "POST",
      "/dbsc-bound/state": "GET",
      "/dbsc-bound/challenge": "GET",
      "/dbsc-bound/registration": "POST",
      "/dbsc-bound/refresh": "POST",
    } as const,

    getActions(fetch: (path: string, options?: RequestInit) => Promise<Response>) {
      return {
        dbsc: {
          /** Check bound state for the current session. */
          getBoundState: () => fetch("/dbsc-bound/state"),
          /** Manually trigger polyfill registration (normally automatic). */
          registerBound: (body: { sessionId: string; jwk: JsonWebKey; challenge: string }) =>
            fetch("/dbsc-bound/registration", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(body),
            }),
        },
      };
    },

    getAtoms() {
      // No reactive state atoms needed for DBSC — the binding happens
      // transparently in the background. Add nanostores here if you need
      // UI that reflects binding status.
      return {};
    },
  };
}
