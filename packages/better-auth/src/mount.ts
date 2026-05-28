/**
 * mountDbscRoutes — install the DBSC protocol endpoints on any
 * Web-standard (Request → Response) framework: Hono, Cloudflare Workers,
 * Node.js + @hono/node-server, Bun, Deno, etc.
 *
 * Better Auth's createAuthEndpoint refuses POSTs without a body
 * (responds 415 Unsupported Media Type), and Chrome's DBSC
 * registration request carries the TPM-signed JWS in a header with
 * no body. So the protocol endpoints can't live inside the Better
 * Auth plugin — they need their own route layer.
 *
 * Usage:
 *   import { Hono } from "hono"
 *   import { mountDbscRoutes } from "@dbsc-toolkit/better-auth"
 *   import { auth } from "./auth"
 *
 *   const app = new Hono()
 *   mountDbscRoutes(app, auth, { basePath: "/api/auth" })
 *   app.all("/api/auth/:rest{.+}", (c) => auth.handler(c.req.raw))
 *
 * The routes are registered before the Better Auth catch-all so they
 * win the match.
 */
import {
  handleRegistration,
  handleRefresh,
  handleBoundRegistration,
  handleBoundRefresh,
  issueChallenge,
  buildChallengeHeader,
  verifyBoundProof,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  resolveCookieNames,
  type StorageAdapter,
  type ProofReplayCache,
} from "dbsc-toolkit";

import { createBetterAuthStorageAdapter } from "./adapter.js";

export interface MountDbscRoutesOptions {
  basePath?: string;
  cookieScope?: "host" | "site";
  cookieDomain?: string;
  sessionTtl?: number;
  replayCache?: ProofReplayCache;
}

/**
 * Minimal subset of Hono's app we depend on. Express adapter has the same
 * shape via app.post / app.get. Working against this shape keeps the helper
 * framework-agnostic.
 */
export interface MountableApp {
  get(path: string, handler: (c: any) => Promise<Response> | Response): unknown;
  post(path: string, handler: (c: any) => Promise<Response> | Response): unknown;
}

export interface AuthLike {
  $context: Promise<{
    adapter: any;
    internalAdapter: any;
  }>;
}

const DEFAULT_BASE_PATH = "/api/auth";
const DEFAULT_SESSION_TTL = 600_000;

export function mountDbscRoutes(
  app: MountableApp,
  auth: AuthLike,
  opts: MountDbscRoutesOptions = {},
): void {
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

  let storage: StorageAdapter | null = null;
  async function getStorage(): Promise<StorageAdapter> {
    if (!storage) {
      const ctx = await auth.$context;
      storage = createBetterAuthStorageAdapter(ctx.adapter, ctx.internalAdapter);
    }
    return storage;
  }

  function sessionCookieHeader(sessionId: string): string {
    return [
      `${names.bound}=${sessionId}`,
      "HttpOnly",
      "Path=/",
      "SameSite=Lax",
      `Max-Age=${Math.floor(sessionTtl / 1000)}`,
      "Secure",
      ...(cookieDomain ? [`Domain=${cookieDomain}`] : []),
    ].join("; ");
  }

  function sessionConfig(sessionId: string) {
    return {
      session_identifier: sessionId,
      refresh_url: `${basePath}/dbsc/refresh`,
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

  // ── Native DBSC ──────────────────────────────────────────────────

  app.post(`${basePath}/dbsc/registration`, async (c: any) => {
    const store = await getStorage();
    const cookies = parseCookies(c.req.header("cookie"));
    const sessionId = cookies[names.reg] ?? "";
    const expectedJti = cookies[names.challenge] ?? "";
    if (!sessionId || !expectedJti) {
      return c.json({ error: "missing session or challenge cookie" }, 400);
    }
    const challenge = await store.getChallenge(expectedJti);
    if (!challenge) return c.json({ error: "challenge not found" }, 400);
    const responseHeader =
      c.req.header("secure-session-response") ?? c.req.header("sec-session-response");
    try {
      await handleRegistration(
        { sessionId, secSessionResponseHeader: responseHeader, expectedJti },
        store,
      );
      c.header("Set-Cookie", sessionCookieHeader(sessionId));
      return c.json(sessionConfig(sessionId));
    } catch (err: any) {
      return c.json({ error: String(err?.message ?? err) }, 400);
    }
  });

  app.post(`${basePath}/dbsc/refresh`, async (c: any) => {
    const store = await getStorage();
    const sessionId =
      c.req.header("sec-secure-session-id") ?? c.req.header("secure-session-id") ?? "";

    if (!sessionId) {
      const ch = await issueChallenge("", store, sessionTtl);
      c.header(CHALLENGE_HEADER, buildChallengeHeader(ch.jti));
      c.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(ch.jti));
      return c.body(null, 403);
    }

    const responseHeader =
      c.req.header("secure-session-response") ?? c.req.header("sec-session-response");
    const challenge = await store.getChallenge(sessionId);

    if (!challenge || !responseHeader) {
      const ch = await issueChallenge(sessionId, store, sessionTtl);
      c.header(CHALLENGE_HEADER, buildChallengeHeader(ch.jti, sessionId));
      c.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(ch.jti, sessionId));
      return c.body(null, 403);
    }

    try {
      await handleRefresh(
        { sessionId, secSessionResponseHeader: responseHeader, expectedJti: challenge.jti },
        store,
      );
      c.header("Set-Cookie", sessionCookieHeader(sessionId));
      return c.json(sessionConfig(sessionId));
    } catch (err: any) {
      return c.json({ error: String(err?.message ?? err) }, 400);
    }
  });

  // ── Polyfill (Web Crypto) ────────────────────────────────────────

  app.get(`${basePath}/dbsc-bound/state`, async (c: any) => {
    c.header("X-Server-Time", String(Date.now()));
    const store = await getStorage();
    const cookies = parseCookies(c.req.header("cookie"));
    const sessionId = cookies[names.bound] ?? cookies[names.reg] ?? "";

    if (!sessionId) return c.json({ phase: "unbound", sessionId: null });

    const session = await store.getSession(sessionId);
    if (!session) return c.json({ phase: "unbound", sessionId: null });

    const nativeKey = await store.getBoundKey(sessionId, "native");
    const boundKey = await store.getBoundKey(sessionId, "bound");

    if (!nativeKey && !boundKey) {
      const ch = await issueChallenge(sessionId, store, sessionTtl);
      return c.json({ phase: "needs-registration", sessionId, challenge: ch.jti });
    }
    if (nativeKey && !boundKey) {
      const ch = await issueChallenge(sessionId, store, sessionTtl);
      return c.json({
        phase: "needs-bound-registration",
        sessionId,
        tier: session.tier,
        challenge: ch.jti,
        refreshIntervalMs: sessionTtl,
      });
    }
    return c.json({
      phase: "bound",
      sessionId,
      tier: session.tier,
      refreshIntervalMs: sessionTtl,
    });
  });

  app.get(`${basePath}/dbsc-bound/challenge`, async (c: any) => {
    c.header("X-Server-Time", String(Date.now()));
    const store = await getStorage();
    const cookies = parseCookies(c.req.header("cookie"));
    const sessionId = cookies[names.bound] ?? cookies[names.reg] ?? "";
    if (!sessionId) return c.json({ error: "no session" }, 403);
    const session = await store.getSession(sessionId);
    if (!session) return c.json({ error: "no session" }, 403);
    const ch = await issueChallenge(sessionId, store, sessionTtl);
    return c.json({ challenge: ch.jti });
  });

  app.post(`${basePath}/dbsc-bound/registration`, async (c: any) => {
    const store = await getStorage();
    const cookies = parseCookies(c.req.header("cookie"));
    const sessionId = cookies[names.bound] ?? cookies[names.reg] ?? "";
    if (!sessionId) return c.json({ error: "missing session" }, 400);
    const body = await c.req.json();
    try {
      await handleBoundRegistration(
        {
          sessionId,
          publicKey: body.publicKey,
          signature: body.signature,
          expectedJti: body.challenge,
        },
        store,
      );
      return c.json({ ok: true });
    } catch (err: any) {
      return c.json({ error: String(err?.message ?? err) }, 400);
    }
  });

  app.post(`${basePath}/dbsc-bound/refresh`, async (c: any) => {
    const store = await getStorage();
    const cookies = parseCookies(c.req.header("cookie"));
    const sessionId = cookies[names.bound] ?? cookies[names.reg] ?? "";
    if (!sessionId) return c.json({ error: "missing session" }, 400);
    const body = await c.req.json();
    try {
      await handleBoundRefresh(
        {
          sessionId,
          signature: body.signature,
          expectedJti: body.challenge,
          timestamp: body.timestamp,
        },
        store,
      );
      return c.json({ ok: true });
    } catch (err: any) {
      return c.json({ error: String(err?.message ?? err) }, 400);
    }
  });
}

/**
 * requireDbscProof — guard factory for app routes. Returns a handler that
 * verifies the X-Dbsc-Bound-Proof header against the session's bound key,
 * or returns 403 if missing/invalid.
 *
 *   app.get("/api/profile", requireDbscProof(auth), async (c) => { ... })
 */
export interface RequireDbscProofOptions {
  replayCache?: ProofReplayCache;
}

export function requireDbscProof(
  auth: AuthLike & { api: { getSession: (args: { headers: Headers }) => Promise<any> } },
  opts: RequireDbscProofOptions = {},
) {
  return async (c: any, next: () => Promise<void>): Promise<Response | void> => {
    const session = await auth.api.getSession({ headers: c.req.raw.headers });
    if (!session) return c.json({ error: "not authenticated" }, 401);

    const proofHeader = c.req.header("x-dbsc-bound-proof");
    if (!proofHeader) {
      return c.json({ error: "PROOF_MISSING" }, 403);
    }

    const ctx = await auth.$context;
    const storage = createBetterAuthStorageAdapter(ctx.adapter, ctx.internalAdapter);

    // boundFetch signs every request body (empty bytes for GET). Always verify
    // with signBody:true; the bh= field must always be present and match.
    const bodyBytes = new Uint8Array(await c.req.arrayBuffer());

    try {
      await verifyBoundProof(
        {
          sessionId: session.session.id,
          proofHeader,
          method: c.req.method,
          path: new URL(c.req.url).pathname,
          signBody: true,
          bodyBytes,
          ...(opts.replayCache ? { replayCache: opts.replayCache } : {}),
        },
        storage,
      );
    } catch (err: any) {
      return c.json({ error: "PROOF_INVALID", reason: String(err?.code ?? err?.message ?? err) }, 403);
    }

    // Body has been consumed for hashing; expose the raw bytes for the route.
    c.set("dbscBody", bodyBytes);
    await next();
  };
}

function parseCookies(header: string | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of (header ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    result[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return result;
}
