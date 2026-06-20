import { describe, it, expect } from "vitest";
import express from "express";
import cookieParser from "cookie-parser";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { dbsc, bindSession, requireBoundProof, requireProof, createDbsc } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

async function startServer(register: (app: express.Application, storage: MemoryStorage) => void) {
  const storage = new MemoryStorage();
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  app.use(dbsc({ storage, secure: false }));
  register(app, storage);
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    storage,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function parseSetCookie(setCookie: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of setCookie) {
    const [pair] = c.split(";");
    const [k, v] = pair!.split("=");
    if (k && v) out[k] = v;
  }
  return out;
}

function cookieHeader(jar: Record<string, string>): string {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
}

function b64url(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return Buffer.from(s, "binary").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function signMessage(privateKey: CryptoKey, message: string): Promise<string> {
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
  );
  return b64url(new Uint8Array(sig));
}

describe("GET /dbsc-bound/state", () => {
  it("returns phase: unbound when no session cookie is set", async () => {
    const ctx = await startServer(() => {});
    try {
      const res = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toEqual({ phase: "unbound", sessionId: null });
    } finally {
      await ctx.close();
    }
  });

  it("emits X-Server-Time response header", async () => {
    const ctx = await startServer(() => {});
    try {
      const before = Date.now();
      const res = await fetch(`${ctx.url}/dbsc-bound/state`);
      const after = Date.now();
      const serverTime = Number(res.headers.get("X-Server-Time"));
      expect(serverTime).toBeGreaterThanOrEqual(before);
      expect(serverTime).toBeLessThanOrEqual(after);
    } finally {
      await ctx.close();
    }
  });

  it("returns nativeSkipped when client sends Secure-Session-Skipped", async () => {
    const ctx = await startServer(() => {});
    try {
      const res = await fetch(`${ctx.url}/dbsc-bound/state`, {
        headers: {
          "Secure-Session-Skipped": `quota_exceeded;session_identifier="abc"`,
        },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.nativeSkipped).toEqual(["quota_exceeded"]);
    } finally {
      await ctx.close();
    }
  });

  it("returns phase: needs-registration after bindSession", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-state-1", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
    });
    try {
      const loginRes = await fetch(`${ctx.url}/login`, { method: "POST" });
      const setCookie = loginRes.headers.getSetCookie?.() ?? [];
      const jar = parseSetCookie(setCookie);
      const stateRes = await fetch(`${ctx.url}/dbsc-bound/state`, {
        headers: { Cookie: cookieHeader(jar) },
      });
      const body = await stateRes.json();
      expect(body.phase).toBe("needs-registration");
      expect(body.sessionId).toBe("sess-state-1");
      expect(body.challenge).toBeTruthy();
    } finally {
      await ctx.close();
    }
  });

  // v2.7+: a native-bound (dbsc) session without a polyfill key triggers
  // the new needs-bound-registration phase so the client co-registers a
  // polyfill key for requireProof(). Modelled directly via storage —
  // the state route reads from the reg cookie when the bound cookie isn't
  // set yet, which is the early-in-the-flow shape we want here.
  it("returns phase: needs-bound-registration when only a native key exists", async () => {
    const sessionId = "sess-state-dual";
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, sessionId, storage, { userId: "u1", secure: false });
        await storage.setBoundKey({
          sessionId,
          kind: "native",
          jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
          algorithm: "ES256",
          createdAt: Date.now(),
        });
        const s = await storage.getSession(sessionId);
        await storage.setSession({ ...s!, tier: "dbsc", lastRefreshAt: Date.now() });
        res.json({ ok: true });
      });
    });
    try {
      const loginRes = await fetch(`${ctx.url}/login`, { method: "POST" });
      const jar = parseSetCookie(loginRes.headers.getSetCookie?.() ?? []);
      const stateRes = await fetch(`${ctx.url}/dbsc-bound/state`, {
        headers: { Cookie: cookieHeader(jar) },
      });
      const body = await stateRes.json();
      expect(body.phase).toBe("needs-bound-registration");
      expect(body.tier).toBe("dbsc");
      expect(body.challenge).toBeTruthy();
    } finally {
      await ctx.close();
    }
  });

  // Late-native-arrival race: the polyfill registered first (so the session row
  // reads tier="bound"), then Chrome's native key landed. With both keys present
  // the state route must report tier="dbsc" — a native key is authoritative — so
  // the client SDK resolves native-dbsc without waiting for the next refresh.
  it("reports tier: dbsc when a native key exists even if the row says bound", async () => {
    const sessionId = "sess-state-native-after-bound";
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, sessionId, storage, { userId: "u1", secure: false });
        // Polyfill won the race: bound key stored, session pinned to bound.
        await storage.setBoundKey({
          sessionId,
          kind: "bound",
          jwk: { kty: "EC", crv: "P-256", x: "bx", y: "by" },
          algorithm: "ES256",
          createdAt: Date.now(),
        });
        const s1 = await storage.getSession(sessionId);
        await storage.setSession({ ...s1!, tier: "bound", lastRefreshAt: Date.now() });
        // Native key arrives afterwards; tier on the row is still "bound".
        await storage.setBoundKey({
          sessionId,
          kind: "native",
          jwk: { kty: "EC", crv: "P-256", x: "nx", y: "ny" },
          algorithm: "ES256",
          createdAt: Date.now(),
        });
        res.json({ ok: true });
      });
    });
    try {
      const loginRes = await fetch(`${ctx.url}/login`, { method: "POST" });
      const jar = parseSetCookie(loginRes.headers.getSetCookie?.() ?? []);
      const stateRes = await fetch(`${ctx.url}/dbsc-bound/state`, {
        headers: { Cookie: cookieHeader(jar) },
      });
      const body = await stateRes.json();
      expect(body.phase).toBe("bound");
      expect(body.tier).toBe("dbsc");
    } finally {
      await ctx.close();
    }
  });
});

async function registerBoundSession(ctx: Awaited<ReturnType<typeof startServer>>) {
  const loginRes = await fetch(`${ctx.url}/login`, { method: "POST" });
  const setCookie = loginRes.headers.getSetCookie?.() ?? [];
  const jar = parseSetCookie(setCookie);

  const stateRes = await fetch(`${ctx.url}/dbsc-bound/state`, {
    headers: { Cookie: cookieHeader(jar) },
  });
  const state = await stateRes.json();
  expect(state.phase).toBe("needs-registration");

  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const signature = await signMessage(pair.privateKey, state.challenge);

  const regRes = await fetch(`${ctx.url}/dbsc-bound/registration`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookieHeader(jar) },
    body: JSON.stringify({ publicKey, signature, challenge: state.challenge }),
  });
  expect(regRes.status).toBe(200);
  const regSet = regRes.headers.getSetCookie?.() ?? [];
  const regJar = parseSetCookie(regSet);
  Object.assign(jar, regJar);
  return { jar, privateKey: pair.privateKey, sessionId: state.sessionId as string };
}

describe("POST /dbsc-bound/registration", () => {
  it("happy path: stores BoundKey, flips session tier to bound, sets bound cookie", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-reg-1", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
    });
    try {
      const { sessionId } = await registerBoundSession(ctx);
      const session = await ctx.storage.getSession(sessionId);
      expect(session?.tier).toBe("bound");
      const key = await ctx.storage.getBoundKey(sessionId);
      expect(key).toBeTruthy();
      expect(key?.algorithm).toBe("ES256");
    } finally {
      await ctx.close();
    }
  });

  it("rejects when publicKey is missing", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-reg-2", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
    });
    try {
      const loginRes = await fetch(`${ctx.url}/login`, { method: "POST" });
      const jar = parseSetCookie(loginRes.headers.getSetCookie?.() ?? []);
      const stateRes = await fetch(`${ctx.url}/dbsc-bound/state`, { headers: { Cookie: cookieHeader(jar) } });
      const state = await stateRes.json();
      const regRes = await fetch(`${ctx.url}/dbsc-bound/registration`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookieHeader(jar) },
        body: JSON.stringify({ signature: "x", challenge: state.challenge }),
      });
      expect(regRes.status).toBe(400);
    } finally {
      await ctx.close();
    }
  });
});

describe("POST /dbsc-bound/refresh", () => {
  it("happy path: updates lastRefreshAt, keeps tier=bound", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-ref-1", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
    });
    try {
      const { jar, privateKey, sessionId } = await registerBoundSession(ctx);
      const before = (await ctx.storage.getSession(sessionId))!.lastRefreshAt;
      await new Promise((r) => setTimeout(r, 10));

      const challengeRes = await fetch(`${ctx.url}/dbsc-bound/challenge`, {
        headers: { Cookie: cookieHeader(jar) },
      });
      const { challenge } = await challengeRes.json();
      const ts = Date.now();
      const sig = await signMessage(privateKey, `${challenge}.${ts}`);

      const refRes = await fetch(`${ctx.url}/dbsc-bound/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookieHeader(jar) },
        body: JSON.stringify({ challenge, signature: sig, timestamp: ts }),
      });
      expect(refRes.status).toBe(200);

      const after = (await ctx.storage.getSession(sessionId))!.lastRefreshAt;
      expect(after).toBeGreaterThan(before);
    } finally {
      await ctx.close();
    }
  });
});

describe("requireBoundProof middleware", () => {
  it("rejects tier=none with 403", async () => {
    const ctx = await startServer((app, storage) => {
      app.get("/strict", requireBoundProof({ storage }), (_req, res) => res.json({ ok: true }));
    });
    try {
      const res = await fetch(`${ctx.url}/strict`);
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.error).toBe("no active binding");
    } finally {
      await ctx.close();
    }
  });

  it("passes tier=bound when proof is valid", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-pr-1", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.get("/strict", requireBoundProof({ storage }), (_req, res) => res.json({ ok: true }));
    });
    try {
      const { jar, privateKey, sessionId } = await registerBoundSession(ctx);
      const ts = Date.now();
      const message = `${sessionId}.GET./strict.${ts}`;
      const sig = await signMessage(privateKey, message);

      const res = await fetch(`${ctx.url}/strict`, {
        headers: {
          Cookie: cookieHeader(jar),
          "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig}`,
        },
      });
      expect(res.status).toBe(200);
    } finally {
      await ctx.close();
    }
  });

  it("rejects tier=bound with MISSING_PROOF when no header is sent", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-pr-2", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.get("/strict", requireBoundProof({ storage }), (_req, res) => res.json({ ok: true }));
    });
    try {
      const { jar } = await registerBoundSession(ctx);
      const res = await fetch(`${ctx.url}/strict`, { headers: { Cookie: cookieHeader(jar) } });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.code).toBe("MISSING_PROOF");
    } finally {
      await ctx.close();
    }
  });

  it("signBody: rejects substituted body", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-pr-3", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.post(
        "/pay",
        express.raw({ type: "*/*" }),
        requireBoundProof({ storage, signBody: true }),
        (_req, res) => res.json({ ok: true }),
      );
    });
    try {
      const { jar, privateKey, sessionId } = await registerBoundSession(ctx);
      const signedBody = '{"amount":1}';
      const sentBody = '{"amount":1000}';
      const ts = Date.now();
      const signedBytes = new TextEncoder().encode(signedBody);
      const bh = b64url(new Uint8Array(createHash("sha256").update(signedBytes).digest()));
      const message = `${sessionId}.POST./pay.${ts}.${bh}`;
      const sig = await signMessage(privateKey, message);

      const res = await fetch(`${ctx.url}/pay`, {
        method: "POST",
        headers: {
          Cookie: cookieHeader(jar),
          "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}`,
          "Content-Type": "application/octet-stream",
        },
        body: sentBody,
      });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.code).toBe("SIGNATURE_INVALID");
    } finally {
      await ctx.close();
    }
  });

  // v2.7+ default flip: dbsc tier no longer passes through without proof.
  // Set up a fully-bound session, then promote it to tier="dbsc" to model
  // a Chromium session that has completed native DBSC + the polyfill co-reg.
  it("rejects a dbsc-tier session that sends no proof header (v2.7 default)", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-pr-dbsc-default", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.get("/strict", requireBoundProof({ storage }), (_req, res) => res.json({ ok: true }));
    });
    try {
      const { jar, sessionId } = await registerBoundSession(ctx);
      const s = await ctx.storage.getSession(sessionId);
      await ctx.storage.setSession({ ...s!, tier: "dbsc", lastRefreshAt: Date.now() });

      const res = await fetch(`${ctx.url}/strict`, { headers: { Cookie: cookieHeader(jar) } });
      expect(res.status).toBe(403);
      const body = await res.json();
      expect(body.code).toBe("MISSING_PROOF");
    } finally {
      await ctx.close();
    }
  });

  it("allowDbscWithoutProof: true reinstates the v2.6 escape hatch", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-pr-dbsc-escape", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.get(
        "/legacy",
        requireBoundProof({ storage, allowDbscWithoutProof: true }),
        (_req, res) => res.json({ ok: true }),
      );
    });
    try {
      const { jar, sessionId } = await registerBoundSession(ctx);
      const s = await ctx.storage.getSession(sessionId);
      await ctx.storage.setSession({ ...s!, tier: "dbsc", lastRefreshAt: Date.now() });

      const res = await fetch(`${ctx.url}/legacy`, { headers: { Cookie: cookieHeader(jar) } });
      expect(res.status).toBe(200);
    } finally {
      await ctx.close();
    }
  });

  it("signBody: accepts matching body", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "sess-pr-4", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.post(
        "/pay",
        express.raw({ type: "*/*" }),
        requireBoundProof({ storage, signBody: true }),
        (_req, res) => res.json({ ok: true }),
      );
    });
    try {
      const { jar, privateKey, sessionId } = await registerBoundSession(ctx);
      const payload = '{"amount":1}';
      const bytes = new TextEncoder().encode(payload);
      const ts = Date.now();
      const bh = b64url(new Uint8Array(createHash("sha256").update(bytes).digest()));
      const message = `${sessionId}.POST./pay.${ts}.${bh}`;
      const sig = await signMessage(privateKey, message);

      // Use application/octet-stream so the global express.json() parser skips
      // it and the route-level express.raw({ type: "*/*" }) captures the body
      // bytes unchanged. Real apps using signBody mount raw before json or
      // bypass json on signed routes — see docs/per-request-signing.md.
      const res = await fetch(`${ctx.url}/pay`, {
        method: "POST",
        headers: {
          Cookie: cookieHeader(jar),
          "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}`,
          "Content-Type": "application/octet-stream",
        },
        body: payload,
      });
      expect(res.status).toBe(200);
    } finally {
      await ctx.close();
    }
  });
});

describe("refreshGraceMs", () => {
  // A server with a tiny TTL and an explicit grace window, plus a /tier route
  // that echoes res.locals.dbsc.tier so the freshness check is observable.
  async function startGraceServer(boundCookieTtl: number, refreshGraceMs: number) {
    const storage = new MemoryStorage();
    const app = express();
    app.use(cookieParser());
    app.use(express.json());
    app.use(dbsc({ storage, secure: false, boundCookieTtl, refreshGraceMs }));
    app.get("/tier", (_req, res) => res.json({ tier: res.locals.dbsc.tier }));
    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const { port } = server.address() as AddressInfo;
    return {
      storage,
      url: `http://127.0.0.1:${port}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  it("keeps tier alive within boundCookieTtl + refreshGraceMs, demotes past it", async () => {
    const boundCookieTtl = 1_000;
    const refreshGraceMs = 5_000;
    const ctx = await startGraceServer(boundCookieTtl, refreshGraceMs);
    try {
      // Seed a bound session whose last refresh is old enough that the cookie
      // TTL has lapsed but the grace window has not.
      const now = Date.now();
      await ctx.storage.setSession({
        id: "grace-1",
        userId: "u1",
        tier: "bound",
        createdAt: now - 10_000,
        expiresAt: now + 60_000,
        lastRefreshAt: now - (boundCookieTtl + 2_000), // 2s into the 5s grace
      });

      const inGrace = await fetch(`${ctx.url}/tier`, {
        headers: { Cookie: "dbsc-session=grace-1" },
      });
      expect((await inGrace.json()).tier).toBe("bound");

      // Now push lastRefreshAt past the grace window entirely.
      const sess = (await ctx.storage.getSession("grace-1"))!;
      await ctx.storage.setSession({
        ...sess,
        lastRefreshAt: now - (boundCookieTtl + refreshGraceMs + 2_000),
      });

      const pastGrace = await fetch(`${ctx.url}/tier`, {
        headers: { Cookie: "dbsc-session=grace-1" },
      });
      expect((await pastGrace.json()).tier).toBe("none");
    } finally {
      await ctx.close();
    }
  });

  it("refreshGraceMs: 0 demotes the instant the cookie TTL lapses", async () => {
    const boundCookieTtl = 1_000;
    const ctx = await startGraceServer(boundCookieTtl, 0);
    try {
      const now = Date.now();
      await ctx.storage.setSession({
        id: "grace-2",
        userId: "u1",
        tier: "bound",
        createdAt: now - 10_000,
        expiresAt: now + 60_000,
        lastRefreshAt: now - (boundCookieTtl + 500), // 0.5s past TTL, no grace
      });

      const res = await fetch(`${ctx.url}/tier`, {
        headers: { Cookie: "dbsc-session=grace-2" },
      });
      expect((await res.json()).tier).toBe("none");
    } finally {
      await ctx.close();
    }
  });
});

describe("requireProof", () => {
  it("rejects tier=none with 403", async () => {
    const ctx = await startServer((app) => {
      app.get("/g", requireProof(), (_req, res) => res.json({ ok: true }));
    });
    try {
      const res = await fetch(`${ctx.url}/g`);
      expect(res.status).toBe(403);
      expect((await res.json()).currentTier).toBe("none");
    } finally {
      await ctx.close();
    }
  });

  it("rejects a bound session that sends no proof header", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "rp-noproof-1", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.get("/g", requireProof(), (_req, res) => res.json({ ok: true }));
    });
    try {
      const { jar } = await registerBoundSession(ctx);
      const res = await fetch(`${ctx.url}/g`, { headers: { Cookie: cookieHeader(jar) } });
      expect(res.status).toBe(403);
    } finally {
      await ctx.close();
    }
  });

  it("passes a bound session with a valid proof — storage from the middleware, no re-passing", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "rp-proof-1", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.get("/g", requireProof(), (_req, res) => res.json({ ok: true }));
    });
    try {
      const { jar, privateKey, sessionId } = await registerBoundSession(ctx);
      // requireProof signs the body — a GET has none, so the hash is of empty bytes.
      const ts = Date.now();
      const bh = b64url(new Uint8Array(createHash("sha256").update(new Uint8Array(0)).digest()));
      const sig = await signMessage(privateKey, `${sessionId}.GET./g.${ts}.${bh}`);
      const res = await fetch(`${ctx.url}/g`, {
        headers: { Cookie: cookieHeader(jar), "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}` },
      });
      expect(res.status).toBe(200);
    } finally {
      await ctx.close();
    }
  });

  it("on a POST enforces body signing", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, res) => {
        await bindSession(res, "rp-pay-1", storage, { userId: "u1", secure: false });
        res.json({ ok: true });
      });
      app.post(
        "/pay",
        express.raw({ type: "*/*" }),
        requireProof(),
        (_req, res) => res.json({ ok: true }),
      );
    });
    try {
      const { jar, privateKey, sessionId } = await registerBoundSession(ctx);
      const payload = '{"amount":1}';
      const bytes = new TextEncoder().encode(payload);
      const ts = Date.now();
      const bh = b64url(new Uint8Array(createHash("sha256").update(bytes).digest()));
      const sig = await signMessage(privateKey, `${sessionId}.POST./pay.${ts}.${bh}`);
      const res = await fetch(`${ctx.url}/pay`, {
        method: "POST",
        headers: {
          Cookie: cookieHeader(jar),
          "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}`,
          "Content-Type": "application/octet-stream",
        },
        body: payload,
      });
      expect(res.status).toBe(200);
    } finally {
      await ctx.close();
    }
  });
});

describe("createDbsc", () => {
  async function startKitServer(register: (app: express.Application, kit: ReturnType<typeof createDbsc>) => void) {
    const storage = new MemoryStorage();
    const app = express();
    const kit = createDbsc({ storage, secure: false, clientPath: false });
    kit.install(app);
    register(app, kit);
    const server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const { port } = server.address() as AddressInfo;
    return {
      storage,
      url: `http://127.0.0.1:${port}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    };
  }

  it("install() mounts the protocol routes", async () => {
    const ctx = await startKitServer(() => {});
    try {
      const res = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect(res.status).toBe(200);
      expect((await res.json()).phase).toBe("unbound");
    } finally {
      await ctx.close();
    }
  });

  it("bind() without a sessionId: two browsers derive different ids, same browser re-derives the same id", async () => {
    const ctx = await startKitServer((app, kit) => {
      app.post("/login", async (_req, res) => {
        const sid = await kit.bind(res, { userId: "user-42" });
        res.json({ sid });
      });
    });
    try {
      // Browser A — no device cookie sent → kit mints one and returns it.
      const resA = await fetch(`${ctx.url}/login`, { method: "POST" });
      const a = await resA.json();
      const deviceCookie = (resA.headers.getSetCookie?.() ?? [])
        .map((c) => c.split(";")[0])
        .find((c) => c!.startsWith("dbsc-device="));
      expect(a.sid).toBeTruthy();
      expect(deviceCookie).toBeTruthy();
      expect(await ctx.storage.getSession(a.sid)).toBeTruthy();

      // Browser B — a separate browser, no device cookie → different derived id.
      const b = await (await fetch(`${ctx.url}/login`, { method: "POST" })).json();
      expect(b.sid).not.toBe(a.sid);

      // Browser A again — carries its device cookie → same derived id.
      const a2 = await (
        await fetch(`${ctx.url}/login`, { method: "POST", headers: { Cookie: deviceCookie! } })
      ).json();
      expect(a2.sid).toBe(a.sid);
    } finally {
      await ctx.close();
    }
  });
});
