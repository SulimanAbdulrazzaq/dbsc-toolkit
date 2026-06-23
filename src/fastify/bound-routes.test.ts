import { describe, it, expect } from "vitest";
import Fastify, { type FastifyInstance } from "fastify";
import fastifyCookie from "@fastify/cookie";
import { createHash } from "node:crypto";
import { dbsc, bindSession, requireBoundProof, requireProof, createDbsc } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

async function startServer(register: (app: FastifyInstance, storage: MemoryStorage) => void) {
  const storage = new MemoryStorage();
  const app = Fastify();
  await app.register(fastifyCookie);
  await app.register(dbsc, { storage, secure: false });
  register(app, storage);
  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return {
    storage,
    url: `http://127.0.0.1:${port}`,
    close: () => app.close(),
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

describe("Fastify GET /dbsc-bound/state", () => {
  it("returns phase: unbound and emits X-Server-Time", async () => {
    const ctx = await startServer(() => {});
    try {
      const res = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect(res.status).toBe(200);
      expect(res.headers.get("X-Server-Time")).toBeTruthy();
      const body = await res.json();
      expect(body.phase).toBe("unbound");
    } finally {
      await ctx.close();
    }
  });

  it("returns nativeSkipped when client sends Secure-Session-Skipped", async () => {
    const ctx = await startServer(() => {});
    try {
      const res = await fetch(`${ctx.url}/dbsc-bound/state`, {
        headers: { "Secure-Session-Skipped": `quota_exceeded;session_identifier="abc"` },
      });
      const body = await res.json();
      expect(body.nativeSkipped).toEqual(["quota_exceeded"]);
    } finally {
      await ctx.close();
    }
  });
});

async function registerBoundSession(ctx: Awaited<ReturnType<typeof startServer>>) {
  const loginRes = await fetch(`${ctx.url}/login`, { method: "POST" });
  const jar = parseSetCookie(loginRes.headers.getSetCookie?.() ?? []);

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
  Object.assign(jar, parseSetCookie(regRes.headers.getSetCookie?.() ?? []));
  return { jar, privateKey: pair.privateKey, sessionId: state.sessionId as string };
}

describe("Fastify POST /dbsc-bound/registration + /refresh", () => {
  it("registration stores BoundKey + flips tier to bound", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, reply) => {
        await bindSession(reply, "fst-reg-1", storage, { userId: "u1", secure: false });
        return { ok: true };
      });
    });
    try {
      const { sessionId } = await registerBoundSession(ctx);
      const session = await ctx.storage.getSession(sessionId);
      expect(session?.tier).toBe("bound");
    } finally {
      await ctx.close();
    }
  });

  it("refresh updates lastRefreshAt", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, reply) => {
        await bindSession(reply, "fst-ref-1", storage, { userId: "u1", secure: false });
        return { ok: true };
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

describe("Fastify requireBoundProof preHandler", () => {
  it("rejects tier=none with 403", async () => {
    const ctx = await startServer((app, storage) => {
      app.get(
        "/strict",
        { preHandler: requireBoundProof({ storage }) },
        async () => ({ ok: true }),
      );
    });
    try {
      const res = await fetch(`${ctx.url}/strict`);
      expect(res.status).toBe(403);
    } finally {
      await ctx.close();
    }
  });

  it("passes tier=bound with valid proof", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, reply) => {
        await bindSession(reply, "fst-pr-1", storage, { userId: "u1", secure: false });
        return { ok: true };
      });
      app.get(
        "/strict",
        { preHandler: requireBoundProof({ storage }) },
        async () => ({ ok: true }),
      );
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

  it("rejects MISSING_PROOF when header is absent", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, reply) => {
        await bindSession(reply, "fst-pr-2", storage, { userId: "u1", secure: false });
        return { ok: true };
      });
      app.get(
        "/strict",
        { preHandler: requireBoundProof({ storage }) },
        async () => ({ ok: true }),
      );
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
      app.post("/login", async (_req, reply) => {
        await bindSession(reply, "fst-pr-3", storage, { userId: "u1", secure: false });
        return { ok: true };
      });
      app.addContentTypeParser(
        "application/octet-stream",
        { parseAs: "buffer" },
        (_req, body, done) => done(null, body),
      );
      app.post(
        "/pay",
        { preHandler: requireBoundProof({ storage, signBody: true }) },
        async () => ({ ok: true }),
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
});

describe("Fastify requireProof", () => {
  it("rejects tier=none", async () => {
    const ctx = await startServer((app) => {
      app.get("/g", { preHandler: requireProof() }, async () => ({ ok: true }));
    });
    try {
      const res = await fetch(`${ctx.url}/g`);
      expect(res.status).toBe(403);
      expect((await res.json()).currentTier).toBe("none");
    } finally {
      await ctx.close();
    }
  });

  it("rejects a bound session that sends no proof", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, reply) => {
        await bindSession(reply, "ft-rp-1", storage, { userId: "u1", secure: false });
        return { ok: true };
      });
      app.get("/g", { preHandler: requireProof() }, async () => ({ ok: true }));
    });
    try {
      const { jar } = await registerBoundSession(ctx);
      const res = await fetch(`${ctx.url}/g`, { headers: { Cookie: cookieHeader(jar) } });
      expect(res.status).toBe(403);
    } finally {
      await ctx.close();
    }
  });

  it("passes a bound session with a valid proof — storage from the plugin", async () => {
    const ctx = await startServer((app, storage) => {
      app.post("/login", async (_req, reply) => {
        await bindSession(reply, "ft-rp-2", storage, { userId: "u1", secure: false });
        return { ok: true };
      });
      app.get("/g", { preHandler: requireProof() }, async () => ({ ok: true }));
    });
    try {
      const { jar, privateKey, sessionId } = await registerBoundSession(ctx);
      // requireProof signs the body — a GET has none, so the hash is of empty bytes.
      const ts = Date.now();
      const bh = b64url(new Uint8Array(createHash("sha256").update(new Uint8Array(0)).digest()));
      const sig = await signMessage(privateKey, `${sessionId}.GET./g.${ts}.${bh}`);
      const ok = await fetch(`${ctx.url}/g`, {
        headers: { Cookie: cookieHeader(jar), "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}` },
      });
      expect(ok.status).toBe(200);
    } finally {
      await ctx.close();
    }
  });
});

describe("Fastify createDbsc", () => {
  it("install() registers the cookie plugin + protocol routes", async () => {
    const storage = new MemoryStorage();
    const app = Fastify();
    const kit = createDbsc({ storage, secure: false });
    await kit.install(app);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/dbsc-bound/state`);
      expect(res.status).toBe(200);
      expect((await res.json()).phase).toBe("unbound");
    } finally {
      await app.close();
    }
  });
});

describe("bound: false (native-only)", () => {
  async function start(register: (app: FastifyInstance, storage: MemoryStorage) => void) {
    const storage = new MemoryStorage();
    const app = Fastify();
    await app.register(fastifyCookie);
    await app.register(dbsc, { storage, secure: false, bound: false });
    register(app, storage);
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    return { storage, url: `http://127.0.0.1:${port}`, close: () => app.close() };
  }

  it("state answers unbound; the other bound routes are not mounted (404)", async () => {
    const ctx = await start(() => {});
    try {
      const state = await fetch(`${ctx.url}/dbsc-bound/state`);
      expect((await state.json()).phase).toBe("unbound");
      expect((await fetch(`${ctx.url}/dbsc-bound/challenge`)).status).toBe(404);
      expect((await fetch(`${ctx.url}/dbsc-bound/registration`, { method: "POST" })).status).toBe(404);
      expect((await fetch(`${ctx.url}/dbsc-bound/refresh`, { method: "POST" })).status).toBe(404);
    } finally {
      await ctx.close();
    }
  });

  it("requireProof() demands a native proof (403 + challenge) and still 403s tier:none", async () => {
    const sessionId = "sess-fastify-native";
    const ctx = await start((app) => {
      app.get("/guarded", { preHandler: requireProof() }, async () => ({ ok: true }));
    });
    try {
      const now = Date.now();
      await ctx.storage.setSession({ id: sessionId, userId: "u1", tier: "dbsc", createdAt: now, expiresAt: now + 60_000, lastRefreshAt: now });
      await ctx.storage.setBoundKey({ sessionId, kind: "native", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, createdAt: now, algorithm: "ES256" });
      // v2.14: native-only no longer relaxes — a proofless dbsc request gets the
      // freshProof handshake (403 + Secure-Session-Challenge).
      const challenged = await fetch(`${ctx.url}/guarded`, { headers: { cookie: `dbsc-session=${sessionId}` } });
      expect(challenged.status).toBe(403);
      expect(challenged.headers.get("secure-session-challenge")).toBeTruthy();
      const denied = await fetch(`${ctx.url}/guarded`);
      expect(denied.status).toBe(403);
    } finally {
      await ctx.close();
    }
  });
});
