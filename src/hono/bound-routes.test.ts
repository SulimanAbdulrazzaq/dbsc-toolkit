import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { createHash } from "node:crypto";
import { dbsc, bindSession, requireBoundProof, requireProof, createDbsc } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

function buildApp(register?: (app: Hono, storage: MemoryStorage) => void) {
  const storage = new MemoryStorage();
  const app = new Hono();
  app.use("*", dbsc({ storage, secure: false }));
  if (register) register(app, storage);
  return { storage, app };
}

function parseSetCookie(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  const all = res.headers.getSetCookie?.() ?? [];
  for (const c of all) {
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

describe("Hono GET /dbsc-bound/state", () => {
  it("returns phase: unbound and emits X-Server-Time", async () => {
    const { app } = buildApp();
    const res = await app.fetch(new Request("http://x/dbsc-bound/state"));
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Server-Time")).toBeTruthy();
    const body = await res.json() as any;
    expect(body.phase).toBe("unbound");
  });

  it("returns nativeSkipped when Secure-Session-Skipped header is present", async () => {
    const { app } = buildApp();
    const res = await app.fetch(new Request("http://x/dbsc-bound/state", {
      headers: { "Secure-Session-Skipped": `quota_exceeded;session_identifier="abc"` },
    }));
    const body = await res.json() as any;
    expect(body.nativeSkipped).toEqual(["quota_exceeded"]);
  });
});

async function registerBoundSession(app: Hono, sessionId: string) {
  const loginRes = await app.fetch(new Request("http://x/login", { method: "POST" }));
  const jar = parseSetCookie(loginRes);

  const stateRes = await app.fetch(new Request("http://x/dbsc-bound/state", {
    headers: { Cookie: cookieHeader(jar) },
  }));
  const state = await stateRes.json() as any;
  expect(state.phase).toBe("needs-registration");

  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const signature = await signMessage(pair.privateKey, state.challenge);

  const regRes = await app.fetch(new Request("http://x/dbsc-bound/registration", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: cookieHeader(jar) },
    body: JSON.stringify({ publicKey, signature, challenge: state.challenge }),
  }));
  expect(regRes.status).toBe(200);
  Object.assign(jar, parseSetCookie(regRes));
  return { jar, privateKey: pair.privateKey, sessionId };
}

describe("Hono bound registration + refresh", () => {
  it("registration flips tier to bound", async () => {
    const { storage, app } = buildApp((a, s) => {
      a.post("/login", async (c) => {
        await bindSession(c, "hono-reg-1", s, { userId: "u1", secure: false });
        return c.json({ ok: true });
      });
    });
    await registerBoundSession(app, "hono-reg-1");
    const sess = await storage.getSession("hono-reg-1");
    expect(sess?.tier).toBe("bound");
  });

  it("refresh updates lastRefreshAt", async () => {
    const { storage, app } = buildApp((a, s) => {
      a.post("/login", async (c) => {
        await bindSession(c, "hono-ref-1", s, { userId: "u1", secure: false });
        return c.json({ ok: true });
      });
    });
    const { jar, privateKey } = await registerBoundSession(app, "hono-ref-1");
    const before = (await storage.getSession("hono-ref-1"))!.lastRefreshAt;
    await new Promise((r) => setTimeout(r, 10));

    const challengeRes = await app.fetch(new Request("http://x/dbsc-bound/challenge", {
      headers: { Cookie: cookieHeader(jar) },
    }));
    const { challenge } = await challengeRes.json() as any;
    const ts = Date.now();
    const sig = await signMessage(privateKey, `${challenge}.${ts}`);

    const refRes = await app.fetch(new Request("http://x/dbsc-bound/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: cookieHeader(jar) },
      body: JSON.stringify({ challenge, signature: sig, timestamp: ts }),
    }));
    expect(refRes.status).toBe(200);
    const after = (await storage.getSession("hono-ref-1"))!.lastRefreshAt;
    expect(after).toBeGreaterThan(before);
  });
});

describe("Hono requireBoundProof", () => {
  it("rejects tier=none with 403", async () => {
    const { app } = buildApp((a, s) => {
      a.get("/strict", requireBoundProof({ storage: s }), (c) => c.json({ ok: true }));
    });
    const res = await app.fetch(new Request("http://x/strict"));
    expect(res.status).toBe(403);
  });

  it("passes tier=bound with valid proof", async () => {
    const { app } = buildApp((a, s) => {
      a.post("/login", async (c) => {
        await bindSession(c, "hono-pr-1", s, { userId: "u1", secure: false });
        return c.json({ ok: true });
      });
      a.get("/strict", requireBoundProof({ storage: s }), (c) => c.json({ ok: true }));
    });
    const { jar, privateKey } = await registerBoundSession(app, "hono-pr-1");
    const ts = Date.now();
    const sig = await signMessage(privateKey, `hono-pr-1.GET./strict.${ts}`);
    const res = await app.fetch(new Request("http://x/strict", {
      headers: {
        Cookie: cookieHeader(jar),
        "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig}`,
      },
    }));
    expect(res.status).toBe(200);
  });

  it("rejects MISSING_PROOF when header is absent", async () => {
    const { app } = buildApp((a, s) => {
      a.post("/login", async (c) => {
        await bindSession(c, "hono-pr-2", s, { userId: "u1", secure: false });
        return c.json({ ok: true });
      });
      a.get("/strict", requireBoundProof({ storage: s }), (c) => c.json({ ok: true }));
    });
    const { jar } = await registerBoundSession(app, "hono-pr-2");
    const res = await app.fetch(new Request("http://x/strict", {
      headers: { Cookie: cookieHeader(jar) },
    }));
    expect(res.status).toBe(403);
    const body = await res.json() as any;
    expect(body.code).toBe("MISSING_PROOF");
  });

  it("signBody: rejects substituted body", async () => {
    const { app } = buildApp((a, s) => {
      a.post("/login", async (c) => {
        await bindSession(c, "hono-pr-3", s, { userId: "u1", secure: false });
        return c.json({ ok: true });
      });
      a.post("/pay", requireBoundProof({ storage: s, signBody: true }), (c) => c.json({ ok: true }));
    });
    const { jar, privateKey } = await registerBoundSession(app, "hono-pr-3");
    const signedBody = '{"amount":1}';
    const sentBody = '{"amount":1000}';
    const ts = Date.now();
    const signedBytes = new TextEncoder().encode(signedBody);
    const bh = b64url(new Uint8Array(createHash("sha256").update(signedBytes).digest()));
    const message = `hono-pr-3.POST./pay.${ts}.${bh}`;
    const sig = await signMessage(privateKey, message);

    const res = await app.fetch(new Request("http://x/pay", {
      method: "POST",
      headers: {
        Cookie: cookieHeader(jar),
        "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}`,
        "Content-Type": "application/octet-stream",
      },
      body: sentBody,
    }));
    expect(res.status).toBe(403);
    const body = await res.json() as any;
    expect(body.code).toBe("SIGNATURE_INVALID");
  });
});

describe("Hono requireProof", () => {
  it("rejects tier=none", async () => {
    const { app } = buildApp((a) => {
      a.get("/g", requireProof(), (c) => c.json({ ok: true }));
    });
    const res = await app.fetch(new Request("http://x/g"));
    expect(res.status).toBe(403);
    expect(((await res.json()) as any).currentTier).toBe("none");
  });

  it("rejects a bound session that sends no proof", async () => {
    const { app } = buildApp((a, s) => {
      a.post("/login", async (c) => {
        await bindSession(c, "hono-rp-1", s, { userId: "u1", secure: false });
        return c.json({ ok: true });
      });
      a.get("/g", requireProof(), (c) => c.json({ ok: true }));
    });
    const { jar } = await registerBoundSession(app, "hono-rp-1");
    const res = await app.fetch(new Request("http://x/g", { headers: { Cookie: cookieHeader(jar) } }));
    expect(res.status).toBe(403);
  });

  it("passes a bound session with a valid proof — storage from the middleware", async () => {
    const { app } = buildApp((a, s) => {
      a.post("/login", async (c) => {
        await bindSession(c, "hono-rp-2", s, { userId: "u1", secure: false });
        return c.json({ ok: true });
      });
      a.get("/g", requireProof(), (c) => c.json({ ok: true }));
    });
    const { jar, privateKey } = await registerBoundSession(app, "hono-rp-2");

    // requireProof signs the body — a GET has none, so the hash is of empty bytes.
    const ts = Date.now();
    const bh = b64url(new Uint8Array(createHash("sha256").update(new Uint8Array(0)).digest()));
    const sig = await signMessage(privateKey, `hono-rp-2.GET./g.${ts}.${bh}`);
    const ok = await app.fetch(
      new Request("http://x/g", {
        headers: { Cookie: cookieHeader(jar), "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}` },
      }),
    );
    expect(ok.status).toBe(200);
  });
});

describe("Hono createDbsc", () => {
  it("install() mounts the protocol routes", async () => {
    const storage = new MemoryStorage();
    const app = new Hono();
    createDbsc({ storage, secure: false }).install(app);
    const res = await app.fetch(new Request("http://x/dbsc-bound/state"));
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).phase).toBe("unbound");
  });
});

describe("bound: false (native-only)", () => {
  function build(register?: (app: Hono, storage: MemoryStorage) => void) {
    const storage = new MemoryStorage();
    const app = new Hono();
    app.use("*", dbsc({ storage, secure: false, bound: false }));
    if (register) register(app, storage);
    return { storage, app };
  }

  it("state answers unbound; other bound routes are not mounted (404)", async () => {
    const { app } = build();
    const state = await app.fetch(new Request("http://x/dbsc-bound/state"));
    expect(((await state.json()) as any).phase).toBe("unbound");
    expect((await app.fetch(new Request("http://x/dbsc-bound/challenge"))).status).toBe(404);
    expect((await app.fetch(new Request("http://x/dbsc-bound/registration", { method: "POST" }))).status).toBe(404);
    expect((await app.fetch(new Request("http://x/dbsc-bound/refresh", { method: "POST" }))).status).toBe(404);
  });

  it("requireProof() auto-relaxes a native dbsc session and still 403s tier:none", async () => {
    const sessionId = "sess-hono-native";
    const { storage, app } = build((a) => {
      a.get("/guarded", requireProof(), (c) => c.json({ ok: true }));
    });
    const now = Date.now();
    await storage.setSession({ id: sessionId, userId: "u1", tier: "dbsc", createdAt: now, expiresAt: now + 60000, lastRefreshAt: now });
    await storage.setBoundKey({ sessionId, kind: "native", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, createdAt: now, algorithm: "ES256" });
    const ok = await app.fetch(new Request("http://x/guarded", { headers: { cookie: `dbsc-session=${sessionId}` } }));
    expect(ok.status).toBe(200);
    const denied = await app.fetch(new Request("http://x/guarded"));
    expect(denied.status).toBe(403);
  });

  // Regression: requireProof() must resolve the relax decision per request, not
  // memoize the first request's boundEnabled. One guard, two dbsc() middlewares
  // dispatched by a header — a bound-mode request must 403 a dbsc session, a
  // native-mode request must pass it, and they must not leak across calls.
  it("resolves relax per request when two middlewares are dispatched by mode", async () => {
    const sessionId = "sess-hono-twomode";
    const storage = new MemoryStorage();
    const now = Date.now();
    await storage.setSession({ id: sessionId, userId: "u1", tier: "dbsc", createdAt: now, expiresAt: now + 60000, lastRefreshAt: now });
    await storage.setBoundKey({ sessionId, kind: "native", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, createdAt: now, algorithm: "ES256" });

    const boundMw = dbsc({ storage, secure: false, bound: true });
    const nativeMw = dbsc({ storage, secure: false, bound: false });
    const app = new Hono();
    app.use("*", async (c, next) => {
      const mw = c.req.header("x-mode") === "native" ? nativeMw : boundMw;
      return mw(c, next);
    });
    app.get("/guarded", requireProof(), (c) => c.json({ ok: true }));

    const cookie = `dbsc-session=${sessionId}`;
    const a = await app.fetch(new Request("http://x/guarded", { headers: { cookie } }));
    expect(a.status).toBe(403); // bound mode: proof required
    const b = await app.fetch(new Request("http://x/guarded", { headers: { cookie, "x-mode": "native" } }));
    expect(b.status).toBe(200); // native mode: relaxed
    const d = await app.fetch(new Request("http://x/guarded", { headers: { cookie } }));
    expect(d.status).toBe(403); // bound again: must not have leaked from native
  });
});
