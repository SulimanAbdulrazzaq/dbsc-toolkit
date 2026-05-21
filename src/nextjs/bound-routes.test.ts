import { describe, it, expect } from "vitest";
import { NextRequest, NextResponse } from "next/server.js";
import { createHash } from "node:crypto";
import { createDbscMiddleware, bindSession, getDbscSession, requireBoundProof } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

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

function reqWith(opts: {
  url: string;
  method?: string;
  cookies?: Record<string, string>;
  headers?: Record<string, string>;
  body?: BodyInit;
}): NextRequest {
  const headers = new Headers(opts.headers ?? {});
  if (opts.cookies) {
    const cookieStr = Object.entries(opts.cookies).map(([k, v]) => `${k}=${v}`).join("; ");
    headers.set("Cookie", cookieStr);
  }
  const init: RequestInit = { method: opts.method ?? "GET", headers };
  if (opts.body !== undefined) init.body = opts.body;
  return new NextRequest(opts.url, init);
}

function extractSetCookieFromResponse(res: NextResponse): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of res.cookies.getAll()) {
    out[c.name] = c.value;
  }
  return out;
}

describe("Next.js /dbsc-bound/state middleware", () => {
  it("returns phase: unbound with X-Server-Time", async () => {
    const storage = new MemoryStorage();
    const mw = createDbscMiddleware({ storage, secure: false });
    const res = await mw(reqWith({ url: "http://x/dbsc-bound/state" }));
    expect(res.status).toBe(200);
    expect(res.headers.get("X-Server-Time")).toBeTruthy();
    const body = await res.json();
    expect(body.phase).toBe("unbound");
  });

  it("echoes nativeSkipped from Secure-Session-Skipped header", async () => {
    const storage = new MemoryStorage();
    const mw = createDbscMiddleware({ storage, secure: false });
    const res = await mw(reqWith({
      url: "http://x/dbsc-bound/state",
      headers: { "Secure-Session-Skipped": `quota_exceeded;session_identifier="abc"` },
    }));
    const body = await res.json();
    expect(body.nativeSkipped).toEqual(["quota_exceeded"]);
  });
});

async function bootstrapBoundSession(
  storage: MemoryStorage,
  sessionId: string,
): Promise<{ jar: Record<string, string>; privateKey: CryptoKey; sessionId: string }> {
  // Skip the bindSession middleware path — populate storage + cookies directly
  // (the bindSession helper is tied to a NextResponse instance we'd need to
  // shuttle through; the equivalent server state is what matters here).
  await storage.setSession({
    id: sessionId,
    userId: "u1",
    tier: "none",
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    lastRefreshAt: 0,
  });

  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicKey = await crypto.subtle.exportKey("jwk", pair.publicKey);

  // Issue a challenge by calling the bound state middleware (which sets phase
  // needs-registration and persists a fresh challenge for this session).
  const mw = createDbscMiddleware({ storage, secure: false });
  const stateRes = await mw(reqWith({
    url: "http://x/dbsc-bound/state",
    cookies: { "dbsc-reg": sessionId },
  }));
  const state = await stateRes.json();
  expect(state.phase).toBe("needs-registration");

  const signature = await signMessage(pair.privateKey, state.challenge);
  const regRes = await mw(reqWith({
    url: "http://x/dbsc-bound/registration",
    method: "POST",
    cookies: { "dbsc-reg": sessionId },
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ publicKey, signature, challenge: state.challenge }),
  }));
  expect(regRes.status).toBe(200);

  const jar: Record<string, string> = { "dbsc-reg": sessionId };
  Object.assign(jar, extractSetCookieFromResponse(regRes));
  return { jar, privateKey: pair.privateKey, sessionId };
}

describe("Next.js bound registration + refresh", () => {
  it("registration flips tier to bound", async () => {
    const storage = new MemoryStorage();
    await bootstrapBoundSession(storage, "next-reg-1");
    const sess = await storage.getSession("next-reg-1");
    expect(sess?.tier).toBe("bound");
  });

  it("refresh updates lastRefreshAt", async () => {
    const storage = new MemoryStorage();
    const { jar, privateKey, sessionId } = await bootstrapBoundSession(storage, "next-ref-1");
    const before = (await storage.getSession(sessionId))!.lastRefreshAt;
    await new Promise((r) => setTimeout(r, 10));

    const mw = createDbscMiddleware({ storage, secure: false });
    const challengeRes = await mw(reqWith({
      url: "http://x/dbsc-bound/challenge",
      cookies: jar,
    }));
    const { challenge } = await challengeRes.json();
    const ts = Date.now();
    const sig = await signMessage(privateKey, `${challenge}.${ts}`);

    const refRes = await mw(reqWith({
      url: "http://x/dbsc-bound/refresh",
      method: "POST",
      cookies: jar,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge, signature: sig, timestamp: ts }),
    }));
    expect(refRes.status).toBe(200);
    const after = (await storage.getSession(sessionId))!.lastRefreshAt;
    expect(after).toBeGreaterThan(before);
  });
});

describe("Next.js requireBoundProof", () => {
  it("rejects tier=none with 403", async () => {
    const storage = new MemoryStorage();
    const req = reqWith({ url: "http://x/strict" });
    const session = await getDbscSession(req, storage, { secure: false });
    const gate = await requireBoundProof(req, session, { storage });
    expect(gate.ok).toBe(false);
    if (!gate.ok) {
      expect(gate.response.status).toBe(403);
    }
  });

  it("passes tier=bound with valid proof", async () => {
    const storage = new MemoryStorage();
    const { jar, privateKey, sessionId } = await bootstrapBoundSession(storage, "next-pr-1");

    const ts = Date.now();
    const sig = await signMessage(privateKey, `${sessionId}.GET./strict.${ts}`);
    const req = reqWith({
      url: "http://x/strict",
      cookies: jar,
      headers: { "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig}` },
    });
    const session = await getDbscSession(req, storage, { secure: false });
    const gate = await requireBoundProof(req, session, { storage });
    expect(gate.ok).toBe(true);
  });

  it("signBody: rejects substituted body", async () => {
    const storage = new MemoryStorage();
    const { jar, privateKey, sessionId } = await bootstrapBoundSession(storage, "next-pr-2");

    const signedBody = '{"amount":1}';
    const sentBody = '{"amount":1000}';
    const ts = Date.now();
    const signedBytes = new TextEncoder().encode(signedBody);
    const bh = b64url(new Uint8Array(createHash("sha256").update(signedBytes).digest()));
    const message = `${sessionId}.POST./pay.${ts}.${bh}`;
    const sig = await signMessage(privateKey, message);

    const req = reqWith({
      url: "http://x/pay",
      method: "POST",
      cookies: jar,
      headers: {
        "X-Dbsc-Bound-Proof": `ts=${ts};sig=${sig};bh=${bh}`,
        "Content-Type": "application/octet-stream",
      },
      body: sentBody,
    });
    const session = await getDbscSession(req, storage, { secure: false });
    const gate = await requireBoundProof(req, session, { storage, signBody: true });
    expect(gate.ok).toBe(false);
    if (!gate.ok) {
      expect(gate.response.status).toBe(403);
    }
  });
});
