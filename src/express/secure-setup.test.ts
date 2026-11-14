import { describe, expect, it } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createDbsc } from "./index.js";
import { MemoryStorage } from "../storage/memory/index.js";

const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");

async function boundSession(storage: MemoryStorage, sessionId: string) {
  const now = Date.now();
  await storage.setSession({ id: sessionId, userId: "u", tier: "bound", createdAt: now, expiresAt: now + 3_600_000, lastRefreshAt: now });
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  await storage.setBoundKey({ sessionId, kind: "bound", jwk, createdAt: now, algorithm: "ES256" });
  return kp;
}

async function proof(kp: CryptoKeyPair, sessionId: string, method: string, path: string, body: Uint8Array) {
  const ts = Date.now();
  const bh = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    kp.privateKey,
    new TextEncoder().encode(`${sessionId}.${method}.${path}.${ts}.${bh}`),
  );
  return `ts=${ts};sig=${b64u(new Uint8Array(sig))};bh=${bh}`;
}

async function serve(app: express.Express) {
  const server = await new Promise<Server>((r) => {
    const s = app.listen(0, () => r(s));
  });
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => server.close() };
}

describe("express kit secure setup", () => {
  it("verifies a JSON body without express.raw and leaves req.body parsed", async () => {
    const storage = new MemoryStorage();
    const sessionId = "s-json";
    const kp = await boundSession(storage, sessionId);
    const kit = createDbsc({ storage, secure: false, expectSessionId: () => sessionId });
    const app = express();
    kit.install(app);
    app.use(express.json());
    app.post("/pay", kit.requireProof(), (req, res) => res.json({ got: req.body }));
    const srv = await serve(app);
    const body = JSON.stringify({ amount: 5 });
    const res = await fetch(`${srv.base}/pay`, {
      method: "POST",
      headers: {
        cookie: `dbsc-session=${sessionId}`,
        "content-type": "application/json",
        "x-dbsc-bound-proof": await proof(kp, sessionId, "POST", "/pay", new TextEncoder().encode(body)),
      },
      body,
    });
    srv.close();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ got: { amount: 5 } });
  });

  it("still hands the route its own raw parser output", async () => {
    const storage = new MemoryStorage();
    const sessionId = "s-raw";
    const kp = await boundSession(storage, sessionId);
    const kit = createDbsc({ storage, secure: false, expectSessionId: () => sessionId });
    const app = express();
    kit.install(app);
    app.post("/upload", express.raw({ type: "*/*" }), kit.requireProof(), (req, res) =>
      res.json({ isBuffer: Buffer.isBuffer(req.body), length: (req.body as Buffer).length }),
    );
    const srv = await serve(app);
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const res = await fetch(`${srv.base}/upload`, {
      method: "POST",
      headers: {
        cookie: `dbsc-session=${sessionId}`,
        "content-type": "application/octet-stream",
        "x-dbsc-bound-proof": await proof(kp, sessionId, "POST", "/upload", bytes),
      },
      body: bytes,
    });
    srv.close();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ isBuffer: true, length: 5 });
  });

  it("rejects a tampered body even though the app parsed it", async () => {
    const storage = new MemoryStorage();
    const sessionId = "s-tamper";
    const kp = await boundSession(storage, sessionId);
    const kit = createDbsc({ storage, secure: false, expectSessionId: () => sessionId });
    const app = express();
    kit.install(app);
    app.use(express.json());
    app.post("/pay", kit.requireProof(), (_req, res) => res.json({ ok: true }));
    const srv = await serve(app);
    const signed = new TextEncoder().encode(JSON.stringify({ amount: 5 }));
    const res = await fetch(`${srv.base}/pay`, {
      method: "POST",
      headers: {
        cookie: `dbsc-session=${sessionId}`,
        "content-type": "application/json",
        "x-dbsc-bound-proof": await proof(kp, sessionId, "POST", "/pay", signed),
      },
      body: JSON.stringify({ amount: 5000 }),
    });
    srv.close();
    expect(res.status).toBe(403);
  });

  it("applies the kit's expectSessionId to every guard", async () => {
    const storage = new MemoryStorage();
    const sessionId = "s-attacker";
    const kp = await boundSession(storage, sessionId);
    const kit = createDbsc({ storage, secure: false, expectSessionId: () => "s-victim" });
    const app = express();
    kit.install(app);
    app.get("/me", kit.requireProof(), (_req, res) => res.json({ ok: true }));
    const srv = await serve(app);
    const res = await fetch(`${srv.base}/me`, {
      headers: {
        cookie: `dbsc-session=${sessionId}`,
        "x-dbsc-bound-proof": await proof(kp, sessionId, "GET", "/me", new Uint8Array(0)),
      },
    });
    srv.close();
    expect(res.status).toBe(403);
    expect((await res.json()).code).toBe("SESSION_MISMATCH");
  });

  it("serves the auto client named by clientScript()", async () => {
    const kit = createDbsc({ storage: new MemoryStorage(), secure: false });
    expect(kit.clientScript({ sign: ["/api/"] })).toContain('src="/dbsc-client/auto.js?sign=%2Fapi%2F"');
  });
});
