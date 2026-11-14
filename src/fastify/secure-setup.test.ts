import { describe, expect, it } from "vitest";
import Fastify from "fastify";
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

async function proof(kp: CryptoKeyPair, sessionId: string, path: string, body: Uint8Array) {
  const ts = Date.now();
  const bh = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    kp.privateKey,
    new TextEncoder().encode(`${sessionId}.POST.${path}.${ts}.${bh}`),
  );
  return `ts=${ts};sig=${b64u(new Uint8Array(sig))};bh=${bh}`;
}

describe("fastify kit secure setup", () => {
  it("verifies a JSON body with Fastify's own parser in place", async () => {
    const storage = new MemoryStorage();
    const sessionId = "f-json";
    const kp = await boundSession(storage, sessionId);
    const kit = createDbsc({ storage, secure: false, expectSessionId: () => sessionId });
    const app = Fastify();
    await kit.install(app);
    app.post("/pay", { preHandler: kit.requireProof() }, async (req) => ({ got: req.body }));
    const body = JSON.stringify({ amount: 7 });
    const res = await app.inject({
      method: "POST",
      url: "/pay",
      headers: {
        cookie: `dbsc-session=${sessionId}`,
        "content-type": "application/json",
        "x-dbsc-bound-proof": await proof(kp, sessionId, "/pay", new TextEncoder().encode(body)),
      },
      payload: body,
    });
    await app.close();
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ got: { amount: 7 } });
  });

  it("rejects a body that differs from the signed one", async () => {
    const storage = new MemoryStorage();
    const sessionId = "f-tamper";
    const kp = await boundSession(storage, sessionId);
    const kit = createDbsc({ storage, secure: false, expectSessionId: () => sessionId });
    const app = Fastify();
    await kit.install(app);
    app.post("/pay", { preHandler: kit.requireProof() }, async () => ({ ok: true }));
    const res = await app.inject({
      method: "POST",
      url: "/pay",
      headers: {
        cookie: `dbsc-session=${sessionId}`,
        "content-type": "application/json",
        "x-dbsc-bound-proof": await proof(kp, sessionId, "/pay", new TextEncoder().encode('{"amount":7}')),
      },
      payload: '{"amount":7000}',
    });
    await app.close();
    expect(res.statusCode).toBe(403);
  });
});
