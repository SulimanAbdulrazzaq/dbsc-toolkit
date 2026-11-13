import { describe, expect, it } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import { dbsc, requireProof } from "./index.js";
import { MemoryStorage } from "../storage/memory/index.js";

const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");

async function boundSession() {
  const storage = new MemoryStorage();
  const sessionId = `s-${Math.random().toString(36).slice(2)}`;
  const now = Date.now();
  await storage.setSession({ id: sessionId, userId: "u", tier: "bound", createdAt: now, expiresAt: now + 3_600_000, lastRefreshAt: now });
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  await storage.setBoundKey({ sessionId, kind: "bound", jwk, createdAt: now, algorithm: "ES256" });
  return { storage, sessionId, kp };
}

async function proof(kp: CryptoKeyPair, sessionId: string, path: string, body = new Uint8Array(0)) {
  const ts = Date.now();
  const bh = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    kp.privateKey,
    new TextEncoder().encode(`${sessionId}.GET.${path}.${ts}.${bh}`),
  );
  return `ts=${ts};sig=${b64u(new Uint8Array(sig))};bh=${bh}`;
}

async function serve(app: express.Express) {
  const server = await new Promise<import("node:http").Server>((r) => {
    const s = app.listen(0, () => r(s));
  });
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => server.close() };
}

describe("express guard fixes", () => {
  it("verifies the full pathname under a mounted router", async () => {
    const { storage, sessionId, kp } = await boundSession();
    const app = express();
    app.use(dbsc({ storage, secure: false }));
    const router = express.Router();
    router.get("/pay", requireProof(), (_req, res) => res.json({ ok: true }));
    app.use("/api", router);
    const srv = await serve(app);
    const res = await fetch(`${srv.base}/api/pay`, {
      headers: { cookie: `dbsc-session=${sessionId}`, "x-dbsc-bound-proof": await proof(kp, sessionId, "/api/pay") },
    });
    srv.close();
    expect(res.status).toBe(200);
  });

  it("routes a storage failure to the error handler instead of hanging", async () => {
    const { storage, sessionId, kp } = await boundSession();
    const app = express();
    app.use(dbsc({ storage, secure: false }));
    app.get("/x", requireProof(), (_req, res) => res.json({ ok: true }));
    app.use((_err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      res.status(500).json({ handled: true });
    });
    const header = await proof(kp, sessionId, "/x");
    storage.getBoundKey = async () => {
      throw new Error("storage down");
    };
    const srv = await serve(app);
    const res = await fetch(`${srv.base}/x`, {
      headers: { cookie: `dbsc-session=${sessionId}`, "x-dbsc-bound-proof": header },
      signal: AbortSignal.timeout(2000),
    });
    srv.close();
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ handled: true });
  });

  it("revoke() keeps cookies the app already set on the response", async () => {
    const { storage, sessionId } = await boundSession();
    const app = express();
    app.use(dbsc({ storage, secure: false }));
    app.post("/logout", async (_req, res) => {
      res.cookie("app-session", "", { maxAge: 0 });
      await res.locals.dbsc.revoke();
      res.json({ ok: true });
    });
    const srv = await serve(app);
    const res = await fetch(`${srv.base}/logout`, { method: "POST", headers: { cookie: `dbsc-session=${sessionId}` } });
    srv.close();
    const cookies = res.headers.getSetCookie().join("\n");
    expect(cookies).toContain("app-session=");
    expect(cookies).toContain("dbsc-session=");
  });
});
