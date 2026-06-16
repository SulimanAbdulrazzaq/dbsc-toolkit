import { describe, it, expect, beforeAll } from "vitest";
import express from "express";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { dbsc, requireDpop } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import { jwkThumbprint, accessTokenHash } from "../core/dpop/index.js";
import { MemoryReplayCache } from "../storage/memory/replay-cache.js";

let privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
let publicJwk: JsonWebKey;
let jkt: string;

beforeAll(async () => {
  const kp = await generateKeyPair("ES256");
  privateKey = kp.privateKey;
  publicJwk = (await exportJWK(kp.publicKey)) as JsonWebKey;
  jkt = await jwkThumbprint(publicJwk);
});

async function mintProof(method: string, url: string, ath?: string): Promise<string> {
  const claims: Record<string, unknown> = {
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
  };
  if (ath) claims["ath"] = ath;
  return new SignJWT(claims)
    .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: publicJwk as JWK })
    .sign(privateKey);
}

async function start(register: (app: express.Application) => void) {
  const storage = new MemoryStorage();
  const app = express();
  app.use(dbsc({ storage, secure: false, replayCache: new MemoryReplayCache() }));
  register(app);
  const server = createServer(app);
  await new Promise<void>((r) => server.listen(0, r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

describe("express requireDpop", () => {
  it("200 on a valid proof of possession", async () => {
    const srv = await start((app) => {
      app.get("/api", requireDpop(), (_req, res) => res.json({ ok: true }));
    });
    const url = `${srv.url}/api`;
    const proof = await mintProof("GET", url);
    const r = await fetch(url, { headers: { DPoP: proof } });
    expect(r.status).toBe(200);
    await srv.close();
  });

  it("401 + WWW-Authenticate on a missing proof", async () => {
    const srv = await start((app) => {
      app.get("/api", requireDpop(), (_req, res) => res.json({ ok: true }));
    });
    const r = await fetch(`${srv.url}/api`);
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toContain("DPoP");
    await srv.close();
  });

  it("200 on a token-bound proof, 401 when jkt mismatches", async () => {
    const srv = await start((app) => {
      app.get(
        "/api",
        requireDpop({ getBoundJkt: () => jkt }),
        (_req, res) => res.json({ ok: true }),
      );
    });
    const url = `${srv.url}/api`;
    const token = "access-token";
    const proof = await mintProof("GET", url, await accessTokenHash(token));
    const ok = await fetch(url, {
      headers: { DPoP: proof, Authorization: `DPoP ${token}` },
    });
    expect(ok.status).toBe(200);

    const srv2 = await start((app) => {
      app.get(
        "/api",
        requireDpop({ getBoundJkt: () => "wrong-jkt" }),
        (_req, res) => res.json({ ok: true }),
      );
    });
    const url2 = `${srv2.url}/api`;
    const proof2 = await mintProof("GET", url2, await accessTokenHash(token));
    const bad = await fetch(url2, {
      headers: { DPoP: proof2, Authorization: `DPoP ${token}` },
    });
    expect(bad.status).toBe(401);
    await srv.close();
    await srv2.close();
  });

  it("401 on a replayed proof", async () => {
    const srv = await start((app) => {
      app.get("/api", requireDpop(), (_req, res) => res.json({ ok: true }));
    });
    const url = `${srv.url}/api`;
    const proof = await mintProof("GET", url);
    const first = await fetch(url, { headers: { DPoP: proof } });
    expect(first.status).toBe(200);
    const replay = await fetch(url, { headers: { DPoP: proof } });
    expect(replay.status).toBe(401);
    await srv.close();
  });
});
