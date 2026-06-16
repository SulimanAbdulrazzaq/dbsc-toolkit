import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { dbsc, requireDpop } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import { jwkThumbprint } from "../core/dpop/index.js";
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

async function mintProof(method: string, url: string): Promise<string> {
  return new SignJWT({
    jti: `jti-${Math.random().toString(36).slice(2)}`,
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
  })
    .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: publicJwk as JWK })
    .sign(privateKey);
}

async function start() {
  const storage = new MemoryStorage();
  const handler = dbsc({ storage, secure: false, replayCache: new MemoryReplayCache() });
  const guard = requireDpop();
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (await handler(req, res)) return;
    if (await guard(req, res)) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ ok: true }));
    }
  });
  await new Promise<void>((r) => server.listen(0, r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/api`,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

describe("node requireDpop", () => {
  it("200 on a valid proof, 401 on a missing one, 401 on replay", async () => {
    const srv = await start();
    expect(jkt).toBeTruthy();

    const proof = await mintProof("GET", srv.url);
    const ok = await fetch(srv.url, { headers: { DPoP: proof } });
    expect(ok.status).toBe(200);

    const missing = await fetch(srv.url);
    expect(missing.status).toBe(401);
    expect(missing.headers.get("www-authenticate")).toContain("DPoP");

    const replay = await fetch(srv.url, { headers: { DPoP: proof } });
    expect(replay.status).toBe(401);

    await srv.close();
  });
});
