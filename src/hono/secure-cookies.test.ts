import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { SignJWT, importJWK, type JWK } from "jose";
import { dbsc } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import { issueChallenge } from "../core/index.js";

describe("hono native registration with secure cookies", () => {
  it("returns the session config instead of throwing while clearing the __Host- challenge cookie", async () => {
    const storage = new MemoryStorage();
    const now = Date.now();
    await storage.setSession({ id: "s1", userId: "u", tier: "none", createdAt: now, expiresAt: now + 3_600_000, lastRefreshAt: 0 });
    const challenge = await issueChallenge("s1", storage);
    const app = new Hono();
    app.use("*", dbsc({ storage }));

    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const pub = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as JWK;
    const priv = await importJWK((await crypto.subtle.exportKey("jwk", kp.privateKey)) as JWK, "ES256");
    const jws = await new SignJWT({ jti: challenge.jti })
      .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: pub })
      .sign(priv);

    const res = await app.request("https://app.test/dbsc/registration", {
      method: "POST",
      headers: {
        cookie: `__Host-dbsc-reg=s1; __Host-dbsc-challenge=${challenge.jti}`,
        "secure-session-response": jws,
      },
    });
    expect(res.status).toBe(200);
    expect((await res.json()).session_identifier).toBe("s1");
    expect(res.headers.getSetCookie().join("\n")).toMatch(/__Host-dbsc-challenge=;.*Secure/);
  });

  it("answers an unknown session's refresh with 401 and no challenge", async () => {
    const storage = new MemoryStorage();
    const app = new Hono();
    app.use("*", dbsc({ storage }));
    const res = await app.request("https://app.test/dbsc/refresh", {
      method: "POST",
      headers: { "sec-secure-session-id": "nobody" },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("secure-session-challenge")).toBeNull();
  });
});
