import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, importJWK, type JWK } from "jose";
import { verifyDbscJws, parseRegistrationJws } from "./jws.js";
import { DbscVerificationError } from "../errors.js";

let privateKey: Awaited<ReturnType<typeof importJWK>>;
let publicJwk: JsonWebKey;

beforeAll(async () => {
  const { privateKey: priv, publicKey: pub } = await generateKeyPair("ES256");
  privateKey = priv;
  publicJwk = await exportJWK(pub) as JsonWebKey;
});

async function signDbscJwt(jti: string, typ = "dbsc+jwt"): Promise<string> {
  return new SignJWT({ jti })
    .setProtectedHeader({ alg: "ES256", typ })
    .sign(privateKey);
}

describe("verifyDbscJws", () => {
  it("accepts a valid JWS with matching jti", async () => {
    const token = await signDbscJwt("test-jti-123");
    const claims = await verifyDbscJws(token, publicJwk, "test-jti-123");
    expect(claims.jti).toBe("test-jti-123");
  });

  it("rejects wrong jti", async () => {
    const token = await signDbscJwt("actual-jti");
    await expect(verifyDbscJws(token, publicJwk, "expected-jti")).rejects.toThrow(
      DbscVerificationError,
    );
  });

  it("rejects wrong typ", async () => {
    const token = await signDbscJwt("jti", "JWT");
    await expect(verifyDbscJws(token, publicJwk, "jti")).rejects.toThrow(
      DbscVerificationError,
    );
  });

  it("rejects tampered signature", async () => {
    const token = await signDbscJwt("jti");
    const parts = token.split(".");
    parts[2] = parts[2]!.split("").reverse().join("");
    const tampered = parts.join(".");
    await expect(verifyDbscJws(tampered, publicJwk, "jti")).rejects.toThrow(
      DbscVerificationError,
    );
  });

  it("rejects malformed token", async () => {
    await expect(verifyDbscJws("not.a.jwt", publicJwk, "jti")).rejects.toThrow(
      DbscVerificationError,
    );
  });
});

describe("parseRegistrationJws", () => {
  it("parses valid registration JWS", async () => {
    const token = new SignJWT({ jti: "reg-jti" })
      .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt", jwk: publicJwk as JWK });
    const signed = await (await token).sign(privateKey);
    const result = await parseRegistrationJws(signed);
    expect(result.algorithm).toBe("ES256");
    expect(result.jwk).toBeDefined();
  });

  it("rejects registration JWS without jwk in header", async () => {
    const token = await new SignJWT({ jti: "jti" })
      .setProtectedHeader({ alg: "ES256", typ: "dbsc+jwt" })
      .sign(privateKey);
    await expect(parseRegistrationJws(token)).rejects.toThrow(DbscVerificationError);
  });
});
