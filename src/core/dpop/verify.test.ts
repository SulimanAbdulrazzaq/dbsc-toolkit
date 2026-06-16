import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT, type JWK } from "jose";
import { verifyDpopProof } from "./verify.js";
import { jwkThumbprint, accessTokenHash } from "./thumbprint.js";
import { DbscVerificationError, ErrorCodes } from "../errors.js";
import { MemoryReplayCache } from "../../storage/memory/replay-cache.js";

let privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
let publicJwk: JsonWebKey;
let jkt: string;

const URL_ = "https://api.example.com/resource";

beforeAll(async () => {
  const { privateKey: priv, publicKey: pub } = await generateKeyPair("ES256");
  privateKey = priv;
  publicJwk = (await exportJWK(pub)) as JsonWebKey;
  jkt = await jwkThumbprint(publicJwk);
});

interface ProofOpts {
  typ?: string;
  alg?: string;
  jwk?: JsonWebKey;
  jti?: string;
  htm?: string;
  htu?: string;
  iat?: number;
  ath?: string;
}

async function mintProof(o: ProofOpts = {}): Promise<string> {
  const claims: Record<string, unknown> = {
    jti: o.jti ?? `jti-${Math.random().toString(36).slice(2)}`,
    htm: o.htm ?? "GET",
    htu: o.htu ?? URL_,
    iat: o.iat ?? Math.floor(Date.now() / 1000),
  };
  if (o.ath !== undefined) claims["ath"] = o.ath;
  return new SignJWT(claims)
    .setProtectedHeader({
      typ: o.typ ?? "dpop+jwt",
      alg: o.alg ?? "ES256",
      jwk: (o.jwk ?? publicJwk) as JWK,
    })
    .sign(privateKey);
}

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

/** Re-encode a signed proof's protected header with overrides, keeping the
 * original payload+signature. Used to forge header-only invalid states the
 * signer would otherwise refuse to produce (e.g. a mismatched alg). */
function forgeHeader(proof: string, overrides: Record<string, unknown>): string {
  const [h, p, s] = proof.split(".");
  const header = JSON.parse(Buffer.from(h!, "base64url").toString());
  return `${b64url({ ...header, ...overrides })}.${p}.${s}`;
}

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await expect(p).rejects.toMatchObject({ code });
  await expect(p).rejects.toBeInstanceOf(DbscVerificationError);
}

describe("verifyDpopProof — happy path", () => {
  it("verifies a fresh proof of possession (no token)", async () => {
    const proof = await mintProof();
    const r = await verifyDpopProof({ proof, method: "GET", url: URL_ });
    expect(r.jkt).toBe(jkt);
    expect(r.jti).toBeTruthy();
  });

  it("verifies a token-bound proof with matching jkt and ath", async () => {
    const token = "access-token-abc";
    const proof = await mintProof({ ath: await accessTokenHash(token) });
    const r = await verifyDpopProof({
      proof,
      method: "GET",
      url: URL_,
      accessToken: token,
      boundJkt: jkt,
    });
    expect(r.jkt).toBe(jkt);
  });
});

describe("verifyDpopProof — failure modes", () => {
  it("missing header", async () => {
    await expectCode(verifyDpopProof({ proof: undefined, method: "GET", url: URL_ }), ErrorCodes.DPOP_PROOF_MISSING);
  });

  it("malformed JWS", async () => {
    await expectCode(verifyDpopProof({ proof: "not.a.jwt", method: "GET", url: URL_ }), ErrorCodes.DPOP_PROOF_MALFORMED);
  });

  it("wrong typ", async () => {
    const proof = await mintProof({ typ: "jwt" });
    await expectCode(verifyDpopProof({ proof, method: "GET", url: URL_ }), ErrorCodes.DPOP_INVALID_TYP);
  });

  it("disallowed alg", async () => {
    // Forge the header alg to a value outside the supported set; the verifier
    // rejects it before importing the key, so the broken signature is moot.
    const proof = forgeHeader(await mintProof(), { alg: "HS256" });
    await expectCode(verifyDpopProof({ proof, method: "GET", url: URL_ }), ErrorCodes.DPOP_INVALID_ALG);
  });

  it("private jwk in header", async () => {
    // Generate an extractable key purely to obtain a private JWK to embed.
    const { privateKey: extPriv } = await generateKeyPair("ES256", { extractable: true });
    const privJwk = (await exportJWK(extPriv)) as JsonWebKey;
    const proof = forgeHeader(await mintProof(), { jwk: privJwk });
    await expectCode(verifyDpopProof({ proof, method: "GET", url: URL_ }), ErrorCodes.DPOP_JWK_PRIVATE);
  });

  it("wrong htm", async () => {
    const proof = await mintProof({ htm: "POST" });
    await expectCode(verifyDpopProof({ proof, method: "GET", url: URL_ }), ErrorCodes.DPOP_HTM_MISMATCH);
  });

  it("wrong htu", async () => {
    const proof = await mintProof({ htu: "https://api.example.com/other" });
    await expectCode(verifyDpopProof({ proof, method: "GET", url: URL_ }), ErrorCodes.DPOP_HTU_MISMATCH);
  });

  it("stale iat", async () => {
    const proof = await mintProof({ iat: Math.floor(Date.now() / 1000) - 3600 });
    await expectCode(verifyDpopProof({ proof, method: "GET", url: URL_ }), ErrorCodes.DPOP_IAT_OUT_OF_WINDOW);
  });

  it("far-future iat", async () => {
    const proof = await mintProof({ iat: Math.floor(Date.now() / 1000) + 3600 });
    await expectCode(verifyDpopProof({ proof, method: "GET", url: URL_ }), ErrorCodes.DPOP_IAT_OUT_OF_WINDOW);
  });

  it("tampered signature", async () => {
    const proof = await mintProof();
    const parts = proof.split(".");
    parts[2] = parts[2]!.split("").reverse().join("");
    await expectCode(verifyDpopProof({ proof: parts.join("."), method: "GET", url: URL_ }), ErrorCodes.DPOP_SIGNATURE_INVALID);
  });

  it("token presented without boundJkt -> binding required (loud)", async () => {
    const token = "tok";
    const proof = await mintProof({ ath: await accessTokenHash(token) });
    await expectCode(
      verifyDpopProof({ proof, method: "GET", url: URL_, accessToken: token }),
      ErrorCodes.DPOP_TOKEN_BINDING_REQUIRED,
    );
  });

  it("mismatched jkt", async () => {
    const token = "tok";
    const proof = await mintProof({ ath: await accessTokenHash(token) });
    await expectCode(
      verifyDpopProof({ proof, method: "GET", url: URL_, accessToken: token, boundJkt: "not-the-jkt" }),
      ErrorCodes.DPOP_JKT_MISMATCH,
    );
  });

  it("wrong ath", async () => {
    const proof = await mintProof({ ath: "wrong-hash" });
    await expectCode(
      verifyDpopProof({ proof, method: "GET", url: URL_, accessToken: "tok", boundJkt: jkt }),
      ErrorCodes.DPOP_ATH_MISMATCH,
    );
  });

  it("replayed jti", async () => {
    const cache = new MemoryReplayCache();
    const proof = await mintProof();
    await verifyDpopProof({ proof, method: "GET", url: URL_, replayCache: cache });
    await expectCode(
      verifyDpopProof({ proof, method: "GET", url: URL_, replayCache: cache }),
      ErrorCodes.DPOP_JTI_REPLAY,
    );
  });

  it("requireTokenBinding:false allows an unbound presented token", async () => {
    const token = "tok";
    const proof = await mintProof({ ath: await accessTokenHash(token) });
    const r = await verifyDpopProof({
      proof,
      method: "GET",
      url: URL_,
      accessToken: token,
      requireTokenBinding: false,
    });
    expect(r.jkt).toBe(jkt);
  });
});
