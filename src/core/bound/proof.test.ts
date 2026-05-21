import { describe, expect, it } from "vitest";
import { verifyBoundProof, parseProofHeader, BOUND_PROOF_HEADER } from "./proof.js";
import { handleBoundRegistration } from "./registration.js";
import { issueChallenge } from "../protocol/challenge.js";
import { MemoryStorage } from "../testing/memory-storage-stub.js";
import { DbscVerificationError, ErrorCodes } from "../errors.js";

interface BoundUser {
  storage: MemoryStorage;
  sessionId: string;
  privateKey: CryptoKey;
}

async function bootstrapBoundSession(sessionId: string): Promise<BoundUser> {
  const storage = new MemoryStorage();
  await storage.setSession({
    id: sessionId,
    userId: "user-1",
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

  const challenge = await issueChallenge(sessionId, storage);
  const signature = await signMessage(pair.privateKey, challenge.jti);

  await handleBoundRegistration(
    { sessionId, publicKey, signature, expectedJti: challenge.jti },
    storage,
  );

  return { storage, sessionId, privateKey: pair.privateKey };
}

async function signMessage(privateKey: CryptoKey, message: string): Promise<string> {
  const data = new TextEncoder().encode(message);
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer,
  );
  let s = "";
  const bytes = new Uint8Array(sig);
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return Buffer.from(s, "binary").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function buildProof(
  privateKey: CryptoKey,
  sessionId: string,
  method: string,
  path: string,
  ts: number,
): Promise<string> {
  const message = `${sessionId}.${method.toUpperCase()}.${path}.${ts}`;
  const sig = await signMessage(privateKey, message);
  return `ts=${ts};sig=${sig}`;
}

describe("BOUND_PROOF_HEADER", () => {
  it("is the documented header name", () => {
    expect(BOUND_PROOF_HEADER).toBe("X-Dbsc-Bound-Proof");
  });
});

describe("parseProofHeader", () => {
  it("parses a well-formed header", () => {
    const parsed = parseProofHeader("ts=1700000000000;sig=abc");
    expect(parsed).toEqual({ ts: 1_700_000_000_000, sig: "abc" });
  });

  it("returns null when ts is missing", () => {
    expect(parseProofHeader("sig=abc")).toBeNull();
  });

  it("returns null when sig is missing", () => {
    expect(parseProofHeader("ts=1700000000000")).toBeNull();
  });

  it("returns null when ts is not numeric", () => {
    expect(parseProofHeader("ts=NaN;sig=abc")).toBeNull();
  });

  it("ignores extra unknown fields", () => {
    expect(parseProofHeader("ts=1;sig=abc;extra=ignored")).toEqual({ ts: 1, sig: "abc" });
  });

  it("rejects duplicate keys", () => {
    expect(parseProofHeader("ts=1;sig=A;sig=B")).toBeNull();
    expect(parseProofHeader("ts=1;sig=A;bh=X;bh=Y")).toBeNull();
  });

  it("rejects headers exceeding the length cap", () => {
    const huge = "ts=1;sig=" + "A".repeat(9000);
    expect(parseProofHeader(huge)).toBeNull();
  });

  it("rejects headers with too many segments", () => {
    const tooMany = "ts=1;sig=A;a=1;b=2;c=3;d=4;e=5;f=6;g=7;h=8";
    expect(parseProofHeader(tooMany)).toBeNull();
  });

  it("rejects segments missing an =", () => {
    expect(parseProofHeader("ts=1;sig=A;novalue")).toBeNull();
  });
});

describe("verifyBoundProof", () => {
  it("accepts a valid proof for the right session, method, and path", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-p1");
    const ts = Date.now();
    const header = await buildProof(privateKey, sessionId, "GET", "/profile-strict", ts);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "GET", path: "/profile-strict" },
        storage,
      ),
    ).resolves.toBeUndefined();
  });

  it("throws MISSING_PROOF when the header is undefined", async () => {
    const { storage, sessionId } = await bootstrapBoundSession("sess-p2");
    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: undefined, method: "GET", path: "/x" },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.MISSING_PROOF,
    });
  });

  it("throws MALFORMED_PROOF on garbage input", async () => {
    const { storage, sessionId } = await bootstrapBoundSession("sess-p3");
    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: "this-is-not-a-proof", method: "GET", path: "/x" },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.MALFORMED_PROOF,
    });
  });

  it("rejects timestamps outside the default 5-minute window", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-p4");
    const staleTs = Date.now() - 10 * 60 * 1000;
    const header = await buildProof(privateKey, sessionId, "GET", "/x", staleTs);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "GET", path: "/x" },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.SIGNATURE_INVALID,
    });
  });

  it("honors a custom timestampWindowMs", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-p5");
    const ts = Date.now() - 60_000;
    const header = await buildProof(privateKey, sessionId, "GET", "/x", ts);

    await expect(
      verifyBoundProof(
        {
          sessionId,
          proofHeader: header,
          method: "GET",
          path: "/x",
          timestampWindowMs: 10_000,
        },
        storage,
      ),
    ).rejects.toBeInstanceOf(DbscVerificationError);

    await expect(
      verifyBoundProof(
        {
          sessionId,
          proofHeader: header,
          method: "GET",
          path: "/x",
          timestampWindowMs: 5 * 60 * 1000,
        },
        storage,
      ),
    ).resolves.toBeUndefined();
  });

  it("throws KEY_NOT_FOUND when no bound key exists for the session", async () => {
    const storage = new MemoryStorage();
    await expect(
      verifyBoundProof(
        {
          sessionId: "nobody",
          proofHeader: `ts=${Date.now()};sig=abc`,
          method: "GET",
          path: "/x",
        },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.KEY_NOT_FOUND,
    });
  });

  it("rejects a signature signed for a different session id", async () => {
    const a = await bootstrapBoundSession("sess-a");
    const b = await bootstrapBoundSession("sess-b");

    const ts = Date.now();
    // Sign using session A's key but submit it as session B's proof.
    const aHeader = await buildProof(a.privateKey, "sess-a", "GET", "/x", ts);

    // The server verifies against session B's key with message "sess-b....",
    // which doesn't match what was signed. Signature fails to verify.
    await expect(
      verifyBoundProof(
        { sessionId: "sess-b", proofHeader: aHeader, method: "GET", path: "/x" },
        b.storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.SIGNATURE_INVALID,
    });
  });

  it("rejects a signature for one path replayed against another", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-p6");
    const ts = Date.now();
    const headerForMe = await buildProof(privateKey, sessionId, "GET", "/me", ts);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: headerForMe, method: "GET", path: "/payment" },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.SIGNATURE_INVALID,
    });
  });

  it("rejects a signature for one method replayed against another", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-p7");
    const ts = Date.now();
    const headerForGet = await buildProof(privateKey, sessionId, "GET", "/payment", ts);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: headerForGet, method: "POST", path: "/payment" },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.SIGNATURE_INVALID,
    });
  });

  it("verifies regardless of method casing", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-p8");
    const ts = Date.now();
    const header = await buildProof(privateKey, sessionId, "POST", "/x", ts);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "post", path: "/x" },
        storage,
      ),
    ).resolves.toBeUndefined();
  });
});

async function sha256B64Url(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  let s = "";
  const b = new Uint8Array(digest);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return Buffer.from(s, "binary").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function buildProofWithBody(
  privateKey: CryptoKey,
  sessionId: string,
  method: string,
  path: string,
  ts: number,
  bodyBytes: Uint8Array,
): Promise<string> {
  const bh = await sha256B64Url(bodyBytes);
  const message = `${sessionId}.${method.toUpperCase()}.${path}.${ts}.${bh}`;
  const sig = await signMessage(privateKey, message);
  return `ts=${ts};sig=${sig};bh=${bh}`;
}

describe("verifyBoundProof body signing", () => {
  it("accepts a proof whose body hash matches the signed body", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-b1");
    const body = new TextEncoder().encode('{"amount":1,"to":"alice"}');
    const ts = Date.now();
    const header = await buildProofWithBody(privateKey, sessionId, "POST", "/payment", ts, body);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "POST", path: "/payment", signBody: true, bodyBytes: body },
        storage,
      ),
    ).resolves.toBeUndefined();
  });

  it("rejects MALFORMED_PROOF when signBody is true but bh is missing", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-b2");
    const body = new TextEncoder().encode("hello");
    const ts = Date.now();
    // Build a proof WITHOUT the bh field.
    const header = await buildProof(privateKey, sessionId, "POST", "/x", ts);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "POST", path: "/x", signBody: true, bodyBytes: body },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.MALFORMED_PROOF,
    });
  });

  it("rejects when body hash on the wire does not match the actual body bytes", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-b3");
    const signedBody = new TextEncoder().encode('{"amount":1}');
    const sentBody = new TextEncoder().encode('{"amount":1000}');
    const ts = Date.now();
    const header = await buildProofWithBody(privateKey, sessionId, "POST", "/payment", ts, signedBody);

    // Attacker substitutes the body; bh in header reflects the original signed body.
    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "POST", path: "/payment", signBody: true, bodyBytes: sentBody },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.SIGNATURE_INVALID,
    });
  });

  it("treats empty body as a valid empty-body signature", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-b4");
    const empty = new Uint8Array(0);
    const ts = Date.now();
    const header = await buildProofWithBody(privateKey, sessionId, "POST", "/x", ts, empty);

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "POST", path: "/x", signBody: true, bodyBytes: empty },
        storage,
      ),
    ).resolves.toBeUndefined();
  });

  it("rejects stray bh on the wire when signBody is false", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-b5");
    const ts = Date.now();
    const message = `${sessionId}.GET./x.${ts}`;
    const sig = await signMessage(privateKey, message);
    const headerWithStrayBh = `ts=${ts};sig=${sig};bh=ignored-value`;

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: headerWithStrayBh, method: "GET", path: "/x" },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.MALFORMED_PROOF,
    });
  });

  it("rejects when signBody is true but bodyBytes are not supplied", async () => {
    const { storage, sessionId, privateKey } = await bootstrapBoundSession("sess-b6");
    const ts = Date.now();
    const sig = await signMessage(privateKey, `${sessionId}.POST./x.${ts}.unused`);
    const header = `ts=${ts};sig=${sig};bh=anyhash`;

    await expect(
      verifyBoundProof(
        { sessionId, proofHeader: header, method: "POST", path: "/x", signBody: true },
        storage,
      ),
    ).rejects.toMatchObject({
      name: "DbscVerificationError",
      code: ErrorCodes.MALFORMED_PROOF,
    });
  });
});
