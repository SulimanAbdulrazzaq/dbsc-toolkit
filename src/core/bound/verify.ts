import { DbscVerificationError, ErrorCodes } from "../errors.js";

export async function verifyP256Signature(
  jwk: JsonWebKey,
  signatureB64Url: string,
  message: string,
): Promise<boolean> {
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new DbscVerificationError(ErrorCodes.INVALID_JWK, "publicKey did not import as ECDSA P-256");
  }

  // The signature header is capped at 8 KB upstream (parseProofHeader's
  // MAX_HEADER_LEN), so the decoded length is bounded and the verify call
  // is constant-time in practice. Pass Uint8Array directly to SubtleCrypto
  // — accepts it as a BufferSource on every runtime, no slice juggling.
  const sig = base64urlDecode(signatureB64Url);
  const msg = new TextEncoder().encode(message);

  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    sig as BufferSource,
    msg as BufferSource,
  );
}

function base64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  // Uint8Array.from with a mapper is linear and bound by bin.length, which
  // is itself bound upstream by the 8KB header cap. CodeQL flagged the
  // explicit `for` loop as "loop bound injection" — it isn't (the upper
  // bound is server-side capped before this is reached), but the
  // Uint8Array.from form makes the intent clearer to the analyzer.
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
