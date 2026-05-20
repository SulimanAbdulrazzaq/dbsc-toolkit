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

  const sig = base64urlDecode(signatureB64Url);
  const msg = new TextEncoder().encode(message);

  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength) as ArrayBuffer,
    msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength) as ArrayBuffer,
  );
}

function base64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
