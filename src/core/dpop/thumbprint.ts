import { calculateJwkThumbprint, type JWK } from "jose";

/**
 * RFC 7638 JWK SHA-256 Thumbprint, base64url without padding. This is the
 * `jkt` value: the access token is bound to the proof key by embedding this
 * thumbprint in the token's `cnf.jkt`, and the resource server confirms the
 * DPoP proof's `jwk` produces the same thumbprint (RFC 9449 §6).
 */
export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  return calculateJwkThumbprint(jwk as JWK, "sha256");
}

/**
 * The `ath` claim: base64url(SHA-256(ASCII(access token))) (RFC 9449 §4.2).
 * Lets the server confirm the proof was minted for the exact token presented.
 */
export async function accessTokenHash(accessToken: string): Promise<string> {
  const bytes = new TextEncoder().encode(accessToken);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64UrlBytes(new Uint8Array(digest));
}

function base64UrlBytes(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return Buffer.from(s, "binary")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
