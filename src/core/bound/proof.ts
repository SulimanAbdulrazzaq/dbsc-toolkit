import { DbscVerificationError, ErrorCodes } from "../errors.js";
import type { StorageAdapter } from "../types.js";
import { verifyP256Signature } from "./verify.js";

export const BOUND_PROOF_HEADER = "X-Dbsc-Bound-Proof";
const DEFAULT_WINDOW_MS = 5 * 60 * 1000;
const MAX_HEADER_LEN = 8 * 1024;
const MAX_SEGMENTS = 8;

export interface VerifyBoundProofRequest {
  sessionId: string;
  proofHeader: string | undefined;
  method: string;
  path: string;
  timestampWindowMs?: number | undefined;
  /** Raw body bytes. Required when signBody is true. */
  bodyBytes?: Uint8Array | undefined;
  /** Hash and verify body bytes into the signed message. */
  signBody?: boolean | undefined;
}

export async function verifyBoundProof(
  req: VerifyBoundProofRequest,
  storage: StorageAdapter,
): Promise<void> {
  if (!req.proofHeader) {
    throw new DbscVerificationError(ErrorCodes.MISSING_PROOF, "proof header missing");
  }
  const parsed = parseProofHeader(req.proofHeader);
  if (!parsed) {
    throw new DbscVerificationError(ErrorCodes.MALFORMED_PROOF, "proof header malformed");
  }
  const windowMs = req.timestampWindowMs ?? DEFAULT_WINDOW_MS;
  if (Math.abs(Date.now() - parsed.ts) > windowMs) {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "proof timestamp outside window");
  }
  // The per-request proof is always verified against the polyfill key.
  // On Chromium sessions that also hold a "native" TPM key, that key is used
  // only by /dbsc/refresh — Chrome cannot sign request-scoped messages with it.
  const key = await storage.getBoundKey(req.sessionId, "bound");
  if (!key) {
    throw new DbscVerificationError(ErrorCodes.KEY_NOT_FOUND, "no polyfill bound key for session");
  }

  const wantBodySig = req.signBody === true;
  if (wantBodySig && req.bodyBytes === undefined) {
    throw new DbscVerificationError(
      ErrorCodes.MALFORMED_PROOF,
      "signBody requires bodyBytes",
    );
  }
  if (!wantBodySig && parsed.bh) {
    throw new DbscVerificationError(
      ErrorCodes.MALFORMED_PROOF,
      "proof header carries bh but signBody is disabled",
    );
  }

  let bodyHash = "";
  if (wantBodySig) {
    if (!parsed.bh) {
      throw new DbscVerificationError(ErrorCodes.MALFORMED_PROOF, "proof header missing bh");
    }
    const actual = await sha256Base64Url(req.bodyBytes!);
    if (actual !== parsed.bh) {
      throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "body hash mismatch");
    }
    bodyHash = parsed.bh;
  }

  const message = wantBodySig
    ? `${req.sessionId}.${req.method.toUpperCase()}.${req.path}.${parsed.ts}.${bodyHash}`
    : `${req.sessionId}.${req.method.toUpperCase()}.${req.path}.${parsed.ts}`;
  const ok = await verifyP256Signature(key.jwk, parsed.sig, message);
  if (!ok) {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "proof signature did not verify");
  }
}

export function parseProofHeader(s: string): { ts: number; sig: string; bh?: string } | null {
  if (s.length > MAX_HEADER_LEN) return null;
  const segments = s.split(";");
  if (segments.length > MAX_SEGMENTS) return null;

  const parts: Record<string, string> = {};
  for (const seg of segments) {
    const trimmed = seg.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) return null;
    const k = trimmed.slice(0, eq);
    const v = trimmed.slice(eq + 1);
    if (!v) return null;
    if (k in parts) return null;
    parts[k] = v;
  }
  const ts = Number(parts.ts);
  if (!Number.isFinite(ts) || !parts.sig) return null;
  const out: { ts: number; sig: string; bh?: string } = { ts, sig: parts.sig };
  if (parts.bh) out.bh = parts.bh;
  return out;
}

async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  return base64UrlBytes(new Uint8Array(digest));
}

function base64UrlBytes(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return Buffer.from(s, "binary").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
