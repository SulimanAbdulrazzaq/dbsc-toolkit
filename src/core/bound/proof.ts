import { DbscVerificationError, ErrorCodes } from "../errors.js";
import type { StorageAdapter } from "../types.js";
import { verifyP256Signature } from "./verify.js";

export const BOUND_PROOF_HEADER = "X-Dbsc-Bound-Proof";
const DEFAULT_WINDOW_MS = 5 * 60 * 1000;

export interface VerifyBoundProofRequest {
  sessionId: string;
  proofHeader: string | undefined;
  method: string;
  path: string;
  timestampWindowMs?: number | undefined;
  /**
   * Raw request body bytes. When present, `signBody` is implied. The server
   * computes sha256(bodyBytes) and demands the proof header carries a
   * matching `bh=` field signed into the message. Pass undefined for GET/HEAD
   * or when body signing is disabled.
   */
  bodyBytes?: Uint8Array | undefined;
  /** Force body signing even on GET/HEAD requests (rare). */
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
  const key = await storage.getBoundKey(req.sessionId);
  if (!key) {
    throw new DbscVerificationError(ErrorCodes.KEY_NOT_FOUND, "no bound key for session");
  }

  const wantBodySig = req.signBody === true || (req.bodyBytes !== undefined && req.bodyBytes.byteLength > 0);
  let expectedBodyHash = "";
  if (wantBodySig) {
    if (!parsed.bh) {
      throw new DbscVerificationError(ErrorCodes.MALFORMED_PROOF, "proof header missing bh (body hash)");
    }
    const actualBodyHash = await sha256Base64Url(req.bodyBytes ?? new Uint8Array(0));
    if (actualBodyHash !== parsed.bh) {
      throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "body hash mismatch");
    }
    expectedBodyHash = parsed.bh;
  }

  const message = wantBodySig
    ? `${req.sessionId}.${req.method.toUpperCase()}.${req.path}.${parsed.ts}.${expectedBodyHash}`
    : `${req.sessionId}.${req.method.toUpperCase()}.${req.path}.${parsed.ts}`;
  const ok = await verifyP256Signature(key.jwk, parsed.sig, message);
  if (!ok) {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "proof signature did not verify");
  }
}

export function parseProofHeader(s: string): { ts: number; sig: string; bh?: string } | null {
  const parts: Record<string, string> = {};
  for (const seg of s.split(";")) {
    const [k, v] = seg.trim().split("=");
    if (k && v) parts[k] = v;
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
