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
  const message = `${req.sessionId}.${req.method.toUpperCase()}.${req.path}.${parsed.ts}`;
  const ok = await verifyP256Signature(key.jwk, parsed.sig, message);
  if (!ok) {
    throw new DbscVerificationError(ErrorCodes.SIGNATURE_INVALID, "proof signature did not verify");
  }
}

export function parseProofHeader(s: string): { ts: number; sig: string } | null {
  const parts: Record<string, string> = {};
  for (const seg of s.split(";")) {
    const [k, v] = seg.trim().split("=");
    if (k && v) parts[k] = v;
  }
  const ts = Number(parts.ts);
  if (!Number.isFinite(ts) || !parts.sig) return null;
  return { ts, sig: parts.sig };
}
