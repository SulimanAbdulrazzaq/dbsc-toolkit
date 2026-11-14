import type { Request, Response, NextFunction, RequestHandler } from "express";
import { BOUND_PROOF_HEADER } from "../core/index.js";

/** Where the captured request bytes live on the request. */
export const PROOF_BODY: unique symbol = Symbol("dbsc-toolkit.express.proofBody");

/** Default cap on a body captured for the proof's body hash (1 MiB). */
export const DEFAULT_MAX_PROOF_BODY_BYTES = 1024 * 1024;

export interface CaptureProofBodyOptions {
  /** Largest body to capture, in bytes. Larger bodies are left alone and fail the proof. Default 1 MiB. */
  limit?: number;
}

/** Reads the bytes the client hashed, if this middleware captured them. */
export function capturedProofBody(req: Request): Uint8Array | undefined {
  return (req as unknown as Record<PropertyKey, unknown>)[PROOF_BODY] as Uint8Array | undefined;
}

/**
 * Copies the raw body of every request that carries a proof header, then puts
 * the bytes back on the stream. `requireProof()` hashes the copy, and the
 * app's own parsers (`express.json()`, `express.raw()`, multer) still read the
 * body as if nothing happened. `createDbsc().install()` mounts this for you.
 *
 * Only bodies with a `Content-Length` are captured. Chunked bodies are left
 * alone; for those, parse the route with `express.raw()` as before.
 */
export function captureProofBody(opts: CaptureProofBodyOptions = {}): RequestHandler {
  const limit = opts.limit ?? DEFAULT_MAX_PROOF_BODY_BYTES;
  const header = BOUND_PROOF_HEADER.toLowerCase();
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.headers[header]) return next();
    const len = Number(req.headers["content-length"]);
    if (!Number.isSafeInteger(len) || len <= 0 || len > limit) return next();
    if (req.readableEnded || !req.readable) return next();

    const chunks: Buffer[] = [];
    let got = 0;
    let finished = false;

    const finish = (err?: unknown): void => {
      if (finished) return;
      finished = true;
      req.off("readable", onReadable);
      req.off("end", onEnd);
      req.off("error", finish);
      if (err) return next(err);
      const body = Buffer.concat(chunks, got);
      (req as unknown as Record<PropertyKey, unknown>)[PROOF_BODY] = new Uint8Array(body);
      // Hand the bytes back so downstream body parsers see an untouched stream.
      // unshift runs in the same tick as the last read, before any 'end'.
      if (!req.readableEnded && body.length > 0) req.unshift(body);
      next();
    };
    const onReadable = (): void => {
      let chunk: Buffer | null;
      while (got < len && (chunk = req.read() as Buffer | null) !== null) {
        chunks.push(chunk);
        got += chunk.length;
      }
      if (got >= len) finish();
    };
    const onEnd = (): void => finish();

    req.on("readable", onReadable);
    req.on("end", onEnd);
    req.on("error", finish);
  };
}
