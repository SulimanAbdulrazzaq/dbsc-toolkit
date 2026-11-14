import { Readable } from "node:stream";
import type { FastifyRequest, FastifyReply } from "fastify";
import { BOUND_PROOF_HEADER } from "../core/index.js";

/** Where the captured request bytes live on the request. */
export const PROOF_BODY: unique symbol = Symbol("dbsc-toolkit.fastify.proofBody");

/** Default cap on a body captured for the proof's body hash (1 MiB). */
export const DEFAULT_MAX_PROOF_BODY_BYTES = 1024 * 1024;

/** Reads the bytes the client hashed, if the capture hook stored them. */
export function capturedProofBody(req: FastifyRequest): Uint8Array | undefined {
  return (req as unknown as Record<PropertyKey, unknown>)[PROOF_BODY] as Uint8Array | undefined;
}

type PreParsing = (
  req: FastifyRequest,
  reply: FastifyReply,
  payload: NodeJS.ReadableStream,
) => Promise<NodeJS.ReadableStream>;

/**
 * A `preParsing` hook that copies the raw body of requests carrying a proof
 * header and hands Fastify an identical stream, so the route keeps its usual
 * JSON parser and `requireProof()` hashes the exact bytes the client signed.
 * `createDbsc().install()` adds it for you.
 */
export function captureProofBody(opts: { limit?: number } = {}): PreParsing {
  const limit = opts.limit ?? DEFAULT_MAX_PROOF_BODY_BYTES;
  const header = BOUND_PROOF_HEADER.toLowerCase();
  return async (req, _reply, payload) => {
    if (!req.headers[header]) return payload;
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > limit) return payload;
    const chunks: Buffer[] = [];
    let got = 0;
    for await (const chunk of payload as AsyncIterable<Buffer | string>) {
      const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      got += buf.length;
      if (got > limit) {
        throw Object.assign(new Error("request body too large for proof verification"), {
          statusCode: 413,
        });
      }
      chunks.push(buf);
    }
    const body = Buffer.concat(chunks, got);
    (req as unknown as Record<PropertyKey, unknown>)[PROOF_BODY] = new Uint8Array(body);
    const replay = Readable.from(body.length > 0 ? [body] : []);
    (replay as unknown as { receivedEncodedLength: number }).receivedEncodedLength = body.length;
    return replay;
  };
}
