import { getKeyRecord } from "./keystore.js";

/**
 * Wraps a `fetch` function so every outgoing request carries a fresh ECDSA P-256
 * signature in the `X-Dbsc-Bound-Proof` header.
 *
 * Use this ONLY for calls to sensitive routes you've gated with
 * `requireBoundProof()` on the server (payment, admin, password-change, etc).
 * It is per-call by design — keep it out of `globalThis.fetch` so third-party
 * SDKs (analytics, React Query, SWR, etc) keep using the native `fetch`.
 *
 * If no bound key is present in IndexedDB the wrapped fetch transparently falls
 * back to the underlying fetch — Chromium native DBSC paths and the
 * unauthenticated paths keep working.
 */
export interface WrapFetchOptions {
  fetch?: typeof fetch;
  headerName?: string;
  /**
   * When true, the wrapper computes sha256(body) and signs it into the proof
   * header. The server must be configured with `requireBoundProof({ signBody: true })`
   * for the matching route. Defaults to false.
   *
   * Cost: one extra SHA-256 hash per request (~0.1 ms for typical JSON
   * payloads). Cannot be used with streaming request bodies — the wrapper
   * reads the body into memory to hash it.
   */
  signBody?: boolean;
}

export function wrapFetch(opts: WrapFetchOptions = {}): typeof fetch {
  const base = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const headerName = opts.headerName ?? "X-Dbsc-Bound-Proof";
  const signBody = opts.signBody ?? false;

  return (async (input, init = {}) => {
    const rec = await getKeyRecord().catch(() => null);
    if (!rec) return base(input, init);

    const url = new URL(
      typeof input === "string" || input instanceof URL ? input.toString() : input.url,
      typeof window !== "undefined" ? window.location.href : "http://localhost",
    );
    const method = (init.method ?? "GET").toUpperCase();
    const offset = rec.clockOffsetMs ?? 0;
    const ts = Date.now() + offset;

    let bodyHash = "";
    let finalBody: BodyInit | null | undefined = init.body;
    if (signBody && init.body !== undefined && init.body !== null) {
      const bodyBytes = await readBodyBytes(init.body);
      // Re-use the bytes as the actual request body so server hashes the same.
      // Wrap in a Blob to satisfy BodyInit on every runtime (Node, browser).
      finalBody = new Blob([bodyBytes as BlobPart]);
      bodyHash = await sha256B64Url(bodyBytes);
    }

    const message = signBody && bodyHash
      ? `${rec.sessionId}.${method}.${url.pathname}.${ts}.${bodyHash}`
      : `${rec.sessionId}.${method}.${url.pathname}.${ts}`;

    const sigBytes = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      rec.keyPair.privateKey,
      new TextEncoder().encode(message),
    );
    const sig = base64url(new Uint8Array(sigBytes));

    const headers = new Headers(init.headers);
    const headerValue = bodyHash
      ? `ts=${ts};sig=${sig};bh=${bodyHash}`
      : `ts=${ts};sig=${sig}`;
    headers.set(headerName, headerValue);

    const nextInit: RequestInit = {
      ...init,
      headers,
      credentials: init.credentials ?? "include",
    };
    if (finalBody !== undefined && finalBody !== null) {
      nextInit.body = finalBody as BodyInit;
    }
    return base(input, nextInit);
  }) as typeof fetch;
}

async function readBodyBytes(body: BodyInit): Promise<Uint8Array> {
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
  if (body instanceof FormData || body instanceof URLSearchParams) {
    return new TextEncoder().encode(body.toString());
  }
  if (body instanceof ReadableStream) {
    throw new Error("wrapFetch with signBody: ReadableStream body is not supported");
  }
  return new TextEncoder().encode(String(body));
}

async function sha256B64Url(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  return base64url(new Uint8Array(digest));
}

function base64url(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
