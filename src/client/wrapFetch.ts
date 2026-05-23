import { getKeyRecord } from "./keystore.js";

/** Per-call fetch wrapper that signs requests with the bound key. Never assign to globalThis.fetch. */
export interface WrapFetchOptions {
  fetch?: typeof fetch;
  headerName?: string;
  /**
   * SHA-256 the body into the proof header. **Default `true` as of v2.8** —
   * `requireProof()` on the server always wants a body hash, so signing by
   * default is the safe shape. Pass `false` only if you have a bespoke
   * server-side path that disables body checking. ReadableStream bodies not
   * supported.
   */
  signBody?: boolean;
}

export function wrapFetch(opts: WrapFetchOptions = {}): typeof fetch {
  const base = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const headerName = opts.headerName ?? "X-Dbsc-Bound-Proof";
  const signBody = opts.signBody ?? true;

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
    if (signBody) {
      const bodyBytes = init.body === undefined || init.body === null
        ? new Uint8Array(0)
        : await readBodyBytes(init.body);
      if (bodyBytes.byteLength > 0) {
        finalBody = new Blob([bodyBytes as BlobPart]);
      }
      bodyHash = await sha256B64Url(bodyBytes);
    }

    const message = signBody
      ? `${rec.sessionId}.${method}.${url.pathname}.${ts}.${bodyHash}`
      : `${rec.sessionId}.${method}.${url.pathname}.${ts}`;

    const sigBytes = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      rec.keyPair.privateKey,
      new TextEncoder().encode(message),
    );
    const sig = base64url(new Uint8Array(sigBytes));

    const headers = new Headers(init.headers);
    const headerValue = signBody
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
