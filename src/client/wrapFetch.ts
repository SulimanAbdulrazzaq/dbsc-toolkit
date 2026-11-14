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
  /**
   * Include the query string in the signed message (`/path?a=1`). Off by
   * default for compatibility; turn it on together with the server's
   * `requireProof({ signQuery: true })` for routes that act on query
   * parameters, which are otherwise not covered by the proof.
   */
  signQuery?: boolean;
}

export function wrapFetch(opts: WrapFetchOptions = {}): typeof fetch {
  const base = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const headerName = opts.headerName ?? "X-Dbsc-Bound-Proof";
  const signBody = opts.signBody ?? true;
  const signQuery = opts.signQuery ?? false;

  return (async (input, init = {}) => {
    const rec = await getKeyRecord().catch(() => null);
    if (!rec) return base(input, init);

    const req = typeof Request !== "undefined" && input instanceof Request ? input : null;
    const url = new URL(
      typeof input === "string" || input instanceof URL ? input.toString() : input.url,
      typeof window !== "undefined" ? window.location.href : "http://localhost",
    );
    const method = (init.method ?? req?.method ?? "GET").toUpperCase();
    const offset = rec.clockOffsetMs ?? 0;
    const ts = Date.now() + offset;
    // fetch(request, { headers }) replaces the Request's headers, so start from them.
    const headers = new Headers(init.headers ?? req?.headers);

    let bodyHash = "";
    let finalBody: BodyInit | null | undefined = init.body;
    if (signBody) {
      let encoded: EncodedBody;
      if (init.body !== undefined && init.body !== null) {
        encoded = await encodeBody(init.body);
      } else if (req && req.body !== null) {
        encoded = { bytes: new Uint8Array(await req.clone().arrayBuffer()), contentType: null };
      } else {
        encoded = { bytes: new Uint8Array(0), contentType: null };
      }
      if (encoded.bytes.byteLength > 0) {
        // Send exactly the bytes that were hashed.
        finalBody = encoded.bytes as BodyInit;
        if (encoded.contentType && !headers.has("content-type")) {
          headers.set("content-type", encoded.contentType);
        }
      }
      bodyHash = await sha256B64Url(encoded.bytes);
    }

    const target = signQuery ? url.pathname + url.search : url.pathname;
    const message = signBody
      ? `${rec.sessionId}.${method}.${target}.${ts}.${bodyHash}`
      : `${rec.sessionId}.${method}.${target}.${ts}`;

    const sigBytes = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      rec.keyPair.privateKey,
      new TextEncoder().encode(message),
    );
    const sig = base64url(new Uint8Array(sigBytes));

    const headerValue = signBody
      ? `ts=${ts};sig=${sig};bh=${bodyHash}`
      : `ts=${ts};sig=${sig}`;
    headers.set(headerName, headerValue);

    const nextInit: RequestInit = {
      ...(req && signBody ? requestInitOf(req) : {}),
      ...init,
      method,
      headers,
      credentials: init.credentials ?? req?.credentials ?? "include",
    };
    if (finalBody !== undefined && finalBody !== null) {
      nextInit.body = finalBody as BodyInit;
    }
    // A signed Request is rebuilt from its URL so the hashed bytes are the body sent.
    return base(req && signBody ? req.url : input, nextInit);
  }) as typeof fetch;
}

/** The parts of a Request that survive rebuilding it from its URL. */
function requestInitOf(req: Request): RequestInit {
  return {
    signal: req.signal,
    mode: req.mode,
    cache: req.cache,
    redirect: req.redirect,
    referrerPolicy: req.referrerPolicy,
    integrity: req.integrity,
    keepalive: req.keepalive,
  };
}

interface EncodedBody {
  bytes: Uint8Array;
  /** The Content-Type fetch would have set for this body, when it sets one. */
  contentType: string | null;
}

/**
 * Turns a fetch body into the exact bytes and Content-Type the browser would
 * send. FormData goes through Response so the multipart boundary in the
 * header matches the bytes that were hashed.
 */
async function encodeBody(body: BodyInit): Promise<EncodedBody> {
  if (typeof body === "string") {
    return { bytes: new TextEncoder().encode(body), contentType: "text/plain;charset=UTF-8" };
  }
  if (body instanceof Uint8Array) return { bytes: body, contentType: null };
  if (body instanceof ArrayBuffer) return { bytes: new Uint8Array(body), contentType: null };
  if (ArrayBuffer.isView(body)) {
    return { bytes: new Uint8Array(body.buffer, body.byteOffset, body.byteLength), contentType: null };
  }
  if (body instanceof URLSearchParams) {
    return {
      bytes: new TextEncoder().encode(body.toString()),
      contentType: "application/x-www-form-urlencoded;charset=UTF-8",
    };
  }
  if (body instanceof Blob) {
    return { bytes: new Uint8Array(await body.arrayBuffer()), contentType: body.type || null };
  }
  if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) {
    throw new Error("wrapFetch with signBody: ReadableStream body is not supported");
  }
  if (typeof FormData !== "undefined" && body instanceof FormData) {
    const res = new Response(body);
    return {
      bytes: new Uint8Array(await res.arrayBuffer()),
      contentType: res.headers.get("content-type"),
    };
  }
  return { bytes: new TextEncoder().encode(String(body)), contentType: "text/plain;charset=UTF-8" };
}

async function sha256B64Url(bytes: Uint8Array): Promise<string> {
  // Pass the Uint8Array directly. Earlier code sliced .buffer to escape any
  // surrounding pool buffer; Node 22's stricter SubtleCrypto rejects that
  // shape because the slice returns a generic ArrayBufferLike. A fresh
  // Uint8Array copy gives the runtime a clean BufferSource without aliasing
  // the input.
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy);
  return base64url(new Uint8Array(digest));
}

function base64url(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
