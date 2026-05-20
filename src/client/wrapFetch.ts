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
}

export function wrapFetch(opts: WrapFetchOptions = {}): typeof fetch {
  const base = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const headerName = opts.headerName ?? "X-Dbsc-Bound-Proof";

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
    const message = `${rec.sessionId}.${method}.${url.pathname}.${ts}`;
    const sigBytes = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      rec.keyPair.privateKey,
      new TextEncoder().encode(message),
    );
    const sig = base64url(new Uint8Array(sigBytes));
    const headers = new Headers(init.headers);
    headers.set(headerName, `ts=${ts};sig=${sig}`);
    return base(input, { ...init, headers, credentials: init.credentials ?? "include" });
  }) as typeof fetch;
}

function base64url(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
