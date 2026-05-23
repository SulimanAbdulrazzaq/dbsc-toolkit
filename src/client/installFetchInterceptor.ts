import { wrapFetch, type WrapFetchOptions } from "./wrapFetch.js";

export interface InstallFetchInterceptorOptions {
  /**
   * Path prefixes to intercept. A request whose URL's pathname starts with
   * any of these (on the current origin) is routed through `wrapFetch` —
   * every other request goes through the original `fetch` untouched.
   *
   * Must be non-empty. Bare `"/"` is rejected: it would match every same-origin
   * fetch and sign every static asset / health check; in production code that
   * is almost certainly not what you want. Use an explicit prefix like
   * `"/api/secure/"` or `"/dbsc-guarded/"` instead.
   *
   * Prefixes that look like absolute URLs (`http://`, `https://`) are rejected
   * — the interceptor only touches same-origin requests, by design, so it
   * cannot sign requests to third-party hosts (and leak the session key).
   */
  pathPrefixes: string[];
  /** Forwarded to `wrapFetch` — defaults to true as of v2.8. */
  signBody?: WrapFetchOptions["signBody"];
  /** Override the header name passed to `wrapFetch`. */
  headerName?: WrapFetchOptions["headerName"];
  /** Override the global fetch — useful in tests. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * Replace `globalThis.fetch` (or the provided `fetch`) with a wrapper that
 * routes matching same-origin requests through `wrapFetch`, and everything
 * else through the original fetch. Returns an `uninstall` function that
 * restores the original.
 *
 * **When to use this:** apps with many guarded routes where calling
 * `wrapFetch` at every call site is a footgun. For small apps, the per-call
 * `wrapFetch(...)` shape stays the recommended default.
 *
 * **Safety:** the interceptor only touches requests whose URL is same-origin
 * and whose pathname matches one of `pathPrefixes`. Third-party hosts are
 * always passed through to the original fetch — the session key never leaves
 * your origin.
 */
export function installFetchInterceptor(opts: InstallFetchInterceptorOptions): () => void {
  if (!opts.pathPrefixes || opts.pathPrefixes.length === 0) {
    throw new Error("installFetchInterceptor: pathPrefixes must be a non-empty array");
  }
  for (const prefix of opts.pathPrefixes) {
    if (typeof prefix !== "string" || prefix.length === 0) {
      throw new Error("installFetchInterceptor: each prefix must be a non-empty string");
    }
    if (prefix === "/") {
      throw new Error(
        "installFetchInterceptor: pathPrefixes cannot include '/' — specify explicit route prefixes (e.g. '/api/secure/') to avoid signing static assets, health checks, or third-party requests",
      );
    }
    if (prefix.startsWith("http://") || prefix.startsWith("https://")) {
      throw new Error(
        "installFetchInterceptor: pathPrefixes must be path-only (e.g. '/api/secure/') — absolute URLs are not allowed; the interceptor never signs cross-origin requests",
      );
    }
    if (!prefix.startsWith("/")) {
      throw new Error(
        "installFetchInterceptor: each prefix must start with '/' (e.g. '/api/secure/')",
      );
    }
  }

  // Two distinct concepts: the upstream fetch the interceptor delegates to
  // (test-friendly override via opts.fetch), and the fetch that was on
  // globalThis at install time (what we restore on uninstall).
  const upstreamFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const priorGlobalFetch = globalThis.fetch;
  const signed = wrapFetch({
    fetch: upstreamFetch,
    ...(opts.signBody !== undefined && { signBody: opts.signBody }),
    ...(opts.headerName !== undefined && { headerName: opts.headerName }),
  });

  const interceptor: typeof fetch = async (input, init) => {
    const url = resolveUrl(input);
    if (url && isSameOrigin(url) && matchesAnyPrefix(url.pathname, opts.pathPrefixes)) {
      return signed(input, init);
    }
    return upstreamFetch(input, init);
  };

  globalThis.fetch = interceptor;
  return () => {
    globalThis.fetch = priorGlobalFetch;
  };
}

function resolveUrl(input: RequestInfo | URL): URL | null {
  try {
    const raw = typeof input === "string" || input instanceof URL ? input.toString() : input.url;
    const base = typeof window !== "undefined" ? window.location.href : "http://localhost";
    return new URL(raw, base);
  } catch {
    return null;
  }
}

function isSameOrigin(url: URL): boolean {
  if (typeof window === "undefined") return true; // no DOM origin to compare against — assume same
  return url.origin === window.location.origin;
}

function matchesAnyPrefix(pathname: string, prefixes: string[]): boolean {
  for (const p of prefixes) {
    if (pathname.startsWith(p)) return true;
  }
  return false;
}
