// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import "fake-indexeddb/auto";
import { installFetchInterceptor } from "./installFetchInterceptor.js";
import { setKeyRecord, clearKeyRecord } from "./keystore.js";

const PROOF_HEADER = "X-Dbsc-Bound-Proof";

async function seedKey(sessionId: string): Promise<void> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  await setKeyRecord({ sessionId, keyPair: pair });
}

interface CallLog {
  url: string;
  hasProof: boolean;
}

function makeUpstream(): { fetch: typeof fetch; calls: CallLog[] } {
  const calls: CallLog[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const urlStr = typeof input === "string" || input instanceof URL ? input.toString() : input.url;
    const headers = new Headers(init.headers);
    calls.push({ url: urlStr, hasProof: headers.has(PROOF_HEADER) });
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

const installed: Array<() => void> = [];
afterEach(async () => {
  while (installed.length) installed.pop()!();
  await clearKeyRecord().catch(() => {});
});

describe("installFetchInterceptor — validation", () => {
  it("rejects an empty pathPrefixes array", () => {
    expect(() => installFetchInterceptor({ pathPrefixes: [] })).toThrow(/non-empty/);
  });

  it("rejects bare '/' to prevent signing everything", () => {
    expect(() => installFetchInterceptor({ pathPrefixes: ["/"] })).toThrow(
      /cannot include '\/'/,
    );
  });

  it("rejects absolute URL prefixes (no cross-origin signing)", () => {
    expect(() =>
      installFetchInterceptor({ pathPrefixes: ["https://evil.example.com/"] }),
    ).toThrow(/path-only/);
    expect(() =>
      installFetchInterceptor({ pathPrefixes: ["http://x/"] }),
    ).toThrow(/path-only/);
  });

  it("rejects prefixes that don't start with '/'", () => {
    expect(() => installFetchInterceptor({ pathPrefixes: ["api/secure/"] })).toThrow(
      /must start with '\/'/,
    );
  });
});

describe("installFetchInterceptor — routing", () => {
  it("signs requests whose pathname matches a prefix", async () => {
    await seedKey("s-int-1");
    const up = makeUpstream();
    installed.push(installFetchInterceptor({ pathPrefixes: ["/api/secure/"], fetch: up.fetch }));

    await globalThis.fetch("/api/secure/payment", { method: "POST", body: "{}" });
    expect(up.calls).toHaveLength(1);
    expect(up.calls[0]?.hasProof).toBe(true);
  });

  it("does not sign requests outside the prefix", async () => {
    await seedKey("s-int-2");
    const up = makeUpstream();
    installed.push(installFetchInterceptor({ pathPrefixes: ["/api/secure/"], fetch: up.fetch }));

    await globalThis.fetch("/public/news");
    expect(up.calls).toHaveLength(1);
    expect(up.calls[0]?.hasProof).toBe(false);
  });

  it("does not sign cross-origin requests even if the pathname matches", async () => {
    await seedKey("s-int-3");
    const up = makeUpstream();
    installed.push(installFetchInterceptor({ pathPrefixes: ["/api/secure/"], fetch: up.fetch }));

    await globalThis.fetch("https://stripe.example.com/api/secure/charge", { method: "POST" });
    expect(up.calls).toHaveLength(1);
    expect(up.calls[0]?.hasProof).toBe(false);
  });

  it("uninstall restores the original fetch", async () => {
    await seedKey("s-int-4");
    const up = makeUpstream();
    const original = globalThis.fetch;
    const uninstall = installFetchInterceptor({ pathPrefixes: ["/api/secure/"], fetch: up.fetch });
    expect(globalThis.fetch).not.toBe(original);
    uninstall();
    expect(globalThis.fetch).toBe(original);
  });
});
