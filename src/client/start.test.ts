// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import "fake-indexeddb/auto";
import { startDbsc, getDbscClient } from "./start.js";
import { setKeyRecord, clearKeyRecord } from "./keystore.js";

interface Call {
  path: string;
  signed: boolean;
}

let calls: Call[] = [];
let loginResponseHeaders: Record<string, string> = {};
const originalFetch = globalThis.fetch;

beforeEach(async () => {
  calls = [];
  loginResponseHeaders = {};
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  await setKeyRecord({ sessionId: "sess", keyPair });
  globalThis.fetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url, window.location.href);
    calls.push({ path: url.pathname, signed: new Headers(init.headers).has("x-dbsc-bound-proof") });
    if (url.pathname === "/dbsc-bound/state") {
      return Response.json({ phase: "bound", tier: "bound", sessionId: "sess", refreshIntervalMs: 600_000 });
    }
    if (url.pathname === "/login") return new Response("ok", { headers: loginResponseHeaders });
    return new Response("ok");
  }) as typeof fetch;
});

afterEach(async () => {
  getDbscClient()?.stop();
  globalThis.fetch = originalFetch;
  await clearKeyRecord();
});

describe("startDbsc", () => {
  it("registers, then signs same-origin calls but not its own protocol calls", async () => {
    const client = startDbsc();
    expect(await client.ready).toEqual({ phase: "polyfill-bound", tier: "bound" });
    await fetch("/api/pay", { method: "POST", body: "x" });
    await fetch("https://other.example/api/pay");
    expect(calls.find((c) => c.path === "/dbsc-bound/state")?.signed).toBe(false);
    expect(calls.find((c) => c.path === "/api/pay")?.signed).toBe(true);
    expect(calls.filter((c) => c.path === "/api/pay")).toHaveLength(2);
    expect(calls.filter((c) => c.path === "/api/pay")[1]?.signed).toBe(false);
  });

  it("limits signing to the given prefixes", async () => {
    const client = startDbsc({ sign: ["/api/"] });
    await client.ready;
    await fetch("/api/a");
    await fetch("/static/b");
    expect(calls.find((c) => c.path === "/api/a")?.signed).toBe(true);
    expect(calls.find((c) => c.path === "/static/b")?.signed).toBe(false);
  });

  it("returns the same client on a second call and notifies subscribers", async () => {
    const first = startDbsc();
    expect(startDbsc()).toBe(first);
    const seen: string[] = [];
    first.subscribe((o) => seen.push(o.phase));
    await first.restart();
    expect(seen).toContain("polyfill-bound");
  });

  it("re-runs registration when a fetch response starts a binding", async () => {
    const client = startDbsc();
    await client.ready;
    const before = calls.filter((c) => c.path === "/dbsc-bound/state").length;
    loginResponseHeaders = { "Secure-Session-Registration": '(ES256);path="/dbsc/registration"' };
    await fetch("/login", { method: "POST" });
    await new Promise((r) => setTimeout(r, 20));
    await client.ready;
    expect(calls.filter((c) => c.path === "/dbsc-bound/state").length).toBeGreaterThan(before);
  });
});
