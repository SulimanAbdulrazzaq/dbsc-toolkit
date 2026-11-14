import { afterEach, describe, expect, it } from "vitest";
import "fake-indexeddb/auto";
import { wrapFetch } from "./wrapFetch.js";
import { setKeyRecord, clearKeyRecord } from "./keystore.js";

interface Sent {
  url: string;
  method: string | undefined;
  headers: Headers;
  bytes: Uint8Array;
}

function recorder(): { fetch: typeof fetch; sent: Sent[] } {
  const sent: Sent[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const body = init.body === undefined || init.body === null ? new Uint8Array(0) : new Uint8Array(await new Response(init.body).arrayBuffer());
    sent.push({ url: String(input), method: init.method, headers: new Headers(init.headers), bytes: body });
    return new Response("ok");
  }) as typeof fetch;
  return { fetch: fetchImpl, sent };
}

async function seedKey(): Promise<void> {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  await setKeyRecord({ sessionId: "sess", keyPair });
}

async function hashOf(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Buffer.from(digest).toString("base64url");
}

afterEach(async () => {
  await clearKeyRecord();
});

describe("wrapFetch body encoding", () => {
  it("signs the exact multipart bytes it sends for FormData", async () => {
    await seedKey();
    const { fetch: upstream, sent } = recorder();
    const form = new FormData();
    form.set("file", new Blob(["hello"], { type: "text/plain" }), "a.txt");
    await wrapFetch({ fetch: upstream })("/upload", { method: "POST", body: form });
    const req = sent[0]!;
    expect(req.headers.get("content-type")).toMatch(/^multipart\/form-data; boundary=/);
    expect(new TextDecoder().decode(req.bytes)).toContain("hello");
    const bh = /bh=([^;]+)/.exec(req.headers.get("x-dbsc-bound-proof") ?? "")?.[1];
    expect(bh).toBe(await hashOf(req.bytes));
  });

  it("keeps the urlencoded content type for URLSearchParams", async () => {
    await seedKey();
    const { fetch: upstream, sent } = recorder();
    await wrapFetch({ fetch: upstream })("/form", { method: "POST", body: new URLSearchParams({ a: "1" }) });
    expect(sent[0]!.headers.get("content-type")).toBe("application/x-www-form-urlencoded;charset=UTF-8");
    expect(new TextDecoder().decode(sent[0]!.bytes)).toBe("a=1");
  });

  it("does not override a content type the caller set", async () => {
    await seedKey();
    const { fetch: upstream, sent } = recorder();
    await wrapFetch({ fetch: upstream })("/json", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"a":1}',
    });
    expect(sent[0]!.headers.get("content-type")).toBe("application/json");
  });

  it("signs a Request object's method, headers and body", async () => {
    await seedKey();
    const { fetch: upstream, sent } = recorder();
    const request = new Request("http://localhost/api/x", {
      method: "PUT",
      headers: { "x-app": "1" },
      body: "payload",
    });
    await wrapFetch({ fetch: upstream })(request);
    const req = sent[0]!;
    expect(req.method).toBe("PUT");
    expect(req.headers.get("x-app")).toBe("1");
    expect(new TextDecoder().decode(req.bytes)).toBe("payload");
    expect(req.headers.get("x-dbsc-bound-proof")).toContain(`bh=${await hashOf(req.bytes)}`);
  });
});
