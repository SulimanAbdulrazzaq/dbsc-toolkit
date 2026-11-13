import { describe, it, expect } from "vitest";
import type { RequestEvent } from "@sveltejs/kit";

// The tested SvelteKit (3.x) requires Node 22.17+; CI also covers Node 20,
// where the adapter is only usable with SvelteKit 2. Load it lazily so an
// unsupported runtime skips these tests instead of failing on import.
const [nodeMajor = 0, nodeMinor = 0] = process.versions.node.split(".").map(Number);
const kitRuns = nodeMajor > 22 || (nodeMajor === 22 && nodeMinor >= 17);
const { dbscHandle } = kitRuns
  ? await import("./index.js")
  : ({} as typeof import("./index.js"));
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

function mockEvent(method: string, path: string, cookies: Record<string, string> = {}): RequestEvent {
  const store: Record<string, string> = { ...cookies };
  const event = {
    request: new Request(`http://localhost${path}`, { method }),
    url: new URL(`http://localhost${path}`),
    cookies: {
      get: (n: string) => store[n],
      set: (n: string, v: string) => {
        store[n] = v;
      },
      delete: (n: string) => {
        delete store[n];
      },
    },
    locals: {} as Record<string, unknown>,
    setHeaders: () => {},
    getClientAddress: () => "127.0.0.1",
  };
  return event as unknown as RequestEvent;
}

const downstream = async () => new Response("downstream", { status: 299 });

describe.skipIf(!kitRuns)("sveltekit dbscHandle", () => {
  it("answers the bound state route", async () => {
    const handle = dbscHandle({ storage: new MemoryStorage(), secure: false });
    const res = await handle({ event: mockEvent("GET", "/dbsc-bound/state"), resolve: downstream });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ phase: "unbound", sessionId: null });
  });

  it("passes non-protocol requests through to resolve()", async () => {
    const handle = dbscHandle({ storage: new MemoryStorage(), secure: false });
    const res = await handle({ event: mockEvent("GET", "/dashboard"), resolve: downstream });
    expect(res.status).toBe(299);
    expect(await res.text()).toBe("downstream");
  });
});

describe.skipIf(!kitRuns)("sveltekit dbscHandle — bound: false", () => {
  it("state answers unbound and the bound challenge route falls through", async () => {
    const handle = dbscHandle({ storage: new MemoryStorage(), secure: false, bound: false });
    const state = await handle({ event: mockEvent("GET", "/dbsc-bound/state"), resolve: downstream });
    expect(await state.json()).toEqual({ phase: "unbound", sessionId: null });
    const challenge = await handle({ event: mockEvent("GET", "/dbsc-bound/challenge"), resolve: downstream });
    expect(challenge.status).toBe(299);
  });
});
