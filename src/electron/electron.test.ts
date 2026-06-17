import { describe, it, expect } from "vitest";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createElectronDbsc } from "./create-dbsc.js";
import { requireProof } from "./index.js";
import { dbsc } from "../node/index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";
import type { Session, BoundKey } from "../core/index.js";

const SCHEME = "https://app.local";

function makeKit(opts: Record<string, unknown> = {}) {
  const storage = new MemoryStorage();
  const kit = createElectronDbsc({ storage, secure: false, ...opts });
  return { storage, handle: kit.protocolHandler(), kit };
}

async function seedDbscSession(storage: MemoryStorage, sessionId: string): Promise<void> {
  const now = Date.now();
  const session: Session = { id: sessionId, userId: "u1", tier: "dbsc", createdAt: now, expiresAt: now + 60_000, lastRefreshAt: now };
  await storage.setSession(session);
  const key: BoundKey = { sessionId, kind: "native", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, createdAt: now, algorithm: "ES256" };
  await storage.setBoundKey(key);
}

describe("electron adapter — protocol.handle bridge", () => {
  it("answers the bound state route (unbound with no session)", async () => {
    const { handle } = makeKit();
    const res = await handle(new Request(`${SCHEME}/dbsc-bound/state`));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ phase: "unbound", sessionId: null });
  });

  it("issues a challenge on the bound challenge route when a session exists", async () => {
    const { storage, handle } = makeKit();
    const sessionId = "sess-electron-1";
    await seedDbscSession(storage, sessionId);
    const res = await handle(
      new Request(`${SCHEME}/dbsc-bound/challenge`, { headers: { cookie: `dbsc-session=${sessionId}` } }),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { challenge?: string };
    expect(typeof body.challenge).toBe("string");
  });

  it("refresh with no proof returns 403 and a challenge header", async () => {
    const { storage, handle } = makeKit();
    const sessionId = "sess-electron-refresh";
    await seedDbscSession(storage, sessionId);
    const res = await handle(
      new Request(`${SCHEME}/dbsc/refresh`, {
        method: "POST",
        headers: { "sec-secure-session-id": sessionId },
      }),
    );
    expect(res.status).toBe(403);
    expect(res.headers.get("sec-session-challenge")).toBeTruthy();
  });

  it("sets the challenge Set-Cookie on the Response when one is produced", async () => {
    const { storage, handle } = makeKit();
    const sessionId = "sess-electron-cookie";
    await seedDbscSession(storage, sessionId);
    const res = await handle(
      new Request(`${SCHEME}/dbsc/refresh`, { method: "POST", headers: { "sec-secure-session-id": sessionId } }),
    );
    expect(res.headers.get("set-cookie")).toContain("dbsc-challenge=");
  });

  it("returns a 404 Response for a route it does not own", async () => {
    const { handle } = makeKit();
    const res = await handle(new Request(`${SCHEME}/api/profile`));
    expect(res.status).toBe(404);
  });

  it("does not own bound routes when bound: false", async () => {
    const { handle } = makeKit({ bound: false });
    const challenge = await handle(new Request(`${SCHEME}/dbsc-bound/challenge`));
    expect(challenge.status).toBe(404);
    const state = await handle(new Request(`${SCHEME}/dbsc-bound/state`));
    expect(await state.json()).toEqual({ phase: "unbound", sessionId: null });
  });
});

describe("electron adapter — guards via the shimmed request", () => {
  it("requireProof 403s a tier:none request", async () => {
    const storage = new MemoryStorage();
    const handler = dbsc({ storage, secure: false });
    const guard = requireProof();
    const req = shimReq(new Request(`${SCHEME}/api/secure`));
    const { res, toResponse } = shimRes();
    await handler(req, res); // resolves + attaches the session (tier none)
    const passed = await guard(req, res);
    expect(passed).toBe(false);
    expect(toResponse().status).toBe(403);
  });
});

// Mirrors the bridge's request/response shim for isolated guard testing.
function shimReq(request: Request): IncomingMessage {
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
  const u = new URL(request.url);
  if (!headers["host"]) headers["host"] = u.host;
  return {
    method: request.method,
    url: u.pathname + u.search,
    headers,
    socket: { remoteAddress: "127.0.0.1", encrypted: u.protocol === "https:" },
    async *[Symbol.asyncIterator]() {},
  } as unknown as IncomingMessage;
}

function shimRes(): { res: ServerResponse; toResponse: () => Response } {
  let statusCode = 200;
  const headers = new Map<string, string | string[]>();
  const chunks: Uint8Array[] = [];
  const res = {
    get statusCode() {
      return statusCode;
    },
    set statusCode(v: number) {
      statusCode = v;
    },
    setHeader(n: string, v: string | number | readonly string[]) {
      headers.set(n.toLowerCase(), Array.isArray(v) ? v.map(String) : String(v));
    },
    getHeader(n: string) {
      return headers.get(n.toLowerCase());
    },
    end(c?: string | Uint8Array) {
      if (c !== undefined) chunks.push(typeof c === "string" ? new TextEncoder().encode(c) : c);
    },
  };
  const toResponse = () => {
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const body = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      body.set(c, off);
      off += c.length;
    }
    return new Response(total ? body : null, { status: statusCode });
  };
  return { res: res as unknown as ServerResponse, toResponse };
}
