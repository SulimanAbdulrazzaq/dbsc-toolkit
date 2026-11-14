import { beforeAll, describe, expect, it } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import Koa from "koa";
import Fastify from "fastify";
import { createDbsc as createNodeDbsc } from "./index.js";
import { createDbsc as createKoaDbsc } from "../koa/index.js";
import { createDbsc as createFastifyDbsc } from "../fastify/index.js";
import { readClientAsset } from "./client-assets.js";
import { MemoryStorage } from "../storage/memory/index.js";

// Fastify loads most of its internals on the first ready(). Pay that once
// here so it doesn't count against the first test's 5s timeout.
beforeAll(async () => {
  const app = Fastify();
  await app.register((await import("@fastify/cookie")).default);
  await app.ready();
  await app.inject({ url: "/" });
  await app.close();
}, 30_000);

// Run from src/, the SDK directory holds .ts files; index.test.ts stands in
// for a real .js asset name in the traversal checks below.
describe("readClientAsset", () => {
  it("refuses anything that is not a plain .js name under the mount", async () => {
    expect(await readClientAsset("/other/auto.js", "/dbsc-client")).toBeNull();
    expect(await readClientAsset("/dbsc-client/../index.js", "/dbsc-client")).toBeNull();
    expect(await readClientAsset("/dbsc-client/%2e%2e/index.js", "/dbsc-client")).toBeNull();
    expect(await readClientAsset("/dbsc-client/keystore.ts", "/dbsc-client")).toBeNull();
    expect(await readClientAsset("/dbsc-client/sub/dir.js", "/dbsc-client")).toBeNull();
  });
});

async function listen(server: http.Server): Promise<string> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("JWT binding on koa and node", () => {
  it("koa bind() derives a per-device id and sets the device cookie", async () => {
    const storage = new MemoryStorage();
    const kit = createKoaDbsc({ storage, secure: false });
    const app = new Koa();
    kit.install(app);
    app.use(async (ctx) => {
      ctx.body = { id: await kit.bind(ctx, { userId: "u1" }) };
    });
    const server = http.createServer(app.callback());
    const base = await listen(server);
    const res = await fetch(`${base}/login`, { method: "POST" });
    server.close();
    const { id } = (await res.json()) as { id: string };
    expect(res.headers.getSetCookie().some((c) => c.startsWith("dbsc-device="))).toBe(true);
    expect((await storage.getSession(id))?.userId).toBe("u1");
  });

  it("koa bindOnLogin works without expectSessionId", async () => {
    const storage = new MemoryStorage();
    const kit = createKoaDbsc({
      storage,
      secure: false,
      bindOnLogin: { userId: (ctx) => ctx.get("x-user") || null, loginAt: () => Date.now() },
    });
    const app = new Koa();
    kit.install(app);
    app.use((ctx) => {
      ctx.body = "ok";
    });
    const server = http.createServer(app.callback());
    const base = await listen(server);
    const res = await fetch(`${base}/`, { headers: { "x-user": "u2" } });
    server.close();
    expect(res.headers.get("secure-session-registration")).toBeTruthy();
  });

  it("node bind() with req derives the id from the device cookie", async () => {
    const storage = new MemoryStorage();
    const kit = createNodeDbsc({ storage, secure: false });
    const handler = kit.handler();
    const ids: string[] = [];
    const server = http.createServer(async (req, res) => {
      if (await handler(req, res)) return;
      ids.push(await kit.bind(res, { userId: "u3", req }));
      res.end("ok");
    });
    const base = await listen(server);
    const first = await fetch(`${base}/login`, { method: "POST" });
    const device = first.headers.getSetCookie().find((c) => c.startsWith("dbsc-device="))!.split(";")[0]!;
    await fetch(`${base}/login`, { method: "POST", headers: { cookie: device } });
    await fetch(`${base}/login`, { method: "POST" });
    server.close();
    expect(ids[0]).toBe(ids[1]);
    expect(ids[2]).not.toBe(ids[0]);
  });
});

describe("client SDK serving", () => {
  it("fastify and node kits answer under /dbsc-client and 404 elsewhere", async () => {
    const fastifyKit = createFastifyDbsc({ storage: new MemoryStorage(), secure: false });
    const app = Fastify();
    await fastifyKit.install(app);
    const missing = await app.inject({ url: "/dbsc-client/nope.js" });
    await app.close();
    expect(missing.statusCode).toBe(404);

    const nodeKit = createNodeDbsc({ storage: new MemoryStorage(), secure: false });
    const handler = nodeKit.handler();
    const server = http.createServer(async (req, res) => {
      if (await handler(req, res)) return;
      res.statusCode = 404;
      res.end();
    });
    const base = await listen(server);
    const res = await fetch(`${base}/dbsc-client/../../package.json`);
    server.close();
    expect(res.status).toBe(404);
  });
});
