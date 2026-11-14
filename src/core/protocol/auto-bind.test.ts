import { beforeAll, describe, expect, it } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import { Hono } from "hono";
import { NextRequest } from "next/server.js";
import { dbsc as expressDbsc } from "../../express/index.js";
import { dbsc as fastifyDbsc } from "../../fastify/index.js";
import { dbsc as honoDbsc } from "../../hono/index.js";
import { dbsc as nodeDbsc } from "../../node/index.js";
import { createDbscMiddleware } from "../../nextjs/index.js";
import { autoBindAllowed } from "./start-binding.js";
import { MemoryStorage } from "../../storage/memory/index.js";

// Fastify loads most of its internals on the first ready(). Pay that once
// here so it doesn't count against the first test's 5s timeout.
beforeAll(async () => {
  const app = Fastify();
  await app.register((await import("@fastify/cookie")).default);
  await app.ready();
  await app.inject({ url: "/" });
  await app.close();
}, 30_000);

// The app identifies the user from its own cookie ("app"); autoBind maps it
// to the DBSC session id. A thief holding that cookie sends it without any
// DBSC cookie. An existing binding must survive that request.

const SID = "app-session-1";
const autoBind = (cookieHeader: string | null | undefined) =>
  cookieHeader?.includes(`app=${SID}`) ? { sessionId: SID, userId: "victim" } : null;

async function boundStorage(): Promise<MemoryStorage> {
  const storage = new MemoryStorage();
  const now = Date.now();
  await storage.setSession({ id: SID, userId: "victim", tier: "bound", createdAt: now, expiresAt: now + 3_600_000, lastRefreshAt: now });
  await storage.setBoundKey({ sessionId: SID, kind: "bound", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, createdAt: now, algorithm: "ES256" });
  return storage;
}

async function expectUntouched(storage: MemoryStorage, registrationHeader: string | null | undefined) {
  expect(registrationHeader ?? null).toBeNull();
  expect(await storage.getBoundKey(SID, "bound")).not.toBeNull();
  expect((await storage.getSession(SID))?.tier).toBe("bound");
}

async function listen(server: http.Server): Promise<string> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("autoBindAllowed", () => {
  it("allows only a session id with no row", async () => {
    const storage = await boundStorage();
    expect(await autoBindAllowed(storage, SID)).toBe(false);
    expect(await autoBindAllowed(storage, "fresh")).toBe(true);
  });
});

describe("autoBind never restarts an existing binding", () => {
  it("express", async () => {
    const storage = await boundStorage();
    const app = express();
    app.use(expressDbsc({ storage, secure: false, autoBind: (req) => autoBind(req.headers.cookie) }));
    app.get("/", (_req, res) => res.send("ok"));
    const server = http.createServer(app);
    const base = await listen(server);
    const res = await fetch(`${base}/`, { headers: { cookie: `app=${SID}` } });
    server.close();
    await expectUntouched(storage, res.headers.get("secure-session-registration"));
  });

  it("fastify", async () => {
    const storage = await boundStorage();
    const app = Fastify();
    await app.register(fastifyCookie);
    await app.register(fastifyDbsc, { storage, secure: false, autoBind: (req) => autoBind(req.headers.cookie) });
    app.get("/", async () => "ok");
    const res = await app.inject({ url: "/", headers: { cookie: `app=${SID}` } });
    await app.close();
    await expectUntouched(storage, res.headers["secure-session-registration"] as string | undefined);
  });

  it("hono", async () => {
    const storage = await boundStorage();
    const app = new Hono();
    app.use(honoDbsc({ storage, secure: false, autoBind: (c) => autoBind(c.req.header("cookie")) }));
    app.get("/", (c) => c.text("ok"));
    const res = await app.request("/", { headers: { cookie: `app=${SID}` } });
    await expectUntouched(storage, res.headers.get("secure-session-registration"));
  });

  it("node (and Koa / Electron, which use it)", async () => {
    const storage = await boundStorage();
    const handler = nodeDbsc({ storage, secure: false, autoBind: (req) => autoBind(req.headers.cookie) });
    const server = http.createServer(async (req, res) => {
      if (await handler(req, res)) return;
      res.end("ok");
    });
    const base = await listen(server);
    const res = await fetch(`${base}/`, { headers: { cookie: `app=${SID}` } });
    server.close();
    await expectUntouched(storage, res.headers.get("secure-session-registration"));
  });

  it("next.js", async () => {
    const storage = await boundStorage();
    const mw = createDbscMiddleware({ storage, secure: false, autoBind: (req) => autoBind(req.headers.get("cookie")) });
    const res = await mw(new NextRequest("http://localhost/", { headers: { cookie: `app=${SID}` } }));
    await expectUntouched(storage, res.headers.get("secure-session-registration"));
  });

  it("still binds a session that has no binding yet", async () => {
    const storage = new MemoryStorage();
    const app = express();
    app.use(expressDbsc({ storage, secure: false, autoBind: (req) => autoBind(req.headers.cookie) }));
    app.get("/", (_req, res) => res.send("ok"));
    const server = http.createServer(app);
    const base = await listen(server);
    const res = await fetch(`${base}/`, { headers: { cookie: `app=${SID}` } });
    server.close();
    expect(res.headers.get("secure-session-registration")).toBeTruthy();
    expect((await storage.getSession(SID))?.userId).toBe("victim");
  });
});
