import { describe, expect, it } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { runDoctor, describeFetchError } from "./doctor.js";
import { detectFramework, detectStorage, snippet, usesPassport } from "./init.js";
import { createDbsc } from "../express/index.js";
import { MemoryStorage } from "../storage/memory/index.js";

async function serve(app: express.Express) {
  const server = await new Promise<Server>((r) => {
    const s = app.listen(0, () => r(s));
  });
  return { base: `http://localhost:${(server.address() as AddressInfo).port}`, close: () => server.close() };
}

describe("doctor", () => {
  it("passes a correctly mounted app and catches an unguarded route", async () => {
    const storage = new MemoryStorage();
    const kit = createDbsc({ storage, secure: false });
    const app = express();
    kit.install(app);
    app.get("/api/guarded", kit.requireProof(), (_req, res) => res.json({ ok: true }));
    app.get("/api/open", (_req, res) => res.json({ ok: true }));
    const srv = await serve(app);
    const good = await runDoctor(srv.base, { cookie: "dbsc-session=nope", guard: "/api/guarded" });
    const bad = await runDoctor(srv.base, { cookie: "dbsc-session=nope", guard: "/api/open" });
    srv.close();
    const byTitle = (r: typeof good) => Object.fromEntries(r.map((x) => [x.title, x.status]));
    // "Client SDK" is not asserted: run from src/, the kit serves .ts files.
    expect(byTitle(good)).toMatchObject({
      "Protocol routes": "ok",
      "Refresh route": "ok",
      "Stolen-cookie replay": "ok",
    });
    expect(byTitle(bad)["Stolen-cookie replay"]).toBe("fail");
  });

  it("fails a site without the protocol routes and a non-https remote", async () => {
    const app = express();
    const srv = await serve(app);
    const local = await runDoctor(srv.base);
    srv.close();
    expect(local.find((r) => r.title === "Protocol routes")?.status).toBe("fail");
    const remote = await runDoctor("http://example.invalid", { fetch: (async () => { throw new Error("offline"); }) as typeof fetch });
    expect(remote.find((r) => r.title === "HTTPS")?.status).toBe("fail");
  });
});

describe("doctor errors", () => {
  it("names the cause of a failed request and explains timeouts", () => {
    const refused = Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } });
    expect(describeFetchError(refused, 30_000).message).toBe("fetch failed (ECONNREFUSED)");
    const timeout = Object.assign(new Error("timed out"), { name: "TimeoutError" });
    expect(describeFetchError(timeout, 30_000).message).toMatch(/30s.*--timeout/);
  });

  it("warns instead of failing when the app's own login check answers 401", async () => {
    const app = express();
    const kit = createDbsc({ storage: new MemoryStorage(), secure: false });
    kit.install(app);
    app.get("/api/me", (_req, res) => res.status(401).json({ error: "not logged in" }));
    const srv = await serve(app);
    const results = await runDoctor(srv.base, { cookie: "x=1", guard: "/api/me" });
    srv.close();
    expect(results.find((r) => r.title === "Stolen-cookie replay")?.status).toBe("warn");
  });
});

describe("init", () => {
  it("detects the framework and storage, most specific first", () => {
    expect(detectFramework({ dependencies: { express: "5", "better-auth": "1" } })).toBe("better-auth");
    expect(detectFramework({ dependencies: { next: "16", react: "19" } })).toBe("nextjs");
    expect(detectFramework({ dependencies: { express: "5" } })).toBe("express");
    expect(detectFramework({})).toBe("node");
    expect(detectStorage({ dependencies: { ioredis: "6" } })).toBe("redis");
    expect(usesPassport({ dependencies: { passport: "0.7", "express-session": "1" } })).toBe(true);
  });

  it("uses the Passport preset when the project has it", () => {
    expect(snippet("express", "memory", true)).toContain("passportSession()");
    expect(snippet("express", "redis")).toContain("RedisStorage");
  });
});
