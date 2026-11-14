import { describe, expect, it } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { runDoctor } from "./doctor.js";
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
