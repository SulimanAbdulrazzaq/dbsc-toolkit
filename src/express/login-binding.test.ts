import { describe, expect, it } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createDbsc, passportSession } from "./index.js";
import { MemoryStorage } from "../storage/memory/index.js";

// A stand-in for express-session + passport.session(): the "sid" cookie names
// a server-side session; a session that has logged in carries a user.
function fakeSession(sessions: Map<string, Record<string, unknown>>): express.RequestHandler {
  return (req, _res, next) => {
    const sid = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
    const data = sid ? sessions.get(sid) : undefined;
    const r = req as unknown as Record<string, unknown>;
    if (sid && data) {
      r.sessionID = sid;
      r.session = data;
      r.user = data.user;
    }
    next();
  };
}

async function serve(app: express.Express) {
  const server = await new Promise<Server>((r) => {
    const s = app.listen(0, () => r(s));
  });
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => server.close() };
}

function setup() {
  const storage = new MemoryStorage();
  const sessions = new Map<string, Record<string, unknown>>();
  const kit = createDbsc({ storage, secure: false, ...passportSession() });
  const app = express();
  app.use(fakeSession(sessions));
  kit.install(app);
  app.use(kit.protect(["/api/*"], { except: ["/api/public"] }));
  app.get("/", (_req, res) => res.send("home"));
  app.get("/api/public", (_req, res) => res.json({ open: true }));
  app.get("/api/me", (_req, res) => res.json({ ok: true }));
  return { storage, sessions, kit, app };
}

describe("express bindOnLogin with the Passport preset", () => {
  it("starts the binding on the first request after login, once", async () => {
    const { storage, sessions, app } = setup();
    sessions.set("sid-1", { user: { id: 42 } });
    const srv = await serve(app);
    const first = await fetch(`${srv.base}/`, { headers: { cookie: "sid=sid-1" } });
    const second = await fetch(`${srv.base}/`, { headers: { cookie: "sid=sid-1" } });
    srv.close();
    expect(first.headers.get("secure-session-registration")).toBeTruthy();
    expect(second.headers.get("secure-session-registration")).toBeNull();
    const row = await storage.getSession("sid-1");
    expect(row?.userId).toBe("42");
    expect(typeof sessions.get("sid-1")?.dbscLoginAt).toBe("number");
  });

  it("does not reset an existing binding for a login it has already seen", async () => {
    const { storage, sessions, app } = setup();
    const loginAt = Date.now() - 1000;
    sessions.set("sid-2", { user: { id: 1 }, dbscLoginAt: loginAt });
    await storage.setSession({ id: "sid-2", userId: "1", tier: "bound", createdAt: loginAt + 10, expiresAt: Date.now() + 3_600_000, lastRefreshAt: Date.now() });
    await storage.setBoundKey({ sessionId: "sid-2", kind: "bound", jwk: { kty: "EC", crv: "P-256", x: "x", y: "y" }, createdAt: loginAt + 20, algorithm: "ES256" });
    const srv = await serve(app);
    const res = await fetch(`${srv.base}/`, { headers: { cookie: "sid=sid-2" } });
    srv.close();
    expect(res.headers.get("secure-session-registration")).toBeNull();
    expect(await storage.getBoundKey("sid-2", "bound")).not.toBeNull();
  });

  it("skips anonymous requests and logins older than the window", async () => {
    const { storage, sessions, app } = setup();
    sessions.set("sid-3", { user: { id: 7 }, dbscLoginAt: Date.now() - 60 * 60 * 1000 });
    const srv = await serve(app);
    const anon = await fetch(`${srv.base}/`);
    const stale = await fetch(`${srv.base}/`, { headers: { cookie: "sid=sid-3" } });
    srv.close();
    expect(anon.headers.get("secure-session-registration")).toBeNull();
    expect(stale.headers.get("secure-session-registration")).toBeNull();
    expect(await storage.getSession("sid-3")).toBeNull();
  });
});

describe("express protect()", () => {
  it("guards matching paths, leaves the rest and the exceptions open", async () => {
    const { app } = setup();
    const srv = await serve(app);
    const guarded = await fetch(`${srv.base}/api/me`);
    const open = await fetch(`${srv.base}/api/public`);
    const home = await fetch(`${srv.base}/`);
    srv.close();
    expect(guarded.status).toBe(403);
    expect(open.status).toBe(200);
    expect(home.status).toBe(200);
  });

  it("makes clientScript() sign the protected paths", () => {
    const { kit } = setup();
    expect(kit.clientScript()).toContain("sign=%2Fapi%2F");
  });
});
