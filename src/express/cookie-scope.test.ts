import { describe, it, expect } from "vitest";
import express from "express";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { dbsc, bindSession } from "./index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

/**
 * v2.9 cookieScope: "site" puts the binding on a registrable apex via the
 * __Secure- prefix + a Domain attribute. The host-scope default keeps the
 * __Host- prefix and emits no Domain. These tests pin the wire format that
 * Chromium reads back on every refresh.
 */

function startApp(opts: Parameters<typeof dbsc>[0]) {
  const app = express();
  app.post("/login", async (req, res) => {
    const optsAny = opts as { secure?: boolean; cookieScope?: "host" | "site"; cookieDomain?: string };
    await bindSession(res, "sess-1", opts.storage, {
      userId: "alice",
      secure: optsAny.secure ?? true,
      ...(optsAny.cookieScope !== undefined && { cookieScope: optsAny.cookieScope }),
      ...(optsAny.cookieDomain !== undefined && { cookieDomain: optsAny.cookieDomain }),
    });
    res.json({ ok: true });
  });
  app.use(dbsc(opts));
  const server = createServer(app);
  return new Promise<{ url: string; close: () => Promise<void> }>((resolve) => {
    server.listen(0, () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

describe("cookieScope: 'host' (default)", () => {
  it("uses __Host- prefix and no Domain attribute", async () => {
    const storage = new MemoryStorage();
    const { url, close } = await startApp({ storage, secure: true });
    try {
      const res = await fetch(`${url}/login`, { method: "POST" });
      const cookies = res.headers.getSetCookie();
      const regCookie = cookies.find((c) => c.startsWith("__Host-dbsc-reg="));
      const challengeCookie = cookies.find((c) => c.startsWith("__Host-dbsc-challenge="));
      expect(regCookie).toBeDefined();
      expect(challengeCookie).toBeDefined();
      // __Host- forbids Domain
      expect(regCookie).not.toMatch(/Domain=/i);
      expect(challengeCookie).not.toMatch(/Domain=/i);
    } finally {
      await close();
    }
  });
});

describe("cookieScope: 'site'", () => {
  it("uses __Secure- prefix and emits Domain", async () => {
    const storage = new MemoryStorage();
    const { url, close } = await startApp({
      storage,
      secure: true,
      cookieScope: "site",
      cookieDomain: "example.com",
    });
    try {
      const res = await fetch(`${url}/login`, { method: "POST" });
      const cookies = res.headers.getSetCookie();
      const regCookie = cookies.find((c) => c.startsWith("__Secure-dbsc-reg="));
      const challengeCookie = cookies.find((c) => c.startsWith("__Secure-dbsc-challenge="));
      expect(regCookie).toBeDefined();
      expect(regCookie).toMatch(/Domain=example\.com/);
      expect(challengeCookie).toBeDefined();
      expect(challengeCookie).toMatch(/Domain=example\.com/);
      // __Host- prefix must be absent
      expect(cookies.some((c) => c.startsWith("__Host-"))).toBe(false);
    } finally {
      await close();
    }
  });

  it("throws at construction when cookieDomain is missing", () => {
    const storage = new MemoryStorage();
    expect(() =>
      dbsc({ storage, secure: true, cookieScope: "site" } as Parameters<typeof dbsc>[0]),
    ).toThrow(/cookieDomain/);
  });

  it("throws at construction when secure is false", () => {
    const storage = new MemoryStorage();
    expect(() =>
      dbsc({
        storage,
        secure: false,
        cookieScope: "site",
        cookieDomain: "example.com",
      } as Parameters<typeof dbsc>[0]),
    ).toThrow(/secure: true/);
  });
});
