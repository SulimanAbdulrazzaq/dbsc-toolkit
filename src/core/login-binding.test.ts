import { describe, expect, it } from "vitest";
import { shouldBindLogin, resolveLoginBinding } from "./login-binding.js";
import { MemoryStorage } from "../storage/memory/index.js";

const WINDOW = 5 * 60 * 1000;

async function row(storage: MemoryStorage, id: string, createdAt: number) {
  await storage.setSession({ id, userId: "u", tier: "bound", createdAt, expiresAt: createdAt + 3_600_000, lastRefreshAt: createdAt });
}

describe("shouldBindLogin", () => {
  it("binds a fresh login with no binding yet", async () => {
    const storage = new MemoryStorage();
    const now = Date.now();
    expect(await shouldBindLogin(storage, { userId: "u", loginAt: now - 1000, sessionId: "s", currentSessionId: null })).toBe(true);
  });

  it("leaves a binding that started after the login alone", async () => {
    const storage = new MemoryStorage();
    const now = Date.now();
    await row(storage, "s", now - 500);
    expect(await shouldBindLogin(storage, { userId: "u", loginAt: now - 1000, sessionId: "s", currentSessionId: null })).toBe(false);
  });

  it("replaces a binding left over from an earlier login on the same id", async () => {
    const storage = new MemoryStorage();
    const now = Date.now();
    await row(storage, "s", now - 60 * 60 * 1000);
    expect(await shouldBindLogin(storage, { userId: "u", loginAt: now - 1000, sessionId: "s", currentSessionId: null })).toBe(true);
  });

  it("never binds once the login is older than the window", async () => {
    const storage = new MemoryStorage();
    const now = Date.now();
    expect(await shouldBindLogin(storage, { userId: "u", loginAt: now - WINDOW - 1, sessionId: "s", currentSessionId: null })).toBe(false);
  });

  it("skips when the request already carries this session", async () => {
    const storage = new MemoryStorage();
    expect(await shouldBindLogin(storage, { userId: "u", loginAt: Date.now(), sessionId: "s", currentSessionId: "s" })).toBe(false);
  });
});

describe("resolveLoginBinding", () => {
  it("returns nothing for anonymous requests or unknown login time", async () => {
    const storage = new MemoryStorage();
    const base = { storage, deriveSessionId: async () => "d", currentSessionId: null };
    expect(await resolveLoginBinding({ userId: () => null, loginAt: () => Date.now() }, {}, base)).toBeNull();
    expect(await resolveLoginBinding({ userId: () => "u", loginAt: () => null }, {}, base)).toBeNull();
  });

  it("uses expectSessionId when set, the derived id otherwise", async () => {
    const storage = new MemoryStorage();
    const cfg = { userId: () => "u", loginAt: () => new Date() };
    const derived = await resolveLoginBinding(cfg, {}, { storage, deriveSessionId: async () => "d", currentSessionId: null });
    expect(derived).toEqual({ sessionId: "d", userId: "u" });
    const explicit = await resolveLoginBinding(cfg, {}, {
      storage,
      expectSessionId: () => "app-session",
      deriveSessionId: async () => "d",
      currentSessionId: null,
    });
    expect(explicit).toEqual({ sessionId: "app-session", userId: "u" });
  });
});
