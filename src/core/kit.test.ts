import { afterEach, describe, expect, it, vi } from "vitest";
import {
  defaultSecure,
  withKitBinding,
  checkKitSetup,
  clientScriptTag,
  resetWarnings,
} from "./kit.js";
import { MemoryStorage } from "../storage/memory/index.js";

const ORIGINAL_ENV = process.env.NODE_ENV;

afterEach(() => {
  process.env.NODE_ENV = ORIGINAL_ENV;
  resetWarnings();
  vi.restoreAllMocks();
});

describe("defaultSecure", () => {
  it("is false only for NODE_ENV=development", () => {
    process.env.NODE_ENV = "development";
    expect(defaultSecure()).toBe(false);
    for (const env of ["production", "test", "staging"]) {
      process.env.NODE_ENV = env;
      expect(defaultSecure()).toBe(true);
    }
    delete process.env.NODE_ENV;
    expect(defaultSecure()).toBe(true);
  });
});

describe("withKitBinding", () => {
  const kitHook = () => "kit";
  const ownHook = () => "own";

  it("fills in the kit hooks when the guard has none", () => {
    const merged = withKitBinding({ expectSessionId: kitHook }, { timestampWindowMs: 5 });
    expect(merged.expectSessionId).toBe(kitHook);
    expect(merged.timestampWindowMs).toBe(5);
  });

  it("keeps a guard's own hook and does not mix in the kit's", () => {
    const merged = withKitBinding({ expectSessionId: kitHook }, { expectUserId: ownHook });
    expect(merged.expectUserId).toBe(ownHook);
    expect(merged.expectSessionId).toBeUndefined();
  });
});

describe("checkKitSetup", () => {
  it("warns once in production about memory storage and a missing binding", () => {
    process.env.NODE_ENV = "production";
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    checkKitSetup({ storage: new MemoryStorage() });
    checkKitSetup({ storage: new MemoryStorage() });
    expect(warn).toHaveBeenCalledTimes(2);
    expect(String(warn.mock.calls[0]?.[0])).toContain("MemoryStorage");
    expect(String(warn.mock.calls[1]?.[0])).toContain("expectSessionId");
  });

  it("stays quiet outside production and when configured", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env.NODE_ENV = "development";
    checkKitSetup({ storage: new MemoryStorage() });
    process.env.NODE_ENV = "production";
    const persistent = Object.assign(new MemoryStorage(), { ephemeral: false });
    checkKitSetup({ storage: persistent, expectUserId: () => "u" });
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("clientScriptTag", () => {
  it("builds the module tag with encoded options", () => {
    expect(clientScriptTag("/dbsc-client")).toBe(
      '<script type="module" src="/dbsc-client/auto.js"></script>',
    );
    expect(clientScriptTag("/c/", { sign: ["/api/", "/me"], signQuery: true })).toBe(
      '<script type="module" src="/c/auto.js?sign=%2Fapi%2F%2C%2Fme&amp;signQuery=1"></script>',
    );
  });
});
