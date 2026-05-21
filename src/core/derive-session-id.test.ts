import { describe, it, expect } from "vitest";
import { deriveSessionId } from "./derive-session-id.js";

describe("deriveSessionId", () => {
  it("is deterministic for the same input", async () => {
    const a = await deriveSessionId({ userId: "user-1" });
    const b = await deriveSessionId({ userId: "user-1" });
    expect(a).toBe(b);
  });

  it("produces different ids for different users", async () => {
    const a = await deriveSessionId({ userId: "user-1" });
    const b = await deriveSessionId({ userId: "user-2" });
    expect(a).not.toBe(b);
  });

  it("scopes by deviceHint — same user, two devices, two ids", async () => {
    const phone = await deriveSessionId({ userId: "user-1", deviceHint: "phone" });
    const laptop = await deriveSessionId({ userId: "user-1", deviceHint: "laptop" });
    expect(phone).not.toBe(laptop);
  });

  it("scopes by namespace", async () => {
    const def = await deriveSessionId({ userId: "user-1" });
    const impersonation = await deriveSessionId({ userId: "user-1", namespace: "impersonation" });
    expect(def).not.toBe(impersonation);
  });

  it("treats omitted deviceHint and namespace as the documented defaults", async () => {
    const omitted = await deriveSessionId({ userId: "user-1" });
    const explicit = await deriveSessionId({ userId: "user-1", deviceHint: "", namespace: "default" });
    expect(omitted).toBe(explicit);
  });

  it("rejects an empty userId", async () => {
    await expect(deriveSessionId({ userId: "" })).rejects.toThrow(/userId is required/);
  });

  it("returns a url-safe string with no padding", async () => {
    const id = await deriveSessionId({ userId: "user-1" });
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(id).not.toContain("=");
  });
});
