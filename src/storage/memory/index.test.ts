import { describe, expect, it } from "vitest";
import { MemoryStorage } from "./index.js";

describe("MemoryStorage — multi-kind bound keys", () => {
  const native = {
    sessionId: "s1",
    kind: "native" as const,
    jwk: { kty: "EC", crv: "P-256", x: "n", y: "n" },
    algorithm: "ES256" as const,
    createdAt: 1,
  };
  const bound = {
    sessionId: "s1",
    kind: "bound" as const,
    jwk: { kty: "EC", crv: "P-256", x: "b", y: "b" },
    algorithm: "ES256" as const,
    createdAt: 2,
  };

  it("stores two keys for one session under separate kinds", async () => {
    const s = new MemoryStorage();
    await s.setBoundKey(native);
    await s.setBoundKey(bound);
    expect((await s.getBoundKey("s1", "native"))?.jwk.x).toBe("n");
    expect((await s.getBoundKey("s1", "bound"))?.jwk.x).toBe("b");
  });

  it("kind-less get prefers native, falls back to bound", async () => {
    const s = new MemoryStorage();
    await s.setBoundKey(bound);
    expect((await s.getBoundKey("s1"))?.kind).toBe("bound");
    await s.setBoundKey(native);
    expect((await s.getBoundKey("s1"))?.kind).toBe("native");
  });

  it("deleteBoundKey with no kind removes both rows", async () => {
    const s = new MemoryStorage();
    await s.setBoundKey(native);
    await s.setBoundKey(bound);
    await s.deleteBoundKey("s1");
    expect(await s.getBoundKey("s1", "native")).toBeNull();
    expect(await s.getBoundKey("s1", "bound")).toBeNull();
  });

  it("deleteBoundKey with a kind removes only that row", async () => {
    const s = new MemoryStorage();
    await s.setBoundKey(native);
    await s.setBoundKey(bound);
    await s.deleteBoundKey("s1", "bound");
    expect(await s.getBoundKey("s1", "native")).not.toBeNull();
    expect(await s.getBoundKey("s1", "bound")).toBeNull();
  });
});
