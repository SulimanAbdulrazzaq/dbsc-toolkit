import { describe, it, expect } from "vitest";
import { ForbiddenException, type ExecutionContext } from "@nestjs/common";
import { DbscModule, DbscGuard, DbscService, DBSC_OPTIONS } from "./index.js";
import { DBSC_INTERNAL } from "../express/index.js";
import { MemoryStorage } from "../core/testing/memory-storage-stub.js";

function execCtx(req: unknown, res: unknown): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => req, getResponse: () => res }),
  } as unknown as ExecutionContext;
}

describe("DbscModule.forRoot", () => {
  it("returns a global dynamic module exposing the options token and service", () => {
    const storage = new MemoryStorage();
    const mod = DbscModule.forRoot({ storage });
    expect(mod.module).toBe(DbscModule);
    expect(mod.global).toBe(true);
    expect(mod.exports).toContain(DBSC_OPTIONS);
    expect(mod.exports).toContain(DbscService);
  });
});

describe("DbscGuard", () => {
  it("rejects a request with no binding (tier none)", async () => {
    const guard = new DbscGuard();
    const res = { locals: {} };
    await expect(guard.canActivate(execCtx({ headers: {} }, res))).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("auto-relaxes a native dbsc session when the polyfill is disabled", async () => {
    const guard = new DbscGuard();
    const res = {
      locals: {
        dbsc: { sessionId: "s1", tier: "dbsc", skipped: [] },
        [DBSC_INTERNAL]: { storage: new MemoryStorage(), secure: false, boundEnabled: false },
      },
    };
    const req = { headers: {}, method: "GET", path: "/account" };
    await expect(guard.canActivate(execCtx(req, res))).resolves.toBe(true);
  });
});
