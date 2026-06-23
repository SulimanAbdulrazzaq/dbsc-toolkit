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

  // v2.14: native-only no longer relaxes — a proofless dbsc request runs the
  // freshProof handshake, setting Secure-Session-Challenge + cookie and throwing
  // a ForbiddenException (Nest emits the 403, keeping the pre-set headers).
  it("demands a native proof (challenge + 403) for a native dbsc session", async () => {
    const guard = new DbscGuard();
    const headers: Record<string, string> = {};
    const cookies: Array<[string, string]> = [];
    const res = {
      locals: {
        dbsc: { sessionId: "s1", tier: "dbsc", skipped: [] },
        [DBSC_INTERNAL]: { storage: new MemoryStorage(), secure: false, boundEnabled: false },
      },
      setHeader(name: string, value: string) { headers[name] = value; },
      cookie(name: string, value: string) { cookies.push([name, value]); },
    };
    const req = { headers: {}, method: "GET", path: "/account", cookies: {} };
    await expect(guard.canActivate(execCtx(req, res))).rejects.toBeInstanceOf(ForbiddenException);
    expect(headers["Secure-Session-Challenge"]).toBeTruthy();
    expect(cookies.some(([n]) => n.endsWith("dbsc-challenge"))).toBe(true);
  });

  it("relaxes a native dbsc session with freshProof:false (escape hatch)", async () => {
    const { createDbscGuard } = await import("./index.js");
    const Guard = createDbscGuard({ freshProof: false });
    const guard = new Guard();
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
