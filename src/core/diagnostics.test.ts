import { afterEach, describe, expect, it } from "vitest";
import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { rejectionHint, debugEnabled, NO_BINDING } from "./diagnostics.js";
import { ErrorCodes } from "./errors.js";
import { createDbsc } from "../express/index.js";
import { MemoryStorage } from "../storage/memory/index.js";

const ENV = { ...process.env };
afterEach(() => {
  process.env = { ...ENV };
});

describe("rejectionHint", () => {
  it("has a hint for every code a guard returns", () => {
    for (const code of [NO_BINDING, ErrorCodes.MISSING_PROOF, ErrorCodes.MALFORMED_PROOF, ErrorCodes.SIGNATURE_INVALID, ErrorCodes.PROOF_REPLAY, ErrorCodes.KEY_NOT_FOUND_BOUND, ErrorCodes.SESSION_MISMATCH]) {
      expect(rejectionHint(code)).toBeTruthy();
    }
  });

  it("prefers the message-specific hint", () => {
    expect(rejectionHint(ErrorCodes.SIGNATURE_INVALID, "proof timestamp outside window")).toMatch(/clock/);
    expect(rejectionHint(ErrorCodes.SIGNATURE_INVALID, "body hash mismatch")).toMatch(/body/);
  });
});

describe("debugEnabled", () => {
  it("follows DBSC_DEBUG first, then NODE_ENV=development", () => {
    process.env.NODE_ENV = "development";
    delete process.env.DBSC_DEBUG;
    expect(debugEnabled()).toBe(true);
    process.env.DBSC_DEBUG = "0";
    expect(debugEnabled()).toBe(false);
    process.env.NODE_ENV = "production";
    process.env.DBSC_DEBUG = "1";
    expect(debugEnabled()).toBe(true);
  });
});

describe("guard responses", () => {
  it("carry a code and hint, and X-Dbsc-Debug when debugging", async () => {
    process.env.DBSC_DEBUG = "1";
    const kit = createDbsc({ storage: new MemoryStorage(), secure: false });
    const app = express();
    kit.install(app);
    app.get("/x", kit.requireProof(), (_req, res) => res.json({ ok: true }));
    const server = await new Promise<Server>((r) => {
      const s = app.listen(0, () => r(s));
    });
    const res = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/x`);
    server.close();
    const body = (await res.json()) as { code: string; hint: string };
    expect(res.status).toBe(403);
    expect(body.code).toBe(NO_BINDING);
    expect(body.hint).toMatch(/auto\.js/);
    expect(res.headers.get("x-dbsc-debug")).toMatch(/^NO_BINDING: /);
  });
});
