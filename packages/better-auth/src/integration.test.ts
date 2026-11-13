import { describe, it, expect } from "vitest";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { dbsc } from "./index.js";

const BASE = "http://localhost:3000";

function makeAuth() {
  const db: Record<string, unknown[]> = {
    user: [],
    session: [],
    account: [],
    verification: [],
    dbscSession: [],
    dbscBoundKey: [],
  };
  const auth = betterAuth({
    baseURL: BASE,
    secret: "test-secret-test-secret-test-secret-123",
    database: memoryAdapter(db),
    emailAndPassword: { enabled: true },
    plugins: [dbsc()],
  });
  return { auth, db };
}

function cookiesFrom(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const eq = pair!.indexOf("=");
    out[pair!.slice(0, eq)] = pair!.slice(eq + 1);
  }
  return out;
}

const jar = (c: Record<string, string>) =>
  Object.entries(c)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");

async function signUp(auth: ReturnType<typeof makeAuth>["auth"], email: string) {
  const res = await auth.handler(
    new Request(`${BASE}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BASE },
      body: JSON.stringify({ email, password: "a-long-password-123", name: "x" }),
    }),
  );
  expect(res.status).toBe(200);
  const cookies = cookiesFrom(res);
  const dbscId = cookies["__Host-dbsc-reg"];
  expect(dbscId).toBeTruthy();
  return { cookies, dbscId: dbscId! };
}

describe("better-auth plugin protocol routes", () => {
  it("refuses a polyfill challenge to a caller holding only the DBSC id", async () => {
    const { auth } = makeAuth();
    const victim = await signUp(auth, "victim@example.com");
    const attacker = await signUp(auth, "attacker@example.com");

    const { "__Host-dbsc-session": _own, ...attackerAuthCookies } = attacker.cookies;
    const asAttacker = await auth.handler(
      new Request(`${BASE}/api/auth/dbsc-bound/challenge`, {
        headers: { cookie: jar({ ...attackerAuthCookies, "__Host-dbsc-reg": victim.dbscId }) },
      }),
    );
    expect(asAttacker.status).toBe(401);

    const asVictim = await auth.handler(
      new Request(`${BASE}/api/auth/dbsc-bound/challenge`, { headers: { cookie: jar(victim.cookies) } }),
    );
    expect(asVictim.status).toBe(200);
  });

  it("keeps the challenge header on the native refresh 403 and ends the binding after sign-out", async () => {
    const { auth } = makeAuth();
    const user = await signUp(auth, "user@example.com");

    const challenged = await auth.handler(
      new Request(`${BASE}/api/auth/dbsc/refresh`, {
        method: "POST",
        headers: { "sec-secure-session-id": user.dbscId },
      }),
    );
    expect(challenged.status).toBe(403);
    expect(challenged.headers.get("secure-session-challenge")).toContain(`id="${user.dbscId}"`);

    const out = await auth.handler(
      new Request(`${BASE}/api/auth/sign-out`, {
        method: "POST",
        headers: { cookie: jar(user.cookies), origin: BASE },
      }),
    );
    expect(out.status).toBe(200);

    const afterSignOut = await auth.handler(
      new Request(`${BASE}/api/auth/dbsc/refresh`, {
        method: "POST",
        headers: { "sec-secure-session-id": user.dbscId },
      }),
    );
    expect(afterSignOut.status).toBe(401);
    expect(afterSignOut.headers.get("secure-session-challenge")).toBeNull();
  });
});
