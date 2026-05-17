import { randomBytes } from "node:crypto";
import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  handleRegistration,
  handleRefresh,
  issueChallenge,
  buildRegistrationHeader,
  buildChallengeHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  NoopRateLimiter,
  emit,
  DbscProtocolError,
  DbscVerificationError,
  type DbscOptions,
  type ProtectionTier,
} from "../core/index.js";

const BOUND_COOKIE = "__Host-dbsc-session";
const REGISTRATION_COOKIE = "__Host-dbsc-reg";
const CHALLENGE_COOKIE = "__Host-dbsc-challenge";

const DEFAULT_BOUND_TTL = 10 * 60;
const DEFAULT_REG_TTL = 24 * 60 * 60;

export interface DbscNextOptions extends DbscOptions {
  secure?: boolean;
}

function cookieBase(secure: boolean) {
  return {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
  };
}

export function createDbscMiddleware(opts: DbscNextOptions) {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL * 1000,
    registrationCookieTtl = DEFAULT_REG_TTL * 1000,
    rateLimiter = new NoopRateLimiter(),
    onEvent,
    secure = true,
  } = opts;

  return async function middleware(req: NextRequest): Promise<NextResponse> {
    const url = req.nextUrl.pathname;
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";

    if (req.method === "POST" && url === registrationPath) {
      const sessionId = req.cookies.get(REGISTRATION_COOKIE)?.value;
      const expectedJti = req.cookies.get(CHALLENGE_COOKIE)?.value;

      if (!sessionId || !expectedJti) {
        return NextResponse.json({ error: "missing session or challenge cookie" }, { status: 400 });
      }

      const allowed = await rateLimiter.checkRegistration(ip);
      if (!allowed) {
        return NextResponse.json({ error: "rate limited" }, { status: 429 });
      }

      try {
        await handleRegistration(
          {
            sessionId,
            secSessionResponseHeader:
              req.headers.get("secure-session-response") ??
              req.headers.get("sec-session-response") ??
              undefined,
            expectedJti,
          },
          storage,
        );

        emit(onEvent, {
          type: "registration",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          algorithm: "ES256",
          ip,
        });

        const body = {
          session_identifier: sessionId,
          refresh_url: refreshPath,
          scope: { include_site: true },
          credentials: [
            {
              type: "cookie",
              name: BOUND_COOKIE,
              attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(boundCookieTtl / 1000)}`,
            },
          ],
        };
        const res = NextResponse.json(body, { status: 200 });
        res.cookies.set(BOUND_COOKIE, sessionId, {
          ...cookieBase(secure),
          maxAge: boundCookieTtl / 1000,
        });
        res.cookies.delete(CHALLENGE_COOKIE);
        return res;
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          return NextResponse.json({ error: err.message }, { status: 400 });
        }
        throw err;
      }
    }

    if (req.method === "POST" && url === refreshPath) {
      const sessionIdHeader = req.headers.get("sec-secure-session-id");
      const sessionId = sessionIdHeader ?? req.cookies.get(BOUND_COOKIE)?.value;

      if (!sessionId) {
        return new NextResponse(null, { status: 403 });
      }

      const allowed = await rateLimiter.checkRefresh(ip, sessionId);
      if (!allowed) {
        return NextResponse.json({ error: "rate limited" }, { status: 429 });
      }

      const responseHeader =
        req.headers.get("secure-session-response") ??
        req.headers.get("sec-session-response");

      if (!responseHeader) {
        const challenge = await issueChallenge(sessionId, storage);
        const res = new NextResponse(null, { status: 403 });
        res.headers.set(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        res.headers.set(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        res.cookies.set(CHALLENGE_COOKIE, challenge.jti, {
          ...cookieBase(secure),
          maxAge: 5 * 60,
        });
        return res;
      }

      const expectedJti = req.cookies.get(CHALLENGE_COOKIE)?.value;
      if (!expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        const res = new NextResponse(null, { status: 403 });
        res.headers.set(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        res.headers.set(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti));
        res.cookies.set(CHALLENGE_COOKIE, challenge.jti, {
          ...cookieBase(secure),
          maxAge: 5 * 60,
        });
        return res;
      }

      try {
        await handleRefresh({ sessionId, secSessionResponseHeader: responseHeader, expectedJti }, storage);

        emit(onEvent, {
          type: "refresh",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          ip,
        });

        const body = {
          session_identifier: sessionId,
          refresh_url: refreshPath,
          scope: { include_site: true },
          credentials: [
            {
              type: "cookie",
              name: BOUND_COOKIE,
              attributes: `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(boundCookieTtl / 1000)}`,
            },
          ],
        };
        const res = NextResponse.json(body, { status: 200 });
        res.cookies.set(BOUND_COOKIE, sessionId, {
          ...cookieBase(secure),
          maxAge: boundCookieTtl / 1000,
        });
        res.cookies.delete(CHALLENGE_COOKIE);
        return res;
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          return NextResponse.json({ error: err.message }, { status: 401 });
        }
        throw err;
      }
    }

    return NextResponse.next();
  };
}

export interface DbscSessionInfo {
  sessionId: string | null;
  tier: ProtectionTier;
}

export async function getDbscSession(
  req: NextRequest,
  storage: DbscOptions["storage"],
  opts: { boundCookieTtl?: number } = {},
): Promise<DbscSessionInfo> {
  const sessionId = req.cookies.get(BOUND_COOKIE)?.value ?? null;
  if (!sessionId) return { sessionId: null, tier: "none" };

  const session = await storage.getSession(sessionId);
  if (!session) return { sessionId: null, tier: "none" };

  const boundCookieTtl = opts.boundCookieTtl ?? DEFAULT_BOUND_TTL * 1000;
  const staleAfter = session.lastRefreshAt + boundCookieTtl;
  if (session.tier === "dbsc" && Date.now() > staleAfter) {
    return { sessionId, tier: "none" };
  }

  return { sessionId, tier: session.tier };
}
