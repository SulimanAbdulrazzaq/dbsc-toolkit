import { randomBytes } from "node:crypto";
import type { NextRequest } from "next/server.js";
import { NextResponse } from "next/server.js";
import {
  handleRegistration,
  handleRefresh,
  issueChallenge,
  buildRegistrationHeader,
  buildChallengeHeader,
  parseSessionSkippedHeader,
  REGISTRATION_HEADER,
  CHALLENGE_HEADER,
  LEGACY_REGISTRATION_HEADER,
  LEGACY_CHALLENGE_HEADER,
  NoopRateLimiter,
  emit,
  DbscProtocolError,
  DbscVerificationError,
  type DbscOptions,
  type StorageAdapter,
  type ProtectionTier,
  type SkippedEntry,
} from "../core/index.js";

const cookieNames = (secure: boolean) => ({
  bound: secure ? "__Host-dbsc-session" : "dbsc-session",
  reg: secure ? "__Host-dbsc-reg" : "dbsc-reg",
  challenge: secure ? "__Host-dbsc-challenge" : "dbsc-challenge",
});

const DEFAULT_BOUND_TTL = 10 * 60;
const DEFAULT_REG_TTL = 24 * 60 * 60;
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

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

export interface BindSessionOptions {
  userId: string;
  secure?: boolean;
  registrationPath?: string;
  registrationCookieTtl?: number;
  sessionTtl?: number;
}

export async function bindSession(
  res: NextResponse,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void> {
  const secure = opts.secure ?? true;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const regCookieTtl = opts.registrationCookieTtl ?? DEFAULT_REG_TTL * 1000;
  const sessionTtl = opts.sessionTtl ?? DEFAULT_SESSION_TTL_MS;

  const existing = await storage.getSession(sessionId);
  const now = Date.now();
  if (!existing) {
    await storage.setSession({
      id: sessionId,
      userId: opts.userId,
      tier: "none",
      createdAt: now,
      expiresAt: now + sessionTtl,
      lastRefreshAt: 0,
    });
  }

  const COOKIES = cookieNames(secure);
  const challenge = await issueChallenge(sessionId, storage);
  const regHeader = buildRegistrationHeader({
    refreshPath: registrationPath,
    challenge: challenge.jti,
    cookieName: COOKIES.bound,
  });

  res.headers.set(REGISTRATION_HEADER, regHeader);
  res.headers.set(LEGACY_REGISTRATION_HEADER, regHeader);

  res.cookies.set(COOKIES.reg, sessionId, {
    ...cookieBase(secure),
    maxAge: regCookieTtl / 1000,
  });
  res.cookies.set(COOKIES.challenge, challenge.jti, {
    ...cookieBase(secure),
    maxAge: 5 * 60,
  });
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
    autoBind,
    secure = true,
  } = opts;

  const COOKIES = cookieNames(secure);

  return async function middleware(req: NextRequest): Promise<NextResponse> {
    const url = req.nextUrl.pathname;
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";

    if (req.method === "POST" && url === registrationPath) {
      const sessionId = req.cookies.get(COOKIES.reg)?.value;
      const expectedJti = req.cookies.get(COOKIES.challenge)?.value;

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
          scope: {
            origin: req.nextUrl.origin,
            include_site: true,
            scope_specification: [],
          },
          credentials: [
            {
              type: "cookie",
              name: COOKIES.bound,
              attributes: "Path=/; Secure; HttpOnly; SameSite=Lax",
            },
          ],
        };
        const res = NextResponse.json(body, { status: 200 });
        res.cookies.set(COOKIES.bound, sessionId, {
          ...cookieBase(secure),
          maxAge: boundCookieTtl / 1000,
        });
        res.cookies.delete(COOKIES.challenge);
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
      const sessionId = sessionIdHeader ?? req.cookies.get(COOKIES.bound)?.value;

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
        res.headers.set(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.headers.set(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.cookies.set(COOKIES.challenge, challenge.jti, {
          ...cookieBase(secure),
          maxAge: 5 * 60,
        });
        return res;
      }

      const expectedJti = req.cookies.get(COOKIES.challenge)?.value;
      if (!expectedJti) {
        const challenge = await issueChallenge(sessionId, storage);
        const res = new NextResponse(null, { status: 403 });
        res.headers.set(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.headers.set(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        res.cookies.set(COOKIES.challenge, challenge.jti, {
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
          scope: {
            origin: req.nextUrl.origin,
            include_site: true,
            scope_specification: [],
          },
          credentials: [
            {
              type: "cookie",
              name: COOKIES.bound,
              attributes: "Path=/; Secure; HttpOnly; SameSite=Lax",
            },
          ],
        };
        const res = NextResponse.json(body, { status: 200 });
        res.cookies.set(COOKIES.bound, sessionId, {
          ...cookieBase(secure),
          maxAge: boundCookieTtl / 1000,
        });
        res.cookies.delete(COOKIES.challenge);
        return res;
      } catch (err) {
        await rateLimiter.recordFailure(ip, sessionId);
        if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
          return NextResponse.json({ error: err.message }, { status: 401 });
        }
        throw err;
      }
    }

    if (autoBind && !req.cookies.get(COOKIES.bound)?.value && !req.cookies.get(COOKIES.reg)?.value) {
      const result = await autoBind(req);
      if (result) {
        const res = NextResponse.next();
        await bindSession(res, result.sessionId, storage, {
          userId: result.userId,
          secure,
          registrationPath,
          registrationCookieTtl,
        });
        return res;
      }
    }

    return NextResponse.next();
  };
}

export interface DbscSessionInfo {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

export async function getDbscSession(
  req: NextRequest,
  storage: DbscOptions["storage"],
  opts: { boundCookieTtl?: number; res?: NextResponse; secure?: boolean } = {},
): Promise<DbscSessionInfo> {
  const skippedRaw: Record<string, string | undefined> = {
    "secure-session-skipped": req.headers.get("secure-session-skipped") ?? undefined,
    "sec-session-skipped": req.headers.get("sec-session-skipped") ?? undefined,
  };
  const skipped = parseSessionSkippedHeader(skippedRaw);

  const secure = opts.secure ?? true;
  const COOKIES = cookieNames(secure);
  const sessionId = req.cookies.get(COOKIES.bound)?.value ?? null;

  const revoke = async () => {
    if (sessionId) await storage.revokeSession(sessionId);
    if (opts.res) {
      opts.res.cookies.delete(COOKIES.bound);
    }
  };

  if (!sessionId) return { sessionId: null, tier: "none", skipped, revoke };

  const session = await storage.getSession(sessionId);
  if (!session) return { sessionId: null, tier: "none", skipped, revoke };

  const boundCookieTtl = opts.boundCookieTtl ?? DEFAULT_BOUND_TTL * 1000;
  const staleAfter = session.lastRefreshAt + boundCookieTtl;
  if (session.tier === "dbsc" && Date.now() > staleAfter) {
    return { sessionId, tier: "none", skipped, revoke };
  }

  return { sessionId, tier: session.tier, skipped, revoke };
}
