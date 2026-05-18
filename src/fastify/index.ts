import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from "fastify";
import fp from "fastify-plugin";
import "@fastify/cookie";
import {
  handleRegistration,
  handleRefresh,
  issueChallenge,
  buildRegistrationHeader,
  buildChallengeHeader,
  readSessionResponseHeader,
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

declare module "fastify" {
  interface FastifyRequest {
    dbsc: {
      sessionId: string | null;
      tier: ProtectionTier;
      skipped: SkippedEntry[];
      revoke: () => Promise<void>;
    };
  }
}

const cookieNames = (secure: boolean) => ({
  bound: secure ? "__Host-dbsc-session" : "dbsc-session",
  reg: secure ? "__Host-dbsc-reg" : "dbsc-reg",
  challenge: secure ? "__Host-dbsc-challenge" : "dbsc-challenge",
});

const DEFAULT_BOUND_TTL_MS = 10 * 60 * 1000;
const DEFAULT_REG_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface DbscFastifyOptions extends DbscOptions {
  secure?: boolean;
}

export interface BindSessionOptions {
  userId: string;
  secure?: boolean;
  registrationPath?: string;
  registrationCookieTtl?: number;
  sessionTtl?: number;
}

export async function bindSession(
  reply: FastifyReply,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void> {
  const secure = opts.secure ?? true;
  const registrationPath = opts.registrationPath ?? "/dbsc/registration";
  const regCookieTtl = opts.registrationCookieTtl ?? DEFAULT_REG_TTL_MS;
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

  reply.header(REGISTRATION_HEADER, regHeader);
  reply.header(LEGACY_REGISTRATION_HEADER, regHeader);

  const cookieBase = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
  };
  reply.setCookie(COOKIES.reg, sessionId, { ...cookieBase, maxAge: regCookieTtl / 1000 });
  reply.setCookie(COOKIES.challenge, challenge.jti, { ...cookieBase, maxAge: 5 * 60 });
}

const dbscPlugin: FastifyPluginAsync<DbscFastifyOptions> = async (fastify, opts) => {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL_MS,
    registrationCookieTtl = DEFAULT_REG_TTL_MS,
    rateLimiter = new NoopRateLimiter(),
    onEvent,
    autoBind,
    secure = true,
  } = opts;

  const cookieOpts = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
  };

  const COOKIES = cookieNames(secure);

  fastify.decorateRequest<FastifyRequest["dbsc"] | null>("dbsc", null);

  fastify.addHook("onRequest", async (req: FastifyRequest, reply: FastifyReply) => {
    const sessionId = req.cookies?.[COOKIES.bound] ?? null;
    const skipped = parseSessionSkippedHeader(req.headers as Record<string, string | string[] | undefined>);

    req.dbsc = {
      sessionId,
      tier: "none",
      skipped,
      revoke: async () => {
        if (sessionId) await storage.revokeSession(sessionId);
        reply.clearCookie(COOKIES.bound, cookieOpts);
      },
    };

    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl;
        if (session.tier === "dbsc" && Date.now() > staleAfter) {
          req.dbsc.tier = "none";
        } else {
          req.dbsc.tier = session.tier;
        }
      }
    } else if (autoBind && !req.cookies?.[COOKIES.reg]) {
      const result = await autoBind(req);
      if (result) {
        await bindSession(reply, result.sessionId, storage, {
          userId: result.userId,
          secure,
          registrationPath,
          registrationCookieTtl,
        });
      }
    }
  });

  fastify.post(registrationPath, async (req: FastifyRequest, reply: FastifyReply) => {
    const ip = req.ip;
    const sessionId = req.cookies?.[COOKIES.reg];
    const expectedJti = req.cookies?.[COOKIES.challenge];

    if (!sessionId || !expectedJti) {
      return reply.status(400).send({ error: "missing session or challenge cookie" });
    }

    const allowed = await rateLimiter.checkRegistration(ip);
    if (!allowed) return reply.status(429).send({ error: "rate limited" });

    try {
      await handleRegistration(
        {
          sessionId,
          secSessionResponseHeader: readSessionResponseHeader(req.headers as Record<string, string | string[] | undefined>),
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

      reply.setCookie(COOKIES.bound, sessionId, {
        ...cookieOpts,
        maxAge: boundCookieTtl / 1000,
      });
      reply.clearCookie(COOKIES.challenge, cookieOpts);
      const origin = `${req.protocol}://${req.hostname}`;
      return reply.status(200).send({
        session_identifier: sessionId,
        refresh_url: refreshPath,
        scope: {
          origin,
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
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        return reply.status(400).send({ error: err.message });
      }
      throw err;
    }
  });

  fastify.post(refreshPath, async (req: FastifyRequest, reply: FastifyReply) => {
    const ip = req.ip;
    const sessionIdHeader = req.headers["sec-secure-session-id"];
    const sessionId =
      (Array.isArray(sessionIdHeader) ? sessionIdHeader[0] : sessionIdHeader) ??
      req.cookies?.[COOKIES.bound];

    if (!sessionId) return reply.status(403).send();

    const allowed = await rateLimiter.checkRefresh(ip, sessionId);
    if (!allowed) return reply.status(429).send({ error: "rate limited" });

    const responseHeader = readSessionResponseHeader(req.headers as Record<string, string | string[] | undefined>);

    if (!responseHeader) {
      const challenge = await issueChallenge(sessionId, storage);
      reply.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.setCookie(COOKIES.challenge, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
      return reply.status(403).send();
    }

    const expectedJti = req.cookies?.[COOKIES.challenge];
    if (!expectedJti) {
      const challenge = await issueChallenge(sessionId, storage);
      reply.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.setCookie(COOKIES.challenge, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
      return reply.status(403).send();
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

      reply.setCookie(COOKIES.bound, sessionId, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
      reply.clearCookie(COOKIES.challenge, cookieOpts);
      const origin = `${req.protocol}://${req.hostname}`;
      return reply.status(200).send({
        session_identifier: sessionId,
        refresh_url: refreshPath,
        scope: {
          origin,
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
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        return reply.status(401).send({ error: err.message });
      }
      throw err;
    }
  });
};

export const dbsc = fp(dbscPlugin, { name: "@dbsc-toolkit/server-fastify" });
