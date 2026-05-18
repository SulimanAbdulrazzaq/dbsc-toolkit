import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from "fastify";
import fp from "fastify-plugin";
import "@fastify/cookie";
import {
  handleRegistration,
  handleRefresh,
  issueChallenge,
  buildChallengeHeader,
  readSessionResponseHeader,
  parseSessionSkippedHeader,
  CHALLENGE_HEADER,
  LEGACY_CHALLENGE_HEADER,
  NoopRateLimiter,
  emit,
  DbscProtocolError,
  DbscVerificationError,
  type DbscOptions,
  type ProtectionTier,
  type SkippedEntry,
} from "../core/index.js";

declare module "fastify" {
  interface FastifyRequest {
    dbsc: {
      sessionId: string | null;
      tier: ProtectionTier;
      skipped: SkippedEntry[];
      revoke(): Promise<void>;
    };
  }
}

const BOUND_COOKIE = "__Host-dbsc-session";
const REGISTRATION_COOKIE = "__Host-dbsc-reg";
const CHALLENGE_COOKIE = "__Host-dbsc-challenge";

const DEFAULT_BOUND_TTL = 10 * 60;

export interface DbscFastifyOptions extends DbscOptions {
  secure?: boolean;
}

const dbscPlugin: FastifyPluginAsync<DbscFastifyOptions> = async (fastify, opts) => {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL * 1000,
    rateLimiter = new NoopRateLimiter(),
    onEvent,
    secure = true,
  } = opts;

  const cookieOpts = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
  };

  fastify.decorateRequest<FastifyRequest["dbsc"] | null>("dbsc", null);

  fastify.addHook("onRequest", async (req: FastifyRequest, reply: FastifyReply) => {
    const sessionId = req.cookies?.[BOUND_COOKIE] ?? null;
    const skipped = parseSessionSkippedHeader(req.headers as Record<string, string | string[] | undefined>);

    req.dbsc = {
      sessionId,
      tier: "none",
      skipped,
      revoke: async () => {
        if (sessionId) await storage.revokeSession(sessionId);
        reply.clearCookie(BOUND_COOKIE, cookieOpts);
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
    }
  });

  fastify.post(registrationPath, async (req: FastifyRequest, reply: FastifyReply) => {
    const ip = req.ip;
    const sessionId = req.cookies?.[REGISTRATION_COOKIE];
    const expectedJti = req.cookies?.[CHALLENGE_COOKIE];

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

      reply.setCookie(BOUND_COOKIE, sessionId, {
        ...cookieOpts,
        maxAge: boundCookieTtl / 1000,
      });
      reply.clearCookie(CHALLENGE_COOKIE, cookieOpts);
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
            name: BOUND_COOKIE,
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
      req.cookies?.[BOUND_COOKIE];

    if (!sessionId) return reply.status(403).send();

    const allowed = await rateLimiter.checkRefresh(ip, sessionId);
    if (!allowed) return reply.status(429).send({ error: "rate limited" });

    const responseHeader = readSessionResponseHeader(req.headers as Record<string, string | string[] | undefined>);

    if (!responseHeader) {
      const challenge = await issueChallenge(sessionId, storage);
      reply.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.setCookie(CHALLENGE_COOKIE, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
      return reply.status(403).send();
    }

    const expectedJti = req.cookies?.[CHALLENGE_COOKIE];
    if (!expectedJti) {
      const challenge = await issueChallenge(sessionId, storage);
      reply.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
      reply.setCookie(CHALLENGE_COOKIE, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
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

      reply.setCookie(BOUND_COOKIE, sessionId, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
      reply.clearCookie(CHALLENGE_COOKIE, cookieOpts);
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
            name: BOUND_COOKIE,
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
