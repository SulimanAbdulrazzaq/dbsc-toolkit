import type { FastifyPluginAsync, FastifyRequest, FastifyReply } from "fastify";
import fp from "fastify-plugin";
import "@fastify/cookie";
import {
  handleRegistration,
  handleRefresh,
  handleBoundRegistration,
  handleBoundRefresh,
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
  maybeEmitPolyfillMissing,
  resolveCookieNames,
  resolveCookieScope,
  cookieAttributesString,
  DbscProtocolError,
  DbscVerificationError,
  ErrorCodes,
  type DbscOptions,
  type StorageAdapter,
  type ProofReplayCache,
  type ProtectionTier,
  type SkippedEntry,
  type CookieScope,
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

/** Internal carrier so `requireProof()` can reach storage without re-passing it. */
export interface DbscInternal {
  storage: StorageAdapter;
  secure: boolean;
  replayCache?: ProofReplayCache;
}
export const DBSC_INTERNAL: unique symbol = Symbol("dbsc-toolkit.fastify.internal");

interface ScopeArgs {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

const cookieNames = (s: ScopeArgs) => resolveCookieNames(s);

const DEFAULT_BOUND_TTL_MS = 10 * 60 * 1000;
const DEFAULT_REG_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface DbscFastifyOptions extends DbscOptions {
  secure?: boolean;
  boundStatePath?: string;
  boundChallengePath?: string;
  boundRegistrationPath?: string;
  boundRefreshPath?: string;
}

export interface BindSessionOptions {
  userId: string;
  /** Match the value passed to dbsc({ secure }). Defaults true. Mismatch = cookies the middleware cannot read. */
  secure?: boolean;
  /** Match the value passed to dbsc({ cookieScope }). Defaults "host". */
  cookieScope?: CookieScope;
  /** Match the value passed to dbsc({ cookieDomain }). Required for cookieScope: "site". */
  cookieDomain?: string;
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
  const scope: ScopeArgs = {
    secure,
    ...(opts.cookieScope !== undefined && { cookieScope: opts.cookieScope }),
    ...(opts.cookieDomain !== undefined && { cookieDomain: opts.cookieDomain }),
  };
  const { domain } = resolveCookieScope(scope);

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

  const COOKIES = cookieNames(scope);
  const challenge = await issueChallenge(sessionId, storage);
  const regHeader = buildRegistrationHeader({
    registrationPath,
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
    ...(domain !== undefined && { domain }),
  };
  reply.setCookie(COOKIES.reg, sessionId, { ...cookieBase, maxAge: regCookieTtl / 1000 });
  reply.setCookie(COOKIES.challenge, challenge.jti, { ...cookieBase, maxAge: 5 * 60 });
}

const dbscPlugin: FastifyPluginAsync<DbscFastifyOptions> = async (fastify, opts) => {
  const {
    storage,
    registrationPath = "/dbsc/registration",
    refreshPath = "/dbsc/refresh",
    boundStatePath = "/dbsc-bound/state",
    boundChallengePath = "/dbsc-bound/challenge",
    boundRegistrationPath = "/dbsc-bound/registration",
    boundRefreshPath = "/dbsc-bound/refresh",
    boundCookieTtl = DEFAULT_BOUND_TTL_MS,
    refreshGraceMs = 30_000,
    registrationCookieTtl = DEFAULT_REG_TTL_MS,
    rateLimiter = new NoopRateLimiter(),
    replayCache,
    onEvent,
    autoBind,
    secure = true,
    cookieScope,
    cookieDomain,
  } = opts;

  const scope: ScopeArgs = {
    secure,
    ...(cookieScope !== undefined && { cookieScope }),
    ...(cookieDomain !== undefined && { cookieDomain }),
  };
  const { domain } = resolveCookieScope(scope);
  const cookieAttrs = cookieAttributesString(scope);

  const cookieOpts = {
    httpOnly: true,
    secure,
    sameSite: "lax" as const,
    path: "/",
    ...(domain !== undefined && { domain }),
  };

  const COOKIES = cookieNames(scope);
  const polyfillMissingEmitted = new Set<string>();

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
    (req as unknown as Record<PropertyKey, unknown>)[DBSC_INTERNAL] = {
      storage,
      secure,
      ...(replayCache !== undefined && { replayCache }),
    } satisfies DbscInternal;

    if (sessionId) {
      const session = await storage.getSession(sessionId);
      if (session) {
        const staleAfter = session.lastRefreshAt + boundCookieTtl + refreshGraceMs;
        const refreshable = session.tier === "dbsc" || session.tier === "bound";
        if (refreshable && Date.now() > staleAfter) {
          req.dbsc.tier = "none";
        } else {
          req.dbsc.tier = session.tier;
        }
        if (onEvent) {
          await maybeEmitPolyfillMissing({
            storage,
            session,
            ip: req.ip ?? "unknown",
            emitted: polyfillMissingEmitted,
            onEvent,
          });
        }
      }
    } else if (autoBind && !req.cookies?.[COOKIES.reg]) {
      const result = await autoBind(req);
      if (result) {
        await bindSession(reply, result.sessionId, storage, {
          userId: result.userId,
          secure,
          ...(cookieScope !== undefined && { cookieScope }),
          ...(cookieDomain !== undefined && { cookieDomain }),
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
            attributes: cookieAttrs,
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
            attributes: cookieAttrs,
          },
        ],
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);

      const stolenCheck = await storage.getBoundKey(sessionId);
      if (stolenCheck && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
        emit(onEvent, { type: "session_stolen", sessionId, tier: "dbsc", timestamp: Date.now(), ip });
      }

      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, {
          type: "verification_failure",
          sessionId,
          tier: "dbsc",
          timestamp: Date.now(),
          reason: (err as DbscVerificationError).code,
          ip,
        });
        const challenge = await issueChallenge(sessionId, storage);
        reply.header(CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        reply.header(LEGACY_CHALLENGE_HEADER, buildChallengeHeader(challenge.jti, sessionId));
        reply.setCookie(COOKIES.challenge, challenge.jti, { ...cookieOpts, maxAge: 5 * 60 });
        return reply.status(403).send({ error: err.message });
      }
      throw err;
    }
  });

  const readBoundSessionId = (req: FastifyRequest): string | undefined =>
    req.cookies?.[COOKIES.bound] ?? req.cookies?.[COOKIES.reg];

  fastify.get(boundStatePath, async (req: FastifyRequest, reply: FastifyReply) => {
    reply.header("X-Server-Time", String(Date.now()));
    const skipped = parseSessionSkippedHeader(req.headers as Record<string, string | string[] | undefined>);
    const nativeSkipped = skipped.length ? skipped.map((s) => s.reason) : undefined;
    const sessionId = readBoundSessionId(req);
    if (!sessionId) {
      return reply.status(200).send({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
    }
    const session = await storage.getSession(sessionId);
    if (!session) {
      return reply.status(200).send({ phase: "unbound", sessionId: null, ...(nativeSkipped && { nativeSkipped }) });
    }
    const nativeKey = await storage.getBoundKey(sessionId, "native");
    const boundKey = await storage.getBoundKey(sessionId, "bound");
    if (!nativeKey && !boundKey) {
      const challenge = await issueChallenge(sessionId, storage);
      return reply.status(200).send({
        phase: "needs-registration",
        sessionId,
        challenge: challenge.jti,
        ...(nativeSkipped && { nativeSkipped }),
      });
    }
    if (nativeKey && !boundKey) {
      const challenge = await issueChallenge(sessionId, storage);
      return reply.status(200).send({
        phase: "needs-bound-registration",
        sessionId,
        tier: session.tier,
        challenge: challenge.jti,
        refreshIntervalMs: boundCookieTtl,
        ...(nativeSkipped && { nativeSkipped }),
      });
    }
    return reply.status(200).send({
      phase: "bound",
      sessionId,
      tier: session.tier,
      refreshIntervalMs: boundCookieTtl,
      ...(nativeSkipped && { nativeSkipped }),
    });
  });

  fastify.get(boundChallengePath, async (req: FastifyRequest, reply: FastifyReply) => {
    reply.header("X-Server-Time", String(Date.now()));
    const sessionId = readBoundSessionId(req);
    if (!sessionId) return reply.status(403).send({ error: "no session" });
    const session = await storage.getSession(sessionId);
    if (!session) return reply.status(403).send({ error: "no session" });
    const challenge = await issueChallenge(sessionId, storage);
    return reply.status(200).send({ challenge: challenge.jti });
  });

  fastify.post(boundRegistrationPath, async (req: FastifyRequest, reply: FastifyReply) => {
    reply.header("X-Server-Time", String(Date.now()));
    const ip = req.ip;
    const allowed = await rateLimiter.checkRegistration(ip);
    if (!allowed) return reply.status(429).send({ error: "rate limited" });

    const sessionId = readBoundSessionId(req);
    if (!sessionId) return reply.status(400).send({ error: "missing session cookie" });

    const body = (req.body ?? {}) as { publicKey?: JsonWebKey; signature?: string; challenge?: string };
    if (!body.publicKey || !body.signature || !body.challenge) {
      return reply.status(400).send({ error: "publicKey, signature, and challenge are required" });
    }

    try {
      await handleBoundRegistration(
        { sessionId, publicKey: body.publicKey, signature: body.signature, expectedJti: body.challenge },
        storage,
      );
      emit(onEvent, {
        type: "registration",
        sessionId,
        tier: "bound",
        timestamp: Date.now(),
        algorithm: "ES256",
        ip,
      });
      reply.setCookie(COOKIES.bound, sessionId, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
      return reply.status(200).send({
        session_identifier: sessionId,
        refresh_url: boundRefreshPath,
        tier: "bound",
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, {
          type: "verification_failure",
          sessionId,
          tier: "bound",
          timestamp: Date.now(),
          reason: err.code,
          ip,
        });
        return reply.status(400).send({ error: err.message });
      }
      throw err;
    }
  });

  fastify.post(boundRefreshPath, async (req: FastifyRequest, reply: FastifyReply) => {
    reply.header("X-Server-Time", String(Date.now()));
    const ip = req.ip;
    const sessionId = readBoundSessionId(req);
    if (!sessionId) return reply.status(403).send({ error: "no session" });

    const allowed = await rateLimiter.checkRefresh(ip, sessionId);
    if (!allowed) return reply.status(429).send({ error: "rate limited" });

    const body = (req.body ?? {}) as { challenge?: string; signature?: string; timestamp?: number };
    if (!body.challenge || !body.signature || typeof body.timestamp !== "number") {
      return reply.status(400).send({ error: "challenge, signature, and timestamp are required" });
    }

    try {
      await handleBoundRefresh(
        { sessionId, signature: body.signature, expectedJti: body.challenge, timestamp: body.timestamp },
        storage,
      );
      emit(onEvent, { type: "refresh", sessionId, tier: "bound", timestamp: Date.now(), ip });
      reply.setCookie(COOKIES.bound, sessionId, { ...cookieOpts, maxAge: boundCookieTtl / 1000 });
      return reply.status(200).send({
        session_identifier: sessionId,
        refresh_url: boundRefreshPath,
        tier: "bound",
      });
    } catch (err) {
      await rateLimiter.recordFailure(ip, sessionId);
      const keyStillThere = await storage.getBoundKey(sessionId);
      if (keyStillThere && err instanceof DbscVerificationError && err.code === ErrorCodes.SIGNATURE_INVALID) {
        emit(onEvent, { type: "session_stolen", sessionId, tier: "bound", timestamp: Date.now(), ip });
      }
      if (err instanceof DbscVerificationError || err instanceof DbscProtocolError) {
        emit(onEvent, {
          type: "verification_failure",
          sessionId,
          tier: "bound",
          timestamp: Date.now(),
          reason: err.code,
          ip,
        });
        return reply.status(401).send({ error: err.message });
      }
      throw err;
    }
  });
};

export const dbsc = fp(dbscPlugin, { name: "@dbsc-toolkit/server-fastify" });

export { requireBoundProof } from "./proof.js";
export type { RequireBoundProofOptions } from "./proof.js";
export { requireProof } from "./require-proof.js";
export { createDbsc } from "./create-dbsc.js";
export type { CreateDbscOptions, DbscKit, BindOptions } from "./create-dbsc.js";
