import type { StorageAdapter } from "./types.js";
import type { SessionBindingHook } from "./protect-policy.js";
import { DEFAULT_BOUND_REGISTRATION_WINDOW_MS } from "./bound/registration.js";

/**
 * Starts the binding by itself on the first request after a login, so the
 * login route needs no DBSC code. Give the kit two facts about the request:
 * who is signed in, and when that login happened.
 */
export interface BindOnLoginOptions<Req> {
  /** The signed-in user's id, or nothing when the request is anonymous. */
  userId: SessionBindingHook<Req>;
  /**
   * When the current login happened (epoch ms or a Date). The binding only
   * starts within `windowMs` of it, the same window a device key has to
   * register in after `bind()`. Return nothing when unknown; the request is
   * then left alone.
   */
  loginAt: (req: Req) => number | Date | null | undefined | Promise<number | Date | null | undefined>;
  /** How long after the login a binding may still start. Default 5 minutes. */
  windowMs?: number;
}

export interface LoginBindingInput {
  userId: string;
  loginAt: number;
  /** The session id the binding will use. */
  sessionId: string;
  /** The DBSC session already on this request, if any. */
  currentSessionId: string | null;
  windowMs?: number;
  now?: number;
}

/**
 * Decides whether this request should start a binding. It does when the
 * login is recent and no binding has started for this session since that
 * login. A binding that predates the login (an earlier sign-in that reused
 * the id) is replaced; one that started at or after it is left alone, so a
 * later request carrying the same app cookie cannot reset it.
 */
export async function shouldBindLogin(storage: StorageAdapter, input: LoginBindingInput): Promise<boolean> {
  const now = input.now ?? Date.now();
  const windowMs = input.windowMs ?? DEFAULT_BOUND_REGISTRATION_WINDOW_MS;
  if (!Number.isFinite(input.loginAt) || input.loginAt > now + 60_000) return false;
  if (now - input.loginAt > windowMs) return false;
  if (input.currentSessionId === input.sessionId) return false;
  const existing = await storage.getSession(input.sessionId);
  return !existing || existing.createdAt < input.loginAt;
}

/** Normalizes a `loginAt` hook result to epoch ms. */
export function loginTime(value: number | Date | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  const ms = value instanceof Date ? value.getTime() : value;
  return Number.isFinite(ms) ? ms : null;
}

export interface ResolveLoginBindingInput<Req> {
  storage: StorageAdapter;
  /** The kit's `expectSessionId`; when set, its value is the id that gets bound. */
  expectSessionId?: SessionBindingHook<Req>;
  /** Derives the id for apps without a server session (JWT mode). */
  deriveSessionId: (userId: string) => Promise<string>;
  /** The DBSC session already on this request, if any. */
  currentSessionId: string | null;
  /** Fallback window when `bindOnLogin.windowMs` is unset. */
  windowMs?: number;
}

/**
 * Runs the `bindOnLogin` hooks for one request. Returns the session to bind,
 * or `null` when this request should not start a binding.
 */
export async function resolveLoginBinding<Req>(
  cfg: BindOnLoginOptions<Req>,
  req: Req,
  input: ResolveLoginBindingInput<Req>,
): Promise<{ sessionId: string; userId: string } | null> {
  const userId = await cfg.userId(req);
  if (!userId) return null;
  const loginAt = loginTime(await cfg.loginAt(req));
  if (loginAt === null) return null;
  const windowMs = cfg.windowMs ?? input.windowMs;
  if (Date.now() - loginAt > (windowMs ?? DEFAULT_BOUND_REGISTRATION_WINDOW_MS)) return null;
  let sessionId: string;
  if (input.expectSessionId) {
    const id = await input.expectSessionId(req);
    if (!id) return null;
    sessionId = id;
  } else {
    sessionId = await input.deriveSessionId(userId);
  }
  const bind = await shouldBindLogin(input.storage, {
    userId,
    loginAt,
    sessionId,
    currentSessionId: input.currentSessionId,
    ...(windowMs !== undefined && { windowMs }),
  });
  return bind ? { sessionId, userId } : null;
}
