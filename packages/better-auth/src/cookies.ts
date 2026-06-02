/**
 * Cookie helpers for the in-plugin DBSC routes. The Express adapter built
 * `Set-Cookie` strings by hand; inside Better Auth we use `ctx.setCookie`,
 * which serializes for us. This module resolves the scope-derived names and
 * attributes (the `__Host-`/`__Secure-` prefix swap) once and exposes thin
 * setters every route handler calls.
 *
 * Multiple `ctx.setCookie` calls in one handler are preserved by Better Auth's
 * endpoint pipeline (to-auth-endpoints.ts special-cases `set-cookie`), so a
 * route can set the bound cookie and clear the challenge cookie in the same
 * response.
 */
import {
  resolveCookieNames,
  resolveCookieScope,
  cookieAttributesString,
} from "dbsc-toolkit";

export interface ScopeConfig {
  secure: boolean;
  cookieScope: "host" | "site";
  cookieDomain?: string | undefined;
}

export interface CookieCtx {
  setCookie: (name: string, value: string, options?: Record<string, unknown>) => void;
  getCookie: (name: string) => string | undefined;
}

export interface DbscCookies {
  names: { bound: string; reg: string; challenge: string };
  /** The `attributes` string advertised in the registration JSON `credentials`. */
  attributesString: string;
  /** Set the bound session cookie (`__Host-dbsc-session`). */
  setBound(ctx: CookieCtx, sessionId: string, ttlMs: number): void;
  /** Set the registration-flow cookie (`__Host-dbsc-reg`). */
  setReg(ctx: CookieCtx, sessionId: string, ttlMs: number): void;
  /** Set the challenge cookie (`__Host-dbsc-challenge`). */
  setChallenge(ctx: CookieCtx, jti: string, ttlMs: number): void;
  /** Expire the challenge cookie. */
  clearChallenge(ctx: CookieCtx): void;
  /** Read the bound cookie, falling back to the reg cookie (refresh path). */
  readBoundOrReg(ctx: CookieCtx): string | undefined;
  /** Read the reg cookie. */
  readReg(ctx: CookieCtx): string | undefined;
  /** Read the challenge cookie. */
  readChallenge(ctx: CookieCtx): string | undefined;
}

export function makeCookies(scope: ScopeConfig): DbscCookies {
  const scopeOpts = scope.cookieDomain
    ? { secure: scope.secure, cookieScope: scope.cookieScope, cookieDomain: scope.cookieDomain }
    : { secure: scope.secure, cookieScope: scope.cookieScope };
  const names = resolveCookieNames(scopeOpts);
  const resolved = resolveCookieScope(scopeOpts);
  const attributesString = cookieAttributesString(scopeOpts);

  function baseOpts(ttlMs: number): Record<string, unknown> {
    return {
      httpOnly: true,
      path: "/",
      sameSite: "lax",
      secure: scope.secure,
      maxAge: Math.floor(ttlMs / 1000),
      ...(resolved.domain !== undefined && { domain: resolved.domain }),
    };
  }

  return {
    names,
    attributesString,
    setBound(ctx, sessionId, ttlMs) {
      ctx.setCookie(names.bound, sessionId, baseOpts(ttlMs));
    },
    setReg(ctx, sessionId, ttlMs) {
      ctx.setCookie(names.reg, sessionId, baseOpts(ttlMs));
    },
    setChallenge(ctx, jti, ttlMs) {
      ctx.setCookie(names.challenge, jti, baseOpts(ttlMs));
    },
    clearChallenge(ctx) {
      ctx.setCookie(names.challenge, "", { ...baseOpts(0), maxAge: 0 });
    },
    readBoundOrReg(ctx) {
      return ctx.getCookie(names.bound) ?? ctx.getCookie(names.reg);
    },
    readReg(ctx) {
      return ctx.getCookie(names.reg);
    },
    readChallenge(ctx) {
      return ctx.getCookie(names.challenge);
    },
  };
}
