import type { RequireProofOptions } from "./protect-policy.js";

/**
 * Options for a kit's `protect()`: `requireProof()` applied by path instead
 * of route by route.
 */
export interface ProtectOptions<Req> extends RequireProofOptions<Req> {
  /** Paths inside the protected set that stay open (a health check, a webhook). */
  except?: string[];
  /** Only these methods are guarded. Default: all. */
  methods?: string[];
}

/**
 * Matches a pathname against protect patterns:
 *
 * - `"/api/*"` or `"/api/"`: everything under `/api/`
 * - `"/account"`: `/account` itself and everything under `/account/`
 * - `"*"`: every path
 */
export function matchesPathPattern(pathname: string, pattern: string): boolean {
  if (pattern === "*" || pattern === "/*") return true;
  const trimmed = pattern.replace(/\*+$/, "");
  if (trimmed.endsWith("/")) return pathname.startsWith(trimmed);
  return pathname === trimmed || pathname.startsWith(`${trimmed}/`);
}

/** Validates patterns once, at `protect()` time. */
export function validatePathPatterns(patterns: readonly string[], label = "protect"): void {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    throw new Error(`${label}: pass at least one path pattern, e.g. ["/api/*"]`);
  }
  for (const p of patterns) {
    if (typeof p !== "string" || (p !== "*" && !p.startsWith("/"))) {
      throw new Error(`${label}: "${String(p)}" must start with "/" (or be "*")`);
    }
  }
}

/** Returns true when the request falls under `protect(patterns, opts)`. */
export function isProtected(
  pathname: string,
  method: string,
  patterns: readonly string[],
  opts: { except?: string[]; methods?: string[] } = {},
): boolean {
  if (opts.methods && !opts.methods.some((m) => m.toUpperCase() === method.toUpperCase())) return false;
  if (!patterns.some((p) => matchesPathPattern(pathname, p))) return false;
  return !(opts.except ?? []).some((p) => matchesPathPattern(pathname, p));
}

/** Turns protect patterns into the client's sign prefixes. */
export function signPrefixes(patterns: readonly string[]): string[] | undefined {
  if (patterns.some((p) => p === "*" || p === "/*")) return undefined;
  return [...new Set(patterns.map((p) => p.replace(/\*+$/, "")))];
}

/** Splits a kit's protect options into the guard options and the path filter. */
export function splitProtectOptions<Req>(opts: ProtectOptions<Req>): {
  guard: RequireProofOptions<Req>;
  filter: { except?: string[]; methods?: string[] };
} {
  const { except, methods, ...guard } = opts;
  return {
    guard,
    filter: {
      ...(except !== undefined && { except }),
      ...(methods !== undefined && { methods }),
    },
  };
}
