/**
 * Cookie-scope helpers shared by every adapter (v2.9+).
 *
 * Single source of truth for the cookie prefix (`__Host-` vs `__Secure-`),
 * the `Domain` attribute, and the `attributes` string echoed back in the
 * registration response's `credentials[].attributes` field.
 *
 * The four adapters wrap framework-specific cookie APIs around the values
 * returned here. The validator throws on construction so a missing
 * `cookieDomain` cannot silently degrade into a broken state at request
 * time.
 */

export type CookieScope = "host" | "site";

export interface CookieScopeOptions {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

export interface CookieScopeResolved {
  /** Whether the cookies use the `__Host-` prefix (host scope, secure). */
  hostPrefix: boolean;
  /** `"__Host-"`, `"__Secure-"`, or `""` (insecure dev). */
  prefix: "__Host-" | "__Secure-" | "";
  /** The `Domain` attribute value, or undefined when no domain is emitted. */
  domain: string | undefined;
}

/**
 * Validates a cookie-scope configuration and returns the resolved values
 * the adapters consume. Throws when `"site"` scope is requested without a
 * `cookieDomain`, or when an insecure config tries to use site scope (a
 * `__Secure-` cookie requires the `Secure` flag, which requires HTTPS).
 */
export function resolveCookieScope(opts: CookieScopeOptions): CookieScopeResolved {
  const scope: CookieScope = opts.cookieScope ?? "host";
  const secure = opts.secure;

  if (scope === "site") {
    if (!opts.cookieDomain) {
      throw new Error(
        'dbsc: cookieScope: "site" requires cookieDomain. ' +
          "Set cookieDomain to the registrable apex (e.g. \"example.com\") " +
          "so the binding cookie can be shared across subdomains. " +
          'Drop cookieScope to keep the default "host" mode.',
      );
    }
    if (!secure) {
      throw new Error(
        'dbsc: cookieScope: "site" requires secure: true. ' +
          "The __Secure- prefix is rejected by browsers without the Secure flag.",
      );
    }
    if (opts.cookieDomain.startsWith(".")) {
      throw new Error(
        'dbsc: cookieDomain must not start with a leading dot. ' +
          'Use "example.com", not ".example.com".',
      );
    }
    return { hostPrefix: false, prefix: "__Secure-", domain: opts.cookieDomain };
  }

  // host scope
  if (opts.cookieDomain) {
    throw new Error(
      'dbsc: cookieDomain is only valid when cookieScope: "site". ' +
        'Remove cookieDomain or set cookieScope: "site".',
    );
  }
  return {
    hostPrefix: secure,
    prefix: secure ? "__Host-" : "",
    domain: undefined,
  };
}

/**
 * Returns the three cookie names (`bound`, `reg`, `challenge`) the adapters
 * read and write. Encapsulates the prefix swap so callers never concatenate
 * a prefix by hand.
 */
export function cookieNames(opts: CookieScopeOptions): {
  bound: string;
  reg: string;
  challenge: string;
} {
  const { prefix } = resolveCookieScope(opts);
  return {
    bound: `${prefix}dbsc-session`,
    reg: `${prefix}dbsc-reg`,
    challenge: `${prefix}dbsc-challenge`,
  };
}

/**
 * The name of the per-device cookie used by the JWT-mode `bind()` path.
 * Same prefix rules as the binding cookies above.
 */
export function deviceCookieName(opts: CookieScopeOptions): string {
  const { prefix } = resolveCookieScope(opts);
  return `${prefix}dbsc-device`;
}

/**
 * Returns the `attributes` string echoed back in the registration response's
 * `credentials[].attributes` field, which Chromium re-reads to know how to
 * re-issue the bound cookie on refresh. Must match what the server actually
 * sets in `Set-Cookie`, byte for byte, or Chromium drops the binding.
 */
export function cookieAttributesString(opts: CookieScopeOptions): string {
  const { domain } = resolveCookieScope(opts);
  const parts = ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"];
  if (domain) parts.push(`Domain=${domain}`);
  return parts.join("; ");
}
