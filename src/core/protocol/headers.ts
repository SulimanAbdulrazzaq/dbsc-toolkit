export interface RegistrationHeaderOptions {
  algorithm?: "ES256" | "RS256";
  refreshPath: string;
  challenge: string;
  cookieName?: string;
}

export function buildRegistrationHeader(opts: RegistrationHeaderOptions): string {
  const alg = opts.algorithm ?? "ES256";
  const parts = [`(${alg})`, `path="${opts.refreshPath}"`, `challenge="${opts.challenge}"`];
  if (opts.cookieName) parts.push(`id="${opts.cookieName}"`);
  return parts.join(";");
}

export function buildChallengeHeader(jti: string, sessionId?: string): string {
  const base = `"${jti}"`;
  return sessionId ? `${base};id="${sessionId}"` : base;
}

export function parseSessionResponseHeader(raw: string): string {
  return raw.trim();
}

export function buildSessionIdCookie(
  sessionId: string,
  opts: { secure: boolean; sameSite: string },
): string {
  const parts = [`__Secure-Session-Id=${sessionId}`, "HttpOnly", "Path=/"];
  if (opts.secure) parts.push("Secure");
  const sameSite = opts.sameSite.charAt(0).toUpperCase() + opts.sameSite.slice(1);
  parts.push(`SameSite=${sameSite}`);
  return parts.join("; ");
}

export const REGISTRATION_HEADER = "Secure-Session-Registration";
export const RESPONSE_HEADER = "Secure-Session-Response";
export const CHALLENGE_HEADER = "Secure-Session-Challenge";

export const LEGACY_REGISTRATION_HEADER = "Sec-Session-Registration";
export const LEGACY_RESPONSE_HEADER = "Sec-Session-Response";
export const LEGACY_CHALLENGE_HEADER = "Sec-Session-Challenge";

export function readSessionResponseHeader(
  headers: Record<string, string | string[] | undefined>,
): string | undefined {
  const v = headers["secure-session-response"] ?? headers["sec-session-response"];
  if (Array.isArray(v)) return v[0];
  return v;
}
