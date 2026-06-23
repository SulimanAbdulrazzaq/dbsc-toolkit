export interface RegistrationHeaderOptions {
  algorithm?: "ES256" | "RS256";
  /** Path where the browser will POST the registration JWS. */
  registrationPath?: string;
  /** @deprecated misnamed alias for registrationPath; kept for back-compat. */
  refreshPath?: string;
  challenge: string;
  /**
   * @deprecated No longer emitted. The W3C draft defines no `id` parameter on
   * `Secure-Session-Registration` — the bound cookie name is carried by the JSON
   * registration response (`credentials[].name`), not the header. Chrome ignored
   * this param; it was a no-op. Accepted for back-compat so existing callers keep
   * compiling. See spec/vectors/registration-header.json.
   */
  cookieName?: string;
}

export function buildRegistrationHeader(opts: RegistrationHeaderOptions): string {
  const alg = opts.algorithm ?? "ES256";
  const path = opts.registrationPath ?? opts.refreshPath;
  if (!path) throw new Error("buildRegistrationHeader: registrationPath is required");
  // No `id` parameter: it is not defined for this header in the W3C draft. The
  // cookie name is bound via the JSON registration response, not here.
  return [`(${alg})`, `path="${path}"`, `challenge="${opts.challenge}"`].join(";");
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
export const SKIPPED_HEADER = "Secure-Session-Skipped";

export const LEGACY_REGISTRATION_HEADER = "Sec-Session-Registration";
export const LEGACY_RESPONSE_HEADER = "Sec-Session-Response";
export const LEGACY_CHALLENGE_HEADER = "Sec-Session-Challenge";
export const LEGACY_SKIPPED_HEADER = "Sec-Session-Skipped";

export function readSessionResponseHeader(
  headers: Record<string, string | string[] | undefined>,
): string | undefined {
  const v = headers["secure-session-response"] ?? headers["sec-session-response"];
  if (Array.isArray(v)) return v[0];
  return v;
}

export type SkippedReason = "unreachable" | "server_error" | "quota_exceeded";

export interface SkippedEntry {
  reason: SkippedReason;
  sessionId?: string;
}

const SKIPPED_REASONS: ReadonlySet<string> = new Set([
  "unreachable",
  "server_error",
  "quota_exceeded",
]);

export function parseSessionSkippedHeader(
  headers: Record<string, string | string[] | undefined>,
): SkippedEntry[] {
  const raw = headers["secure-session-skipped"] ?? headers["sec-session-skipped"];
  if (!raw) return [];
  const value = Array.isArray(raw) ? raw.join(", ") : raw;
  const entries: SkippedEntry[] = [];

  for (const item of value.split(",")) {
    const trimmed = item.trim();
    if (!trimmed) continue;

    const [tokenPart, ...paramParts] = trimmed.split(";");
    const reason = tokenPart!.trim();
    if (!SKIPPED_REASONS.has(reason)) continue;

    let sessionId: string | undefined;
    for (const param of paramParts) {
      const eq = param.indexOf("=");
      if (eq === -1) continue;
      const key = param.slice(0, eq).trim();
      let val = param.slice(eq + 1).trim();
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }
      if (key === "session_identifier") sessionId = val;
    }

    const entry: SkippedEntry = { reason: reason as SkippedReason };
    if (sessionId !== undefined) entry.sessionId = sessionId;
    entries.push(entry);
  }

  return entries;
}
