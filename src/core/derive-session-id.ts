export interface DeriveSessionIdInput {
  /** Stable user identifier from your JWT (the `sub` claim is the canonical choice). */
  userId: string;
  /** Optional per-device hint. If omitted, one stable id per user — fine for single-device apps. */
  deviceHint?: string;
  /** Optional namespace to scope ids when the same user has multiple binding contexts (e.g. impersonation). Defaults to "default". */
  namespace?: string;
}

/**
 * Returns a stable, opaque sessionId suitable for `bindSession()` when the
 * caller has no server-side session row to take the id from (NextAuth in
 * JWT mode, iron-session, Lucia stateless, raw JWT cookies). Output is
 * deterministic for the same input — call it on every request, get the
 * same id, bind against it once at login, look it up on refresh.
 *
 * The id is SHA-256 of `${namespace}.${userId}.${deviceHint ?? ""}`,
 * base64url-encoded. It is not a secret and not reversible; it only needs
 * to be stable and collision-free across your users.
 */
export async function deriveSessionId(input: DeriveSessionIdInput): Promise<string> {
  if (!input.userId) {
    throw new Error("deriveSessionId: userId is required");
  }
  const namespace = input.namespace ?? "default";
  const deviceHint = input.deviceHint ?? "";
  const material = `${namespace}.${input.userId}.${deviceHint}`;
  const bytes = new TextEncoder().encode(material);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  return base64Url(new Uint8Array(digest));
}

function base64Url(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i] as number);
  return Buffer.from(s, "binary").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
