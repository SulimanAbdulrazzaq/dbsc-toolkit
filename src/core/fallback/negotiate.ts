import type { ProtectionTier } from "../types.js";

export interface NegotiationContext {
  acceptsDbsc: boolean;
  supportsWebAuthn: boolean;
  hmacAllowed: boolean;
}

export function negotiateTier(ctx: NegotiationContext): ProtectionTier {
  if (ctx.acceptsDbsc) return "dbsc";
  if (ctx.supportsWebAuthn) return "webauthn";
  if (ctx.hmacAllowed) return "hmac";
  return "none";
}

export function detectDbscSupport(headers: Record<string, string | string[] | undefined>): boolean {
  const secFetch = headers["sec-fetch-site"];
  const ua = (headers["user-agent"] ?? "") as string;

  // Chrome 146+ on Windows carries DBSC support
  // The definitive signal is whether the browser responds to Secure-Session-Registration
  // This header is set by the server; we detect support by checking Chrome version
  const chromeMatch = /Chrome\/(\d+)/.exec(ua);
  if (!chromeMatch) return false;
  const version = parseInt(chromeMatch[1] ?? "0", 10);
  return version >= 146 && !!secFetch;
}
