import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

// This tier binds a cookie to a set of browser signals via HMAC.
// It does NOT provide hardware-level binding. Use only when DBSC and WebAuthn
// are both unavailable. Document this limitation to end users.

const SIGNAL_SEPARATOR = "|";

export interface HmacSignalBundle {
  userAgent: string;
  acceptLanguage: string;
  secureContext: boolean;
}

export function collectSignals(headers: Record<string, string | string[] | undefined>): HmacSignalBundle {
  return {
    userAgent: (headers["user-agent"] as string) ?? "",
    acceptLanguage: (headers["accept-language"] as string) ?? "",
    secureContext: (headers["x-forwarded-proto"] as string) === "https",
  };
}

function serializeSignals(bundle: HmacSignalBundle): string {
  return [bundle.userAgent, bundle.acceptLanguage, String(bundle.secureContext)].join(
    SIGNAL_SEPARATOR,
  );
}

export function generateHmacToken(signals: HmacSignalBundle, secret: Buffer): string {
  const nonce = randomBytes(16).toString("base64url");
  const data = `${nonce}${SIGNAL_SEPARATOR}${serializeSignals(signals)}`;
  const mac = createHmac("sha256", secret).update(data).digest("base64url");
  return `${nonce}.${mac}`;
}

export function verifyHmacToken(
  token: string,
  signals: HmacSignalBundle,
  secret: Buffer,
): boolean {
  const dot = token.indexOf(".");
  if (dot === -1) return false;

  const nonce = token.slice(0, dot);
  const providedMac = token.slice(dot + 1);

  const data = `${nonce}${SIGNAL_SEPARATOR}${serializeSignals(signals)}`;
  const expectedMac = createHmac("sha256", secret).update(data).digest("base64url");

  try {
    return timingSafeEqual(Buffer.from(providedMac), Buffer.from(expectedMac));
  } catch {
    return false;
  }
}
