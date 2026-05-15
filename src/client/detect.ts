export type ClientTier = "dbsc" | "webauthn" | "hmac" | "none";

export async function detectClientTier(): Promise<ClientTier> {
  // DBSC is browser-native; Chrome 146+ handles it automatically via HTTP headers.
  // No JS detection is needed for the DBSC path — the browser drives it.
  // This SDK only handles the fallback paths.

  if (typeof window === "undefined") return "none";

  if (
    window.PublicKeyCredential &&
    typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
  ) {
    try {
      const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (available) return "webauthn";
    } catch {
      // platform check failed, fall through to hmac
    }
  }

  return "hmac";
}
