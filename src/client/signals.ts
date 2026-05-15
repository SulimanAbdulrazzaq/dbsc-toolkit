// Signal collection for the HMAC fallback tier.
// This is NOT hardware binding. It is best-effort context binding.
// Operators using this tier must review GDPR obligations for signal collection.

export interface ClientSignals {
  userAgent: string;
  acceptLanguage: string;
  secureContext: boolean;
  screenDepth: number;
  timezone: string;
}

export function collectClientSignals(): ClientSignals {
  return {
    userAgent: navigator.userAgent,
    acceptLanguage: navigator.language,
    secureContext: window.isSecureContext,
    screenDepth: screen.colorDepth,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  };
}
