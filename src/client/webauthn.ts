import { startRegistration, startAuthentication } from "@simplewebauthn/browser";

export async function registerWebAuthn(options: unknown): Promise<unknown> {
  return startRegistration(options as Parameters<typeof startRegistration>[0]);
}

export async function authenticateWebAuthn(options: unknown): Promise<unknown> {
  return startAuthentication(options as Parameters<typeof startAuthentication>[0]);
}
