import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type VerifiedRegistrationResponse,
  type VerifyAuthenticationResponseOpts,
} from "@simplewebauthn/server";

export interface WebAuthnRegistrationChallenge {
  options: Awaited<ReturnType<typeof generateRegistrationOptions>>;
  challenge: string;
}

export async function generateWebAuthnRegistration(
  rpName: string,
  rpId: string,
  userId: string,
  userName: string,
): Promise<WebAuthnRegistrationChallenge> {
  const opts: GenerateRegistrationOptionsOpts = {
    rpName,
    rpID: rpId,
    userID: new TextEncoder().encode(userId),
    userName,
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "preferred",
    },
    attestationType: "none",
  };

  const options = await generateRegistrationOptions(opts);
  return {
    options,
    challenge: options.challenge,
  };
}

export async function verifyWebAuthnRegistration(
  response: Parameters<typeof verifyRegistrationResponse>[0]["response"],
  expectedChallenge: string,
  expectedOrigin: string,
  rpId: string,
): Promise<VerifiedRegistrationResponse> {
  return verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID: rpId,
  });
}

export async function generateWebAuthnAuthentication(
  rpId: string,
  allowedCredentialIds: string[],
): Promise<Awaited<ReturnType<typeof generateAuthenticationOptions>>> {
  return generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: allowedCredentialIds.map((id) => ({
      id,
      transports: ["internal"],
    })),
    userVerification: "preferred",
  });
}

export async function verifyWebAuthnAuthentication(
  opts: VerifyAuthenticationResponseOpts,
): Promise<Awaited<ReturnType<typeof verifyAuthenticationResponse>>> {
  return verifyAuthenticationResponse(opts);
}
