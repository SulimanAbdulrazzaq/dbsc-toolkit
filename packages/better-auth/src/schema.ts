/**
 * Better Auth schema extension for dbsc-toolkit.
 *
 * Defines two tables:
 *   dbscSession  — tracks binding state (tier, lastRefreshAt) per session
 *   dbscBoundKey — stores the JWK for native (TPM) and bound (polyfill) keys
 *
 * Challenges are stored in Better Auth's built-in `verification` table
 * so we get atomic consumeVerificationValue for free.
 */
export const dbscSchema = {
  dbscSession: {
    fields: {
      userId: {
        type: "string" as const,
        required: true,
        references: { model: "user", field: "id" },
      },
      tier: {
        type: "string" as const,
        required: true,
        // "dbsc" | "bound" | "none"
      },
      createdAt: {
        type: "number" as const,
        required: true,
      },
      expiresAt: {
        type: "number" as const,
        required: true,
      },
      lastRefreshAt: {
        type: "number" as const,
        required: true,
      },
    },
  },
  dbscBoundKey: {
    fields: {
      sessionId: {
        type: "string" as const,
        required: true,
        references: { model: "dbscSession", field: "id" },
      },
      kind: {
        type: "string" as const,
        required: true,
        // "native" | "bound"
      },
      jwk: {
        type: "string" as const,
        required: true,
        // JSON-serialized JWK — stored as text, never logged
      },
      createdAt: {
        type: "number" as const,
        required: true,
      },
      algorithm: {
        type: "string" as const,
        required: true,
        // "ES256" | "RS256"
      },
    },
  },
} as const;
