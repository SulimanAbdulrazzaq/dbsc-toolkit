# API reference

Every public export across all subpaths.

## Subpaths

| Import | Module |
|--------|--------|
| `dbsc-toolkit` | Core: types, crypto, protocol, fallback, telemetry |
| `dbsc-toolkit/express` | Express middleware |
| `dbsc-toolkit/fastify` | Fastify plugin |
| `dbsc-toolkit/hono` | Hono middleware |
| `dbsc-toolkit/nextjs` | Next.js middleware + `getDbscSession` |
| `dbsc-toolkit/client` | Browser SDK |
| `dbsc-toolkit/storage/memory` | `MemoryStorage` |
| `dbsc-toolkit/storage/redis` | `RedisStorage` |
| `dbsc-toolkit/storage/postgres` | `PostgresStorage` |

---

## `dbsc-toolkit` (core)

### Types

```ts
type ProtectionTier = "dbsc" | "webauthn" | "hmac" | "none";

interface Session {
  id: string;
  userId: string;
  tier: ProtectionTier;
  createdAt: number;
  expiresAt: number;
  lastRefreshAt: number;
}

interface BoundKey {
  sessionId: string;
  jwk: JsonWebKey;
  createdAt: number;
  algorithm: "ES256" | "RS256";
}

interface Challenge {
  jti: string;
  sessionId: string;
  createdAt: number;
  expiresAt: number;
  consumed: boolean;
}

interface RegistrationProof {
  sessionId: string;
  jwk: JsonWebKey;
  algorithm: "ES256" | "RS256";
  jti: string;
}

interface RefreshProof {
  sessionId: string;
  jti: string;
  verified: boolean;
}

interface StorageAdapter {
  getSession(id: string): Promise<Session | null>;
  setSession(session: Session): Promise<void>;
  deleteSession(id: string): Promise<void>;
  getBoundKey(sessionId: string): Promise<BoundKey | null>;
  setBoundKey(key: BoundKey): Promise<void>;
  deleteBoundKey(sessionId: string): Promise<void>;
  getChallenge(jti: string): Promise<Challenge | null>;
  setChallenge(challenge: Challenge): Promise<void>;
  consumeChallenge(jti: string): Promise<boolean>;
  revokeSession(sessionId: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
}

interface RateLimiter {
  checkRegistration(ip: string): Promise<boolean>;
  checkRefresh(ip: string, sessionId: string): Promise<boolean>;
  recordFailure(ip: string, sessionId?: string): Promise<void>;
}

interface DbscOptions {
  storage: StorageAdapter;
  registrationPath?: string;        // default "/dbsc/registration"
  refreshPath?: string;             // default "/dbsc/refresh"
  boundCookieTtl?: number;          // default 600000 (10 min, in ms)
  registrationCookieTtl?: number;   // default 86400000 (24h, in ms)
  rateLimiter?: RateLimiter;
  onEvent?: (event: AnyTelemetryEvent) => void;
  autoBind?: (req: any) => Promise<AutoBindResult | null> | AutoBindResult | null;
}

interface AutoBindResult {
  sessionId: string;
  userId: string;
}
```

`autoBind` is the transparent-migration hook. The middleware calls it on every request that does not carry the bound cookie yet, passing the framework-native request. Return a `{ sessionId, userId }` to start binding, or `null` to skip. See [integrating-existing-auth.md](./integrating-existing-auth.md).

### Telemetry events

```ts
interface RegistrationEvent { type: "registration"; sessionId; tier; timestamp; algorithm; ip }
interface RefreshEvent { type: "refresh"; sessionId; tier; timestamp; ip }
interface VerificationFailureEvent { type: "verification_failure"; sessionId; tier; timestamp; reason; ip }
interface SessionStolenEvent { type: "session_stolen"; sessionId; tier; timestamp; ip }
interface FallbackTierEvent { type: "fallback_tier"; sessionId; tier; timestamp; from; to; reason }

type AnyTelemetryEvent = RegistrationEvent | RefreshEvent | VerificationFailureEvent | SessionStolenEvent | FallbackTierEvent;
```

### Errors

```ts
class DbscProtocolError extends Error { code: string }
class DbscVerificationError extends Error { code: string }
class DbscStorageError extends Error { code: string }

const ErrorCodes: {
  MISSING_RESPONSE_HEADER: string;
  CHALLENGE_NOT_FOUND: string;
  CHALLENGE_CONSUMED: string;
  CHALLENGE_EXPIRED: string;
  JTI_MISMATCH: string;
  KEY_NOT_FOUND: string;
  MALFORMED_JWS: string;
  UNKNOWN_ALGORITHM: string;
  INVALID_JWK: string;
  SIGNATURE_INVALID: string;
};
```

### Header constants and helpers

```ts
const REGISTRATION_HEADER: "Secure-Session-Registration";
const RESPONSE_HEADER: "Secure-Session-Response";
const CHALLENGE_HEADER: "Secure-Session-Challenge";
const LEGACY_REGISTRATION_HEADER: "Sec-Session-Registration";
const LEGACY_RESPONSE_HEADER: "Sec-Session-Response";
const LEGACY_CHALLENGE_HEADER: "Sec-Session-Challenge";

interface RegistrationHeaderOptions {
  algorithm?: "ES256" | "RS256";
  refreshPath: string;
  challenge: string;
  cookieName?: string;
}
function buildRegistrationHeader(opts: RegistrationHeaderOptions): string;
function buildChallengeHeader(jti: string, sessionId?: string): string;
function parseSessionResponseHeader(raw: string): string;
function buildSessionIdCookie(sessionId: string, opts: { secure: boolean; sameSite: string }): string;
function readSessionResponseHeader(headers: Record<string, string | string[] | undefined>): string | undefined;

const SKIPPED_HEADER: "Secure-Session-Skipped";
const LEGACY_SKIPPED_HEADER: "Sec-Session-Skipped";

type SkippedReason = "unreachable" | "server_error" | "quota_exceeded";
interface SkippedEntry { reason: SkippedReason; sessionId?: string }
function parseSessionSkippedHeader(headers: Record<string, string | string[] | undefined>): SkippedEntry[];
```

`buildChallengeHeader` takes an optional `sessionId` that becomes a `;id="..."` parameter on the header value. Chrome 147+ requires it on `Secure-Session-Challenge` responses or it silently drops the challenge.

`parseSessionSkippedHeader` reads the browser's diagnostic header that explains why a request arrived without the bound credential. See [troubleshooting.md](./troubleshooting.md) for what each reason means.

### Protocol functions

```ts
function handleRegistration(
  req: { sessionId: string; secSessionResponseHeader: string | undefined; expectedJti: string },
  storage: StorageAdapter
): Promise<{ boundKey: BoundKey }>;

function handleRefresh(
  req: { sessionId: string; secSessionResponseHeader: string | undefined; expectedJti: string },
  storage: StorageAdapter
): Promise<RefreshProof>;

function generateJti(): string;
function issueChallenge(sessionId: string, storage: StorageAdapter, ttlMs?: number): Promise<Challenge>;
```

### Crypto

```ts
function validateJwk(jwk: JsonWebKey): void;
function detectAlgorithm(jwk: JsonWebKey): "ES256" | "RS256";

function verifyDbscJws(token: string, storedJwk: JsonWebKey, expectedJti: string): Promise<DbscJwsClaims>;
function parseRegistrationJws(token: string): Promise<{ claims; jwk; algorithm }>;
```

### Fallback

```ts
function negotiateTier(req: { headers: Record<string, string | string[] | undefined> }): ProtectionTier;
function detectDbscSupport(headers: Record<string, string | string[] | undefined>): boolean;

// WebAuthn (server-side helpers wrapping @simplewebauthn/server)
function generateWebAuthnRegistration(opts): Promise<RegistrationOptions>;
function verifyWebAuthnRegistration(opts): Promise<boolean>;
function generateWebAuthnAuthentication(opts): Promise<AuthenticationOptions>;
function verifyWebAuthnAuthentication(opts): Promise<boolean>;

// HMAC tier
function collectSignals(headers: Record<string, string | string[] | undefined>): SignalBundle;
function generateHmacToken(signals: SignalBundle, secret: Uint8Array): string;
function verifyHmacToken(token: string, signals: SignalBundle, secret: Uint8Array): boolean;
```

### Telemetry

```ts
function emit(handler: ((event: AnyTelemetryEvent) => void) | undefined, event: AnyTelemetryEvent): void;
```

### Rate limiter

```ts
class NoopRateLimiter implements RateLimiter {
  checkRegistration(): Promise<true>;
  checkRefresh(): Promise<true>;
  recordFailure(): Promise<void>;
}
```

---

## `dbsc-toolkit/express`

```ts
interface DbscExpressOptions extends DbscOptions {
  secure?: boolean;  // default true (forces __Host- prefix and Secure flag)
}

interface DbscLocals {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

declare global {
  namespace Express {
    interface Locals { dbsc: DbscLocals }
  }
}

function dbsc(opts: DbscExpressOptions): RequestHandler;

interface BindSessionOptions {
  userId: string;
  secure?: boolean;
  registrationPath?: string;
  registrationCookieTtl?: number;
  sessionTtl?: number;
}
function bindSession(
  res: Response,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void>;
```

After mount, every request has `res.locals.dbsc` populated. Call `bindSession` once on your login response to start a new binding — it writes the session row, issues a challenge, sets both registration headers (legacy + new), and sets the two short-lived cookies Chrome needs.

---

## `dbsc-toolkit/fastify`

```ts
interface DbscFastifyOptions extends DbscOptions {
  secure?: boolean;
}

declare module "fastify" {
  interface FastifyRequest {
    dbsc: {
      sessionId: string | null;
      tier: ProtectionTier;
      skipped: SkippedEntry[];
      revoke(): Promise<void>;
    };
  }
}

const dbsc: FastifyPluginAsync<DbscFastifyOptions>;

function bindSession(
  reply: FastifyReply,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void>;
```

Register with `await fastify.register(dbsc, { storage })`. `registrationCookieTtl` is honored as of 1.4.0.

---

## `dbsc-toolkit/hono`

```ts
interface DbscHonoOptions extends DbscOptions {
  secure?: boolean;
}

interface DbscHonoSession {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

declare module "hono" {
  interface ContextVariableMap {
    dbsc: DbscHonoSession;
    /** @deprecated read c.get("dbsc").sessionId. Removed in 2.0.0. */
    dbscSessionId: string | null;
    /** @deprecated read c.get("dbsc").tier. Removed in 2.0.0. */
    dbscTier: ProtectionTier;
    /** @deprecated read c.get("dbsc").skipped. Removed in 2.0.0. */
    dbscSkipped: SkippedEntry[];
  }
}

function dbsc(opts: DbscHonoOptions): MiddlewareHandler;

function bindSession(
  c: Context,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void>;
```

Read everything as `c.get("dbsc")` — a single object matching the Express/Fastify shape. The three legacy keys (`dbscSessionId`, `dbscTier`, `dbscSkipped`) still resolve in 1.x for back-compat and will be removed in 2.0.0. `registrationCookieTtl` is honored as of 1.4.0.

---

## `dbsc-toolkit/nextjs`

```ts
interface DbscNextOptions extends DbscOptions {
  secure?: boolean;
}

interface DbscSessionInfo {
  sessionId: string | null;
  tier: ProtectionTier;
  skipped: SkippedEntry[];
  revoke: () => Promise<void>;
}

function createDbscMiddleware(opts: DbscNextOptions): (req: NextRequest) => Promise<NextResponse>;

function getDbscSession(
  req: NextRequest,
  storage: StorageAdapter,
  opts?: { boundCookieTtl?: number; res?: NextResponse; secure?: boolean },
): Promise<DbscSessionInfo>;

function bindSession(
  res: NextResponse,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void>;
```

Export `createDbscMiddleware` from `middleware.ts` for the App Router. Use `getDbscSession` inside route handlers. Pass `res` if you want `revoke()` to clear the cookie for you; otherwise it only deletes the server-side session and you clear cookies yourself.

---

## `dbsc-toolkit/client`

Browser-side SDK for fallback tiers. Chrome with native DBSC does not need this.

```ts
function detectClientTier(): Promise<"dbsc" | "webauthn" | "hmac">;
function registerWebAuthn(opts): Promise<Credential>;
function authenticateWebAuthn(opts): Promise<AuthenticationResponseJSON>;
function collectClientSignals(): SignalBundle;
```

---

## `dbsc-toolkit/storage/memory`

```ts
class MemoryStorage implements StorageAdapter {
  // Map-based, periodic TTL sweep, dev/test only
}
```

No constructor arguments. Lives in process memory only.

---

## `dbsc-toolkit/storage/redis`

```ts
class RedisStorage implements StorageAdapter {
  constructor(redis: Redis | Cluster, opts?: { keyPrefix?: string });
}
```

`redis` is an `ioredis` instance. The adapter uses Lua scripts for atomic challenge consume.

---

## `dbsc-toolkit/storage/postgres`

```ts
class PostgresStorage implements StorageAdapter {
  constructor(pool: Pool);
  runMigrations(): Promise<void>;
}
```

Run the included migration once before first use:

```sh
psql $DATABASE_URL < node_modules/dbsc-toolkit/migrations/001_initial.sql
```
