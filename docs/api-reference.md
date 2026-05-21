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
type ProtectionTier = "dbsc" | "bound" | "none";

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
interface TierChangeEvent { type: "tier_change"; sessionId; tier; timestamp; from; to; reason }

type AnyTelemetryEvent = RegistrationEvent | RefreshEvent | VerificationFailureEvent | SessionStolenEvent | TierChangeEvent;
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

`buildChallengeHeader` takes an optional `sessionId` that becomes a `;id="..."` parameter on the header value. Chromium 145+ requires it on `Secure-Session-Challenge` responses or it silently drops the challenge.

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

### Bound polyfill (server side)

```ts
interface BoundRegistrationRequest {
  sessionId: string;
  publicKey: JsonWebKey;
  signature: string;        // base64url ECDSA P-256 signature over the JTI bytes
  expectedJti: string;
}
function handleBoundRegistration(req: BoundRegistrationRequest, storage: StorageAdapter): Promise<{ boundKey: BoundKey }>;

interface BoundRefreshRequest {
  sessionId: string;
  signature: string;        // base64url ECDSA P-256 signature over `${jti}.${timestamp}`
  expectedJti: string;
  timestamp: number;        // must be within ±60s of server time
}
function handleBoundRefresh(req: BoundRefreshRequest, storage: StorageAdapter): Promise<RefreshProof>;

// Web Crypto signature verification helper used by both handlers, exposed for adapters.
function verifyP256Signature(jwk: JsonWebKey, signatureB64Url: string, message: string): Promise<boolean>;

// Per-request signing — see docs/per-request-signing.md.
// Throws DbscVerificationError on any failure; the caller decides the HTTP status.
const BOUND_PROOF_HEADER = "X-Dbsc-Bound-Proof";
interface VerifyBoundProofRequest {
  sessionId: string;
  proofHeader: string | undefined;
  method: string;
  path: string;
  timestampWindowMs?: number;   // default 5 * 60 * 1000
}
function verifyBoundProof(req: VerifyBoundProofRequest, storage: StorageAdapter): Promise<void>;
function parseProofHeader(s: string): { ts: number; sig: string } | null;
```

The bound polyfill protocol is documented in [bound-polyfill.md](./bound-polyfill.md). The per-request signing flow that closes the bound-tier ride-along gap is documented in [per-request-signing.md](./per-request-signing.md). New `ErrorCodes` entries: `MISSING_PROOF`, `MALFORMED_PROOF`.

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

// Per-request signing gate for sensitive routes — see docs/per-request-signing.md.
interface RequireBoundProofOptions {
  storage: StorageAdapter;
  allowDbscWithoutProof?: boolean;   // default true — tier=dbsc passes through
  timestampWindowMs?: number;        // default 5 * 60 * 1000
  signBody?: boolean;                // default false — when true, verifies bh=sha256(body) for tier=bound only (2.3.0+).
                                     // tier=dbsc still passes through unless allowDbscWithoutProof is set to false.
}
function requireBoundProof(opts: RequireBoundProofOptions): RequestHandler;
```

After mount, every request has `res.locals.dbsc` populated. Call `bindSession` once on your login response to start a new binding — it writes the session row, issues a challenge, sets both registration headers (legacy + new), and sets the two short-lived cookies Chrome needs.

`requireBoundProof()` gates sensitive routes on a fresh proof signed by the bound key — pair it with `wrapFetch()` on the client. Native DBSC users pass through by default. The same `RequireBoundProofOptions` shape is used by every adapter; the wrapper just changes return type to match each framework's middleware idiom (Fastify returns a `preHandler`, Hono a `MiddlewareHandler`, Next.js a handler-callable that returns `{ ok }` or a short-circuit response).

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

Read everything as `c.get("dbsc")` — a single object matching the Express/Fastify shape. The legacy keys (`dbscSessionId`, `dbscTier`, `dbscSkipped`) that existed in 1.x were removed in 2.0.0; use the unified object only.

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

Browser-side SDK for the bound polyfill. Load on every page that needs `tier: "bound"` on non-Chromium browsers; Chromium 145+ users see no effect (the SDK detects the native binding and steps back).

```ts
interface InitBoundDbscOptions {
  statePath?: string;             // default "/dbsc-bound/state"
  challengePath?: string;         // default "/dbsc-bound/challenge"
  registrationPath?: string;      // default "/dbsc-bound/registration"
  refreshPath?: string;           // default "/dbsc-bound/refresh"
  nativeProbeWindowMs?: number;   // default 5000 — how long to wait for native DBSC before polyfilling
  pollIntervalMs?: number;        // default 1000 — active poll cadence during the probe window. Min 250
  refreshMarginMs?: number;       // default 5000 — refresh this many ms before the bound cookie expires
}

// Returns a structured outcome (2.2.0+). Awaiters that previously discarded
// the void return value continue to work; type-strict consumers that declared
// `Promise<void>` will need to update.
type BoundDbscOutcome =
  | { phase: "native-dbsc"; tier: "dbsc" }
  | { phase: "polyfill-bound"; tier: "bound"; skipReason?: string }
  | { phase: "unbound" }
  | { phase: "error"; error: string };

function initBoundDbsc(options?: InitBoundDbscOptions): Promise<BoundDbscOutcome>;
function stopBoundDbsc(): void;

// Drops the IndexedDB key record. Call after logout (2.3.0+).
function clearBoundKey(): Promise<void>;

// Per-request signing for sensitive routes — see docs/per-request-signing.md.
// Returns a NEW fetch-shaped function. Do not assign to globalThis.fetch.
interface WrapFetchOptions {
  fetch?: typeof fetch;
  headerName?: string;            // default "X-Dbsc-Bound-Proof"
  signBody?: boolean;             // default false — when true, adds bh=sha256(body) (2.3.0+)
}
function wrapFetch(options?: WrapFetchOptions): typeof fetch;
```

Typical use:

```html
<script type="module">
  import { initBoundDbsc } from "/dbsc-client/index.js";
  initBoundDbsc();
</script>
```

See [bound-polyfill.md](./bound-polyfill.md) for the wire protocol and threat coverage.

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
