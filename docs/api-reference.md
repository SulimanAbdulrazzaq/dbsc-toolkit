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
| `dbsc-toolkit/nestjs` | NestJS `DbscModule` + `DbscGuard` + `DbscService` |
| `dbsc-toolkit/koa` | Koa middleware |
| `dbsc-toolkit/sveltekit` | SvelteKit `dbscHandle` hook + `requireProof` |
| `dbsc-toolkit/node` | Generic raw `node:http` handler |
| `dbsc-toolkit/dpop` | Optional DPoP (RFC 9449): `verifyDpopProof`, `dpopConfirmation`, `jwkThumbprint` |
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

type BoundKeyKind = "native" | "bound";   // v2.7+: a session can hold both

interface BoundKey {
  sessionId: string;
  kind: BoundKeyKind;     // "native" = TPM (used by /dbsc/refresh);
                          // "bound"  = polyfill ECDSA (used by requireProof + /dbsc-bound/refresh)
  jwk: JsonWebKey;
  createdAt: number;
  algorithm: "ES256" | "RS256";
}

interface StorageAdapter {
  getSession(id: string): Promise<Session | null>;
  setSession(session: Session): Promise<void>;
  deleteSession(id: string): Promise<void>;
  getBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<BoundKey | null>;
  setBoundKey(key: BoundKey): Promise<void>;
  deleteBoundKey(sessionId: string, kind?: BoundKeyKind): Promise<void>;
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

// v2.8+
interface ProofReplayCache {
  /** Returns true if first sighting (allow), false on replay (reject). */
  checkAndRecord(key: string, ttlMs: number): Promise<boolean>;
}

interface DbscOptions {
  storage: StorageAdapter;
  registrationPath?: string;        // default "/dbsc/registration"
  refreshPath?: string;             // default "/dbsc/refresh"
  bound?: boolean;                  // default true — false runs native DBSC only (see below)
  boundCookieTtl?: number;          // default 600000 (10 min, in ms)
  registrationCookieTtl?: number;   // default 86400000 (24h, in ms)
  refreshGraceMs?: number;          // default 30000 — see below (2.5.0+)
  cookieScope?: "host" | "site";    // default "host" — "site" enables multi-subdomain (2.9.0+)
  cookieDomain?: string;            // required when cookieScope: "site" (2.9.0+)
  rateLimiter?: RateLimiter;
  replayCache?: ProofReplayCache;   // v2.8+; default NoopReplayCache (no replay check)
  onEvent?: (event: AnyTelemetryEvent) => void;
  autoBind?: (req: any) => Promise<AutoBindResult | null> | AutoBindResult | null;
}

interface AutoBindResult {
  sessionId: string;
  userId: string;
}
```

`bound` (default `true`) toggles the Web Crypto polyfill. Set `false` to run native DBSC only (Chromium 145+): the `/dbsc-bound/challenge`, `/dbsc-bound/registration`, and `/dbsc-bound/refresh` routes are not mounted (`/dbsc-bound/state` still answers `phase: "unbound"` so a loaded client SDK stands down), non-Chromium browsers stay at `tier: "none"`, and `requireProof()` auto-relaxes so a native `dbsc`-tier session passes without a per-request bound proof. Use it only when you can mandate a Chromium build with a hardware key store; for general-audience apps the polyfill is what covers Firefox / Safari. See [bound-polyfill.md](./bound-polyfill.md#disabling-the-polyfill-bound-false).

`autoBind` is the transparent-migration hook. The middleware calls it on every request that does not carry the bound cookie yet, passing the framework-native request. Return a `{ sessionId, userId }` to start binding, or `null` to skip. See [integrating-existing-auth.md](./integrating-existing-auth.md).

`refreshGraceMs` (2.5.0+) extends the freshness check. A bound cookie's freshness lapses at `lastRefreshAt + boundCookieTtl`, but the browser's next `/dbsc/refresh` lands a short moment later — during that gap a `/me`-style poll would see `tier: "none"`. The middleware keeps the previous tier until `lastRefreshAt + boundCookieTtl + refreshGraceMs`. Default 30000 ms. Set `0` to demote the instant freshness lapses (use on routes that tolerate no grace).

`cookieScope` (2.9.0+) picks the cookie-prefix model. `"host"` (default) keeps the `__Host-` prefix — origin-locked, no `Domain` attribute, strongest. `"site"` switches to `__Secure-` and emits `Domain=<cookieDomain>`, so an app spread across `app.example.com` and `api.example.com` can share one binding. `"site"` requires `cookieDomain` (the registrable apex, no leading dot) and `secure: true`; passing either wrong throws at `dbsc()` / `createDbsc()` construction so the misconfiguration cannot reach a request. `__Secure-` cookies do not carry `__Host-`'s protection against a sibling subdomain setting or overwriting the cookie — prefer host scope when a same-origin deployment (or proxying `/dbsc/*` + `/dbsc-bound/*` through one origin) is workable. See [integration-recipes.md](./integration-recipes.md#multi-subdomain-cookiescope-site).

### Cookie-scope helpers (for adapter authors)

```ts
export type CookieScope = "host" | "site";

interface CookieScopeOptions {
  secure: boolean;
  cookieScope?: CookieScope;
  cookieDomain?: string;
}

interface CookieScopeResolved {
  hostPrefix: boolean;       // true when __Host- is in effect
  prefix: "__Host-" | "__Secure-" | "";
  domain: string | undefined;
}

function resolveCookieScope(opts: CookieScopeOptions): CookieScopeResolved;
function resolveCookieNames(opts: CookieScopeOptions): {
  bound: string; reg: string; challenge: string;
};
function deviceCookieName(opts: CookieScopeOptions): string;
function cookieAttributesString(opts: CookieScopeOptions): string;
```

Used internally by all four shipped adapters. Export surface for anyone writing a fifth — see [adapters.md](./adapters.md) "Writing your own adapter". `resolveCookieScope` is the validator: it throws when `"site"` is set without `cookieDomain`, with `secure: false`, with a leading-dot domain, or when a domain is given under host scope. Run it once at construction so the failure mode is loud, not silent at request time.

### `deriveSessionId`

```ts
interface DeriveSessionIdInput {
  userId: string;        // stable user id — the JWT `sub` claim is the canonical choice
  deviceHint?: string;   // optional — distinct value per device for separate bindings
  namespace?: string;    // optional — defaults to "default"
}
function deriveSessionId(input: DeriveSessionIdInput): Promise<string>;
```

Produces a stable, deterministic, opaque `sessionId` for `bindSession()` when the caller has no server-side session row to take an id from — JWT-mode NextAuth, iron-session, Lucia stateless, raw JWT cookies. Same input always returns the same id. SHA-256 of `${namespace}.${userId}.${deviceHint ?? ""}`, base64url-encoded.

**`deviceHint` matters for multi-device users.** Without it, the same `userId` always derives the same id — so a user on two browsers collides on one binding, and the second browser fails to register. Pass a per-device value as `deviceHint`. You normally don't call `deriveSessionId` directly: the `createDbsc` kit's `bind(res, { userId })` does it for you and **auto-manages a `__Host-dbsc-device` cookie** as the `deviceHint`, so each browser binds independently with no extra code. See [integration-recipes.md](./integration-recipes.md).

### Route protection

```ts
interface RequireProofOptions {
  allowDbscWithoutProof?: boolean;  // v2.7+ default: false — every tier must carry a proof header
  timestampWindowMs?: number;       // accepted proof timestamp window, ms
  storage?: StorageAdapter;         // override; default = the adapter's storage
}

function noBindingReason(skipped?: SkippedEntry[]): string;
```

`allowDbscWithoutProof` defaults to `false` as of v2.7 — Chromium sessions
register a polyfill key alongside the TPM key on first init, so the per-request
proof works the same way on every tier. Set this to `true` only if your
Chromium client cannot ship the v2.7 client SDK (then the legacy v2.6
behavior is restored, with the refresh-cycle replay window — see CHANGELOG).

`RequireProofOptions` is the (entirely optional) option shape of every adapter's `requireProof()`. `noBindingReason` produces the quota-aware human reason used in a `tier: "none"` rejection — exported for custom adapters.

### Cookie parsing

```ts
function parseCookieHeader(header?: string | null): Record<string, string>;
```

Parses a `Cookie` request header into a name→value map. The Express middleware uses this so it no longer needs `cookie-parser`. Useful when writing your own adapter.

### Telemetry events

```ts
interface RegistrationEvent { type: "registration"; sessionId; tier; timestamp; algorithm; ip }
interface RefreshEvent { type: "refresh"; sessionId; tier; timestamp; ip }
interface VerificationFailureEvent { type: "verification_failure"; sessionId; tier; timestamp; reason; ip }
interface SessionStolenEvent { type: "session_stolen"; sessionId; tier; timestamp; ip }
interface TierChangeEvent { type: "tier_change"; sessionId; tier; timestamp; from; to; reason }
// v2.8+: a Chromium session has held a "native" key past the grace window
// (60s default) without registering its "bound" polyfill key. Fires once per
// session per server-process restart. The session reads tier: "dbsc" but
// every requireProof() call 403s — a degraded state worth alerting on.
interface PolyfillMissingEvent { type: "polyfill_missing"; sessionId; tier: "dbsc"; timestamp; ip }

type AnyTelemetryEvent =
  | RegistrationEvent
  | RefreshEvent
  | VerificationFailureEvent
  | SessionStolenEvent
  | TierChangeEvent
  | PolyfillMissingEvent;
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
  KEY_NOT_FOUND: string;                 // legacy, retained for back-compat
  KEY_NOT_FOUND_NATIVE: string;          // v2.8+: missing TPM key (storage wipe)
  KEY_NOT_FOUND_BOUND: string;           // v2.8+: missing polyfill key (client re-init)
  MALFORMED_JWS: string;
  UNKNOWN_ALGORITHM: string;
  INVALID_JWK: string;
  SIGNATURE_INVALID: string;
  SESSION_NOT_FOUND: string;
  SESSION_ALREADY_REGISTERED: string;
  RATE_LIMITED: string;
  MISSING_PROOF: string;                 // requireProof + no X-Dbsc-Bound-Proof header
  MALFORMED_PROOF: string;
  PROOF_REPLAY: string;                  // v2.8+: replay cache rejected a second arrival
};
```

`KEY_NOT_FOUND` is kept for any consumer pinned to it. v2.8 throw sites use the kind-specific codes: `KEY_NOT_FOUND_NATIVE` from `/dbsc/refresh` (the TPM-key row is missing — usually a storage wipe; the user has to restart from `/login`) and `KEY_NOT_FOUND_BOUND` from `requireProof()` / `/dbsc-bound/refresh` (the polyfill-key row is missing — the client SDK can re-init via `initBoundDbsc()` without a full logout).

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
  registrationPath?: string;         // path where the browser POSTs the registration JWS
  /** @deprecated misnamed alias for registrationPath; kept for back-compat */
  refreshPath?: string;
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

`buildChallengeHeader` takes an optional `sessionId` that becomes a `;id="..."` parameter on the header value. Chromium 146+ requires it on `Secure-Session-Challenge` responses or it silently drops the challenge.

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

The bound polyfill protocol is documented in [bound-polyfill.md](./bound-polyfill.md). The per-request signing flow is documented in [per-request-signing.md](./per-request-signing.md). `ErrorCodes` entries added across releases: `MISSING_PROOF`, `MALFORMED_PROOF` (v2.1.0+), `PROOF_REPLAY`, `KEY_NOT_FOUND_NATIVE`, `KEY_NOT_FOUND_BOUND` (v2.8+).

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

## `dbsc-toolkit/dpop` (optional)

Optional DPoP (RFC 9449) layer for binding bearer/access tokens to a device key.
Off the default import path. Per-adapter `requireDpop` guards live on each
adapter subpath; the core verification surface is here.

```ts
function verifyDpopProof(req: VerifyDpopProofRequest): Promise<DpopVerifyResult>;

interface VerifyDpopProofRequest {
  proof: string | undefined;          // the DPoP header value
  method: string;                     // actual request method
  url: string;                        // actual absolute request URL
  accessToken?: string;               // bearer, when binding a token
  boundJkt?: string;                  // the token's cnf.jkt
  requireTokenBinding?: boolean;      // default true — reject an unbound presented token
  iatWindowMs?: number;               // default 300000
  replayCache?: ProofReplayCache;     // jti store (reuses the DBSC cache)
}
interface DpopVerifyResult { jkt: string; jti: string; payload: JWTPayload; }

// Bind a token at issue time: embed { cnf: { jkt } } in the token.
function dpopConfirmation(jwk: JsonWebKey): Promise<{ jkt: string }>;

// RFC 7638 JWK thumbprint, and the ath claim hash.
function jwkThumbprint(jwk: JsonWebKey): Promise<string>;
function accessTokenHash(token: string): Promise<string>;

// htu normalization, exposed for testing / custom guards.
function normalizeHtu(uri: string): string;
function htuMatches(claimed: string, requestUrl: string): boolean;

// Adapter-neutral guard core + the WWW-Authenticate value.
function runDpopGuard(input: DpopGuardInput): Promise<DpopGuardOutcome>;
function parseDpopAuthorization(authorization?: string): string | undefined;
const DPOP_WWW_AUTHENTICATE: string;  // 'DPoP error="invalid_dpop_proof"'

interface RequireDpopOptions<Req = unknown> {
  getBoundJkt?: (req: Req) => string | undefined | Promise<string | undefined>;
  requireTokenBinding?: boolean;
  iatWindowMs?: number;
  replayCache?: ProofReplayCache;
}
```

Every adapter exports `requireDpop(opts?: RequireDpopOptions<AdapterReq>)`
(NestJS: `createDbscDpopGuard(opts)`). A failed check answers **401** with
`WWW-Authenticate: DPoP`. New error codes (`DPOP_*`) are added to `ErrorCodes`.
See [dpop.md](./dpop.md) and [spec/10-dpop.md](../spec/10-dpop.md).

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
  allowDbscWithoutProof?: boolean;   // v2.7+ default: false — every tier must prove
  timestampWindowMs?: number;        // default 5 * 60 * 1000
  signBody?: boolean;                // default false — when true, verifies bh=sha256(body) on every tier
}
function requireBoundProof(opts: RequireBoundProofOptions): RequestHandler;
```

After mount, every request has `res.locals.dbsc` populated. Call `bindSession` once on your login response to start a new binding — it writes the session row, issues a challenge, sets both registration headers (legacy + new), and sets the two short-lived cookies Chrome needs.

`requireBoundProof()` gates sensitive routes on a fresh proof signed by the bound key — pair it with `wrapFetch()` on the client. As of v2.7 every tier must carry a proof header, including Chromium: the client SDK now co-registers a polyfill ECDSA key on Chromium sessions alongside the TPM key, and `wrapFetch` signs every guarded request with that key. The TPM key continues to drive `/dbsc/refresh` in the background. The same `RequireBoundProofOptions` shape is used by every adapter; the wrapper just changes return type to match each framework's middleware idiom (Fastify returns a `preHandler`, Hono a `MiddlewareHandler`, Next.js a handler-callable that returns `{ ok }` or a short-circuit response).

### `requireProof` (Express)

```ts
function requireProof(opts?: RequireProofOptions): RequestHandler;
```

The route guard. One call, no arguments — `requireProof()` requires the request to come from a bound device and prove it per-request. **Works on every browser**: Chromium's hardware-backed `dbsc` tier passes through, the software `bound` tier (Firefox / Safari / older Chromium) must carry a signed, body-hashed proof. There is no "tier level" argument — a `dbsc`-only gate would lock out non-Chromium browsers, and a `bound`-only check (no proof) is not actually secure.

Internally it reuses `requireBoundProof` with `signBody: true` and reads storage from the request context the `dbsc()` middleware populates (pass `{ storage }` only to override). A failed check returns 403 with `{ error, currentTier, reason, skipped }`. Because the `bound` tier signs the body, a **POST** guarded route needs `express.raw({ type: "*/*" })` in front (`requireProof` is a pure guard, it does not inject body parsers) and the client must use `wrapFetch({ signBody: true })`. GET routes have no body and need no parser.

### `createDbsc` (Express)

```ts
interface CreateDbscOptions extends DbscExpressOptions {
  clientPath?: string | false;   // static SDK mount; default "/dbsc-client", false to skip
  sessionTtl?: number;           // default session TTL (ms) for bind()
  trustProxy?: boolean;          // default true — install() sets `trust proxy`
}

interface BindOptions { userId: string; deviceHint?: string; namespace?: string }

interface DbscKit {
  install(app: Express): Express;
  middleware(): RequestHandler;
  bind(res: Response, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: Response, opts: BindOptions): Promise<string>;   // derives the id
  requireProof(opts?: RequireProofOptions): RequestHandler;
}

function createDbsc(opts: CreateDbscOptions): DbscKit;
```

A single configured kit. Storage, `secure`, TTLs, the rate limiter and telemetry are set once in `createDbsc`; `install()`, `bind()` and `requireProof()` read that config. `install(app)` mounts the protocol middleware, scoped JSON parsing for the bound routes, the `/dbsc-client` static SDK, and `trust proxy` — one line. Returns the `sessionId` used.

`bind()` without a `sessionId` (the JWT path) derives one via `deriveSessionId` **and auto-manages a `__Host-dbsc-device` cookie** as the `deviceHint`, so each browser of the same user binds independently. Pass `deviceHint` in `BindOptions` only to control device identity yourself.

`install()` sets `trust proxy: true` so the registration response advertises `https` behind a proxy — required on Render/Fly/Cloudflare/nginx. An app **not** behind a proxy should pass `createDbsc({ trustProxy: false })`: otherwise `X-Forwarded-For` is client-spoofable and the IP-keyed rate limiter can be bypassed.

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

`requireProof(opts?)` returns a `preHandler` — `app.post("/p", { preHandler: requireProof() }, handler)`. `createDbsc(opts)` returns a kit whose `install(fastify)` is **async** (it registers `@fastify/cookie` if missing, then the plugin); `bind(reply, …)` and `requireProof` match the core shapes. Fastify's kit does not mount a static client SDK — serve `dist/client/` yourself.

**Fastify POST routes:** `requireProof()` signs the request body, and Fastify's default JSON parser yields a parsed object, not the raw bytes the proof needs. A guarded **POST** route must register a buffer content-type parser so `req.body` arrives as a `Buffer`:

```ts
app.addContentTypeParser("application/octet-stream", { parseAs: "buffer" }, (_req, body, done) =>
  done(null, body),
);
app.post("/payment", { preHandler: requireProof() }, paymentHandler);
// the client posts with Content-Type: application/octet-stream + wrapFetch({ signBody: true })
```

GET routes have no body and need no parser.

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

`requireProof(opts?)` returns a `MiddlewareHandler` — `app.post("/p", requireProof(), handler)`. `createDbsc(opts)` returns a kit whose `install(app)` mounts the dbsc middleware; `bind(c, …)` and `requireProof` match the core shapes. No static client SDK is mounted — serve `dist/client/` with your runtime's static handler.

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
  opts?: { boundCookieTtl?: number; refreshGraceMs?: number; res?: NextResponse; secure?: boolean },
): Promise<DbscSessionInfo>;

function bindSession(
  res: NextResponse,
  sessionId: string,
  storage: StorageAdapter,
  opts: BindSessionOptions,
): Promise<void>;
```

Export `createDbscMiddleware` from `middleware.ts` for the App Router. Use `getDbscSession` inside route handlers. Pass `res` if you want `revoke()` to clear the cookie for you; otherwise it only deletes the server-side session and you clear cookies yourself.

```ts
type RequireProofResult = { ok: true } | { ok: false; response: NextResponse };
interface RequireProofSession { sessionId: string | null; tier: ProtectionTier; skipped?: SkippedEntry[] }

function requireProof(
  req: NextRequest,
  session: RequireProofSession,
  opts?: RequireProofOptions,
): Promise<RequireProofResult>;

function createDbsc(opts: DbscNextOptions & { sessionTtl?: number }): {
  middleware(): (req: NextRequest) => Promise<NextResponse>;
  bind(res: NextResponse, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: NextResponse, opts: BindOptions): Promise<string>;
  getSession(req: NextRequest, res?: NextResponse): Promise<DbscSessionInfo>;
  requireProof(req: NextRequest, session: RequireProofSession): Promise<RequireProofResult>;
};
```

Next.js has no shared request context, so `requireProof` takes the session (from `getDbscSession`) and storage explicitly, and returns `{ ok }` / `{ ok: false, response }` like `requireBoundProof`. The `createDbsc` kit has no `install()` — export `kit.middleware()` from `middleware.ts`, call `kit.getSession` / `kit.requireProof` inside route handlers (storage is baked in).

On the no-sessionId JWT path, pass the request in `BindOptions` so the kit can manage the per-device cookie: `kit.bind(res, { userId, req })`. Without `req` (and without `deviceHint`) the derived id is `userId`-only — which collides for a user with two browsers. `BindOptions` here is `{ userId, deviceHint?, namespace?, req?: NextRequest }`.

---

## `dbsc-toolkit/nestjs`

```ts
DbscModule.forRoot(opts: DbscNestOptions): DynamicModule  // mounts the protocol middleware globally
class DbscService { bind(res, sessionId, opts): Promise<string> }   // injectable
class DbscGuard implements CanActivate                              // @UseGuards(DbscGuard)
createDbscGuard(opts: RequireProofOptions): new () => CanActivate   // guard with options baked in
bindSession(res, sessionId, storage, opts): Promise<void>          // re-exported from the Express adapter
```

Express platform. The guard reads `res.locals.dbsc` set by the middleware. A guarded POST is body-hashed, so it must deliver raw bytes (`rawBody: true`). `DbscNestOptions` is the Express adapter's option set.

## `dbsc-toolkit/koa`

```ts
dbsc(opts: DbscKoaOptions): Middleware
bindSession(ctx, sessionId, storage, opts): Promise<void>
requireProof(opts?: RequireProofOptions): Middleware
createDbsc(opts): { install(app), middleware(), bind(ctx, sessionId, opts), requireProof(opts?) }
```

Delegates to the `node:http` handler over `ctx.req` / `ctx.res`; sets `ctx.respond = false` when it answers a protocol route. The session lands on `ctx.state.dbsc`. The guard reads the raw body from `ctx.request.rawBody` when present.

## `dbsc-toolkit/sveltekit`

```ts
dbscHandle(opts: DbscSvelteKitOptions): Handle            // src/hooks.server.ts
bindSession(event, sessionId, storage, opts): Promise<void>
requireProof(opts?: RequireProofOptions): (event) => Promise<void>  // throws error(403) on failure
```

The hook resolves the session onto `event.locals.dbsc`. Protocol routes return a `Response` directly with manual `Set-Cookie`; `bindSession` uses `event.cookies` (it runs inside an action/handler that goes through `resolve`).

## `dbsc-toolkit/node`

```ts
dbsc(opts: DbscNodeOptions): (req, res) => Promise<boolean>   // true = answered a protocol route
getDbscSession(req): DbscNodeSession | undefined
bindSession(res, sessionId, storage, opts): Promise<void>
readJsonBody(req): Promise<Record<string, unknown>>
requireProof(opts?): (req, res) => Promise<boolean>          // true = passed; false = 403 already written
createDbsc(opts): { handler(), getSession(req), bind(res, sessionId, opts), requireProof(opts?) }
```

Generic raw `node:http`. No `install()` — branch on the handler's boolean return. The guard caches the verified raw body on the request so a downstream handler can re-read it via `readJsonBody`.

---

## `dbsc-toolkit/client`

Browser-side SDK for the bound polyfill. Load on every page that needs `tier: "bound"` on non-Chromium browsers; Chromium 146+ users see no effect (the SDK detects the native binding and steps back).

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
  signBody?: boolean;             // v2.8+ default: true. Adds bh=sha256(body) and signs it.
}
function wrapFetch(options?: WrapFetchOptions): typeof fetch;

// v2.8+: install once at boot instead of calling wrapFetch per call site.
// Routes matching same-origin requests whose pathname starts with one of
// `pathPrefixes` through wrapFetch; everything else through the original
// fetch. Returns an uninstall function that restores globalThis.fetch.
//
// Throws at install time on: empty pathPrefixes, bare "/" (would sign every
// request including static assets), absolute URL prefixes (would leak the
// session key cross-origin), prefixes missing the leading "/".
interface InstallFetchInterceptorOptions {
  pathPrefixes: string[];
  signBody?: boolean;             // forwarded to wrapFetch
  headerName?: string;            // forwarded to wrapFetch
  fetch?: typeof fetch;           // override globalThis.fetch — useful in tests
}
function installFetchInterceptor(options: InstallFetchInterceptorOptions): () => void;
```

Typical use:

```html
<script type="module">
  import { initBoundDbsc } from "/dbsc-client/index.js";
  initBoundDbsc();
</script>
```

For apps with many guarded routes, install the interceptor once at boot:

```js
import { installFetchInterceptor } from "dbsc-toolkit/client";
installFetchInterceptor({ pathPrefixes: ["/api/secure/"] });
// from now on `fetch("/api/secure/...")` carries the proof header.
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
