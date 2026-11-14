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
| `dbsc-toolkit/electron` | Electron main-process adapter (`protocol.handle` bridge + node re-exports) |
| `dbsc-toolkit/dpop` | Optional DPoP (RFC 9449): `verifyDpopProof`, `dpopConfirmation`, `jwkThumbprint` |
| `dbsc-toolkit/client` | Browser SDK: `startDbsc()` and the lower-level pieces |
| `dbsc-toolkit/client/auto` | Side-effect import: calls `startDbsc()` (also served as `/dbsc-client/auto.js`) |
| `dbsc-toolkit/react` | `useDbsc()` hook |
| `dbsc-toolkit/storage/memory` | `MemoryStorage` |
| `dbsc-toolkit/storage/redis` | `RedisStorage` |
| `dbsc-toolkit/storage/postgres` | `PostgresStorage` |
| `npx dbsc-toolkit` | CLI: `doctor` and `init` |

---

## The kit (`createDbsc`)

Every adapter has a `createDbsc(options)` that returns a configured kit. It is the recommended way in; `dbsc()`, `bindSession()` and the bare `requireProof` import are the lower-level pieces it is built from. SvelteKit takes the same options on `dbscHandle()`, and NestJS on `DbscModule.forRoot()`.

### Options shared by every kit

On top of the adapter's middleware options (`storage`, `boundCookieTtl`, `rateLimiter`, `replayCache`, `onEvent`, `cookieScope`, ... see `DbscOptions` below):

```ts
interface KitSessionBinding<Req> {
  // The id passed to bind() for the login on this request. Every
  // requireProof()/protect() from the kit rejects a DBSC session from
  // another login with 403 SESSION_MISMATCH.
  expectSessionId?: (req: Req) => string | null | undefined | Promise<...>;
  // Same, compared with the userId passed to bind(). For JWT apps.
  expectUserId?: (req: Req) => string | null | undefined | Promise<...>;
  // Bind on the first request after a login instead of calling bind().
  bindOnLogin?: BindOnLoginOptions<Req>;
}

interface BindOnLoginOptions<Req> {
  userId: (req: Req) => string | null | undefined | Promise<...>;            // who is signed in
  loginAt: (req: Req) => number | Date | null | undefined | Promise<...>;    // when that login happened
  windowMs?: number;   // default: boundRegistrationWindowMs, 5 minutes
}
```

| Option | Kits | Default | Meaning |
|---|---|---|---|
| `expectSessionId` / `expectUserId` | all | none | Ties guards to your login. `createDbsc()` warns once under `NODE_ENV=production` when neither is set. |
| `bindOnLogin` | all | none | The binding starts on the first request whose `loginAt` is within `windowMs`, when no binding has started for this session since that login. The id bound is `expectSessionId(req)`, or one derived from the user id plus a per-device cookie when `expectSessionId` is unset (SvelteKit requires `expectSessionId`). |
| `secure` | all | `defaultSecure()` | `__Host-` cookies and the Secure flag. `defaultSecure()` is `false` only when `NODE_ENV === "development"`. |
| `sessionTtl` | all | 24 h | Lifetime of the DBSC session row created by `bind()`. |
| `clientPath` | Express, Fastify, Koa, node | `"/dbsc-client"` | Where the browser SDK is served. `false` to skip. |
| `maxProofBodyBytes` | Express, Fastify | 1 MiB | Largest request body copied for the proof's body hash. |
| `trustProxy` | Express | `true` | `install()` sets `trust proxy`. Pass `false` when not behind a proxy. |
| `protect` | Next.js, SvelteKit | none | `string[]` or `{ paths, except?, methods?, ...RequireProofOptions }`, guarded in the middleware / handle. |

`createDbsc()` also warns once under `NODE_ENV=production` when the storage is ephemeral (`MemoryStorage`).

### Methods

| Method | Express | Fastify | Hono | Koa | node | Next.js |
|---|---|---|---|---|---|---|
| `install(app)` | yes | async | yes | yes | `handler()` | `middleware()` |
| `bind(res, sessionId, { userId })` | yes | yes | yes | yes | yes | yes |
| `bind(res, { userId })` (derived per device) | yes | yes | yes | yes | pass `req` | pass `req` |
| `requireProof(opts?)` | yes | yes | yes | yes | yes | `(req, session, opts?)` |
| `protect(patterns, opts?)` | yes | yes | yes | yes | yes | `protect` option |
| `clientScript(opts?)` | yes | yes | yes | yes | yes | yes |
| `requireDpop(opts?)` | yes | yes | yes | yes | yes | separate import |
| `guard(req, opts?)` | | | | | | yes |
| `loginMiddleware()` | yes | | | | | |

**`install(app)`** mounts, in order: proof-body capture (Express, Fastify), the browser SDK (Express, Fastify, Koa), the protocol middleware, and the `bindOnLogin` step. Call it after the middleware that identifies the user when you use `bindOnLogin`, and before your body parsers.

**`protect(patterns, opts?)`** returns middleware (Express, Hono, Koa), a `preHandler` (Fastify) or a guard function (node) that runs `requireProof()` for matching requests:

```ts
interface ProtectOptions<Req> extends RequireProofOptions<Req> {
  except?: string[];    // paths inside the protected set that stay open
  methods?: string[];   // only these methods are guarded
}
```

Patterns: `"/api/*"` or `"/api/"` (everything under `/api/`), `"/account"` (the path and its children, not `/accounts`), `"*"` (everything). Patterns must start with `/`; an empty list throws.

**`clientScript(opts?)`** returns `<script type="module" src="/dbsc-client/auto.js?...">`. By default it signs the paths passed to `protect()`; `{ sign: string[], signQuery?: boolean }` overrides.

**`requireProof(opts?)`** uses the kit's `expectSessionId` / `expectUserId` unless `opts` sets either one.

**`loginMiddleware()`** (Express) is the `bindOnLogin` step alone, for apps that call `install()` before their session middleware. NestJS mounts it for you.

**`guard(req, opts?)`** (Next.js) reads the session and runs the guard: `const denied = await dbsc.guard(req); if (denied) return denied;`.

### Presets

```ts
import { passportSession } from "dbsc-toolkit/express";
createDbsc({ storage, ...passportSession({ userId?: (user) => string }) });
```

Fills in `expectSessionId` (`req.sessionID`) and `bindOnLogin` for express-session + Passport. The login time is stored in the session as `dbscLoginAt` the first time the kit sees the login.

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

`bound` (default `true`) toggles the Web Crypto polyfill. Set `false` to run native DBSC only (Chromium 145+): the `/dbsc-bound/challenge`, `/dbsc-bound/registration`, and `/dbsc-bound/refresh` routes are not mounted (`/dbsc-bound/state` still answers `phase: "unbound"` so a loaded client SDK stands down), non-Chromium browsers stay at `tier: "none"`, and `requireProof()` auto-relaxes so a native `dbsc`-tier session passes without a per-request bound proof. Use it only when you can mandate a Chromium build with a hardware key store; for general-audience apps the polyfill is what covers Firefox / Safari. See [polyfill.md](./polyfill.md#disabling-the-polyfill-bound-false).

`autoBind` is the transparent-migration hook. The middleware calls it on every request that does not carry the bound cookie yet, passing the framework-native request. Return a `{ sessionId, userId }` to start binding, or `null` to skip. A sessionId that already has a DBSC session is left alone (`autoBindAllowed(storage, sessionId)` in core is the check). See [guide.md](./guide.md).

`refreshGraceMs` (2.5.0+) extends the freshness check. A bound cookie's freshness lapses at `lastRefreshAt + boundCookieTtl`, but the browser's next `/dbsc/refresh` lands a short moment later — during that gap a `/me`-style poll would see `tier: "none"`. The middleware keeps the previous tier until `lastRefreshAt + boundCookieTtl + refreshGraceMs`. Default 30000 ms. Set `0` to demote the instant freshness lapses (use on routes that tolerate no grace).

`cookieScope` (2.9.0+) picks the cookie-prefix model. `"host"` (default) keeps the `__Host-` prefix — origin-locked, no `Domain` attribute, strongest. `"site"` switches to `__Secure-` and emits `Domain=<cookieDomain>`, so an app spread across `app.example.com` and `api.example.com` can share one binding. `"site"` requires `cookieDomain` (the registrable apex, no leading dot) and `secure: true`; passing either wrong throws at `dbsc()` / `createDbsc()` construction so the misconfiguration cannot reach a request. `__Secure-` cookies do not carry `__Host-`'s protection against a sibling subdomain setting or overwriting the cookie — prefer host scope when a same-origin deployment (or proxying `/dbsc/*` + `/dbsc-bound/*` through one origin) is workable. See [recipes.md](./recipes.md#multi-subdomain-apps-cookiescope-site).

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

**`deviceHint` matters for multi-device users.** Without it, the same `userId` always derives the same id — so a user on two browsers collides on one binding, and the second browser fails to register. Pass a per-device value as `deviceHint`. You normally don't call `deriveSessionId` directly: the `createDbsc` kit's `bind(res, { userId })` does it for you and **auto-manages a `__Host-dbsc-device` cookie** as the `deviceHint`, so each browser binds independently with no extra code. See [recipes.md](./recipes.md).

### Route protection

```ts
interface RequireProofOptions<Req = unknown> {
  allowDbscWithoutProof?: boolean;  // v2.7+ default: false — every tier must carry a proof header
  timestampWindowMs?: number;       // accepted proof timestamp window, ms
  storage?: StorageAdapter;         // override; default = the adapter's storage
  expectSessionId?: (req: Req) => string | null | undefined | Promise<string | null | undefined>; // 2.15+
  expectUserId?: (req: Req) => string | null | undefined | Promise<string | null | undefined>;    // 2.15+
  signQuery?: boolean;              // 2.15+: include the query string in the signed path
}

function noBindingReason(skipped?: SkippedEntry[]): string;
```

`allowDbscWithoutProof` defaults to `false` as of v2.7 — Chromium sessions
register a polyfill key alongside the TPM key on first init, so the per-request
proof works the same way on every tier. Set this to `true` only if your
Chromium client cannot ship the v2.7 client SDK (then the legacy v2.6
behavior is restored, with the refresh-cycle replay window — see CHANGELOG).

When the polyfill is off (`bound: false`), a native `dbsc` session has no
per-request key to verify, so `requireProof()` relaxes it — the request passes
on the hardware binding. Native DBSC protects that session by cookie rotation
(Chrome re-proves the TPM key at the refresh endpoint each `~boundCookieTtl`),
not per request; there is no protocol way to force a hardware proof on an
ordinary resource request. For true per-request rejection of a stolen cookie,
run with the polyfill on (the bound key signs each request) or use DPoP for
token-bound APIs.

**Tie the proof to your login (2.15+).** `requireProof()` on its own proves that a request came from *a* bound device, not from the device bound to the user your app authenticated. Pass `expectSessionId` (return the session id you gave `bind()`) or `expectUserId` (return the `userId`) on every guarded route where the app identifies the user from its own cookie or token. A mismatch, or a hook that returns nothing, is a 403 with `code: "SESSION_MISMATCH"`. Skipping this lets an attacker pair a stolen app cookie with their own bound session.

`signQuery: true` covers the query string; the client must sign it too (`wrapFetch({ signQuery: true })`). Without it, a captured proof can be replayed with different query parameters inside the timestamp window, so keep state-changing input out of the query or turn it on.

`RequireProofOptions` is the (entirely optional) option shape of every adapter's `requireProof()`. `noBindingReason` produces the quota-aware human reason used in a `tier: "none"` rejection — exported for custom adapters.

Set the hooks once on the kit (`createDbsc({ expectSessionId })`) rather than on every guard; a guard's own hooks win when it has any.

### Path matching (for adapter authors)

```ts
function matchesPathPattern(pathname: string, pattern: string): boolean;
function isProtected(pathname: string, method: string, patterns: readonly string[], opts?: { except?: string[]; methods?: string[] }): boolean;
function validatePathPatterns(patterns: readonly string[], label?: string): void;   // throws on bad input
function signPrefixes(patterns: readonly string[]): string[] | undefined;           // client sign list; undefined = sign everything
```

### Login binding (for adapter authors)

```ts
function shouldBindLogin(storage: StorageAdapter, input: {
  userId: string; loginAt: number; sessionId: string; currentSessionId: string | null; windowMs?: number; now?: number;
}): Promise<boolean>;
function resolveLoginBinding<Req>(cfg: BindOnLoginOptions<Req>, req: Req, input: ResolveLoginBindingInput<Req>):
  Promise<{ sessionId: string; userId: string } | null>;
```

`shouldBindLogin` is the rule every adapter's `bindOnLogin` uses: inside the window, and no binding created at or after `loginAt` for this id.

### Kit helpers

```ts
function defaultSecure(): boolean;                     // false only when NODE_ENV === "development"
function withKitBinding<Req>(kit: KitSessionBinding<Req>, opts?: RequireProofOptions<Req>): RequireProofOptions<Req>;
function checkKitSetup(setup: { storage; expectSessionId?; expectUserId? }): void;   // production warnings
function clientScriptTag(clientPath: string, opts?: { sign?: string[]; signQuery?: boolean }): string;
```

### Diagnostics

```ts
const NO_BINDING = "NO_BINDING";        // guarded request with no active binding
const DEBUG_HEADER = "X-Dbsc-Debug";
function rejectionHint(code: string | undefined, message?: string): string | undefined;
function describeRejection(code: string, message?: string): { hint?: string; debugHeader?: string };
function debugEnabled(): boolean;       // DBSC_DEBUG=1|true, else NODE_ENV === "development"
```

Every guard's 403 body is `{ error, code, hint?, ...extra }`. `code` is stable; `hint` is a plain-language explanation of the likely cause, safe to send to clients (it describes setup, never the session). When `debugEnabled()`, the response also carries `X-Dbsc-Debug: CODE: hint`, and the client SDK logs it with `console.warn`. A `tier: "none"` rejection keeps its `currentTier`, `reason` and `skipped` fields and now has `code: "NO_BINDING"`.

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
  SESSION_MISMATCH: string;              // 2.15+: binding belongs to another login
  REGISTRATION_WINDOW_CLOSED: string;    // 2.15+: polyfill key arrived too late
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
  /** @deprecated no-op; the header carries no id parameter (cookie name lives in the JSON response) */
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

// Per-request signing — see docs/request-signing.md.
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

The bound polyfill protocol is documented in [polyfill.md](./polyfill.md). The per-request signing flow is documented in [request-signing.md](./request-signing.md). `ErrorCodes` entries added across releases: `MISSING_PROOF`, `MALFORMED_PROOF` (v2.1.0+), `PROOF_REPLAY`, `KEY_NOT_FOUND_NATIVE`, `KEY_NOT_FOUND_BOUND` (v2.8+).

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

// Per-request signing gate for sensitive routes — see docs/request-signing.md.
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

The route guard: the request must come from a bound device and carry a fresh per-request proof. **Works on every browser.** Prefer the kit's `dbsc.requireProof()` (it applies `expectSessionId`) or `dbsc.protect()`.

It verifies a body hash, so it needs the raw request bytes. Behind `createDbsc().install()` those come from `captureProofBody()`, which copies the body of every signed request (with a `Content-Length`, up to `maxProofBodyBytes`) and hands the stream back to your parsers. Without the kit, put `captureProofBody()` first in the app, or `express.raw({ type: "*/*" })` on the route. A failed check returns 403 with `{ error, code, hint }` (see [Diagnostics](#diagnostics)).

```ts
function captureProofBody(opts?: { limit?: number }): RequestHandler;   // limit default 1 MiB
```

### `createDbsc` (Express)

```ts
interface CreateDbscOptions extends DbscExpressOptions, KitSessionBinding<Request> {
  clientPath?: string | false;   // static SDK mount; default "/dbsc-client", false to skip
  sessionTtl?: number;           // default session TTL (ms) for bind()
  trustProxy?: boolean;          // default true — install() sets `trust proxy`
  maxProofBodyBytes?: number;    // default 1 MiB
}

interface BindOptions { userId: string; deviceHint?: string; namespace?: string }

interface DbscKit {
  install(app: Express): Express;
  middleware(): RequestHandler;
  loginMiddleware(): RequestHandler;
  bind(res: Response, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: Response, opts: BindOptions): Promise<string>;   // derives the id
  requireProof(opts?: RequireProofOptions<Request>): RequestHandler;
  requireDpop(opts?: RequireDpopOptions<Request>): RequestHandler;
  protect(patterns: string[], opts?: ProtectOptions<Request>): RequestHandler;
  clientScript(opts?: ClientScriptOptions): string;
}

function createDbsc(opts: CreateDbscOptions): DbscKit;
function passportSession(opts?: { userId?: (user: unknown) => string | null | undefined }): KitSessionBinding<Request>;
```

A single configured kit; see [the kit](#the-kit-createdbsc) for what each option and method does. `install(app)` mounts proof-body capture, scoped JSON parsing for the bound routes, the protocol middleware, the `bindOnLogin` step, the `/dbsc-client` SDK and `trust proxy`. `bind()` returns the `sessionId` used.

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

`requireProof(opts?)` returns a `preHandler` — `app.post("/p", { preHandler: dbsc.requireProof() }, handler)`. `createDbsc(opts)` returns a kit whose `install(fastify)` is **async**: it registers `@fastify/cookie` if missing, a `preParsing` hook that copies the body of signed requests (so Fastify's own JSON parser keeps working on guarded routes), the plugin, the `bindOnLogin` `preHandler`, and a `GET /dbsc-client/*` route for the browser SDK. `protect(patterns)` returns a `preHandler`: `fastify.addHook("preHandler", dbsc.protect(["/api/*"]))`.

Without the kit, register a buffer content-type parser on guarded POST routes so `req.body` arrives as a `Buffer`, as before.

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

`requireProof(opts?)` returns a `MiddlewareHandler` — `app.post("/p", dbsc.requireProof(), handler)`. Hono reads the body with `c.req.arrayBuffer()`, which it caches, so no body setup is needed. `createDbsc(opts)` returns a kit whose `install(app)` mounts the dbsc middleware and the `bindOnLogin` step; `protect(patterns)` returns a `MiddlewareHandler`. No static client SDK is mounted, since Hono runs on runtimes without a filesystem: serve `dist/client/` with your runtime's static handler, or bundle `startDbsc()` from `dbsc-toolkit/client`.

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

interface CreateDbscOptions extends DbscNextOptions, KitSessionBinding<NextRequest> {
  sessionTtl?: number;
  protect?: string[] | { paths: string[]; except?: string[]; methods?: string[] } & RequireProofOptions<NextRequest>;
}

function createDbsc(opts: CreateDbscOptions): {
  middleware(): (req: NextRequest) => Promise<NextResponse>;
  bind(res: NextResponse, sessionId: string, opts: BindOptions): Promise<string>;
  bind(res: NextResponse, opts: BindOptions): Promise<string>;
  getSession(req: NextRequest, res?: NextResponse): Promise<DbscSessionInfo>;
  requireProof(req: NextRequest, session: RequireProofSession, opts?: RequireProofOptions<NextRequest>): Promise<RequireProofResult>;
  guard(req: NextRequest, opts?: RequireProofOptions<NextRequest>): Promise<NextResponse | null>;
  clientScript(opts?: ClientScriptOptions): string;
};
```

The kit's `middleware()` answers the protocol routes, then for pass-through requests runs `protect` (returning the 403 itself) and `bindOnLogin` (adding the registration header and cookies to the pass-through response). Your `config.matcher` must include the protected paths and, for `bindOnLogin`, the pages users land on after signing in.

Next.js has no shared request context, so `requireProof` takes the session (from `getDbscSession`) and storage explicitly, and returns `{ ok }` / `{ ok: false, response }` like `requireBoundProof`. The `createDbsc` kit has no `install()` — export `kit.middleware()` from `middleware.ts`, call `kit.getSession` / `kit.requireProof` inside route handlers (storage is baked in).

On the no-sessionId JWT path, pass the request in `BindOptions` so the kit can manage the per-device cookie: `kit.bind(res, { userId, req })`. Without `req` (and without `deviceHint`) the derived id is `userId`-only — which collides for a user with two browsers. `BindOptions` here is `{ userId, deviceHint?, namespace?, req?: NextRequest }`.

---

## `dbsc-toolkit/nestjs`

```ts
DbscModule.forRoot(opts: DbscNestOptions): DynamicModule  // the Express kit's options, incl. expectSessionId and bindOnLogin
class DbscService { bind(res, sessionId, opts): Promise<string> }   // injectable
class DbscGuard implements CanActivate                              // @UseGuards(DbscGuard)
createDbscGuard(opts: RequireProofOptions): new () => CanActivate   // guard with options baked in
bindSession(res, sessionId, storage, opts): Promise<void>          // re-exported from the Express adapter
```

Express platform. `forRoot` mounts the protocol middleware and the `bindOnLogin` step for every route; Nest middleware already runs after the session middleware `main.ts` installed. `expectSessionId` / `expectUserId` given to `forRoot` apply to `DbscGuard` and every `createDbscGuard()` unless the guard passes its own. Nest parses bodies before any module middleware, so a guarded POST still needs `NestFactory.create(AppModule, { rawBody: true })`. 403s carry `code` and `hint`.

## `dbsc-toolkit/koa`

```ts
dbsc(opts: DbscKoaOptions): Middleware
bindSession(ctx, sessionId, storage, opts): Promise<void>
requireProof(opts?: RequireProofOptions): Middleware
createDbsc(opts): {
  install(app), middleware(),
  bind(ctx, sessionId, opts), bind(ctx, { userId }),   // second form derives a per-device id
  requireProof(opts?), requireDpop(opts?), protect(patterns, opts?), clientScript(opts?)
}
```

Delegates to the `node:http` handler over `ctx.req` / `ctx.res`; sets `ctx.respond = false` when it answers a protocol route. The session lands on `ctx.state.dbsc`. The guard reads the raw body from `ctx.request.rawBody` when present. `install(app)` also serves the browser SDK at `/dbsc-client` and mounts the `bindOnLogin` step.

## `dbsc-toolkit/sveltekit`

```ts
dbscHandle(opts: DbscSvelteKitOptions): DbscHandle        // src/hooks.server.ts
// DbscSvelteKitOptions adds expectSessionId, expectUserId, bindOnLogin (needs expectSessionId)
// and protect: string[] | { paths, except?, methods?, ...RequireProofOptions }
bindSession(event, sessionId, storage, opts): Promise<void>
requireProof(opts?: RequireProofOptions): (event) => Promise<void>  // throws error(403) on failure
```

The hook resolves the session onto `event.locals.dbsc`. Protocol routes return a `Response` directly with manual `Set-Cookie`; `bindSession` uses `event.cookies` (it runs inside an action/handler that goes through `resolve`). `expectSessionId` / `expectUserId` on the handle apply to every `requireProof()`. `protect` runs the guard in the handle, before the route; a failure is `error(403, { message, code, hint })`.

## `dbsc-toolkit/node`

```ts
dbsc(opts: DbscNodeOptions): (req, res) => Promise<boolean>   // true = answered a protocol route
getDbscSession(req): DbscNodeSession | undefined
bindSession(res, sessionId, storage, opts): Promise<void>
readJsonBody(req): Promise<Record<string, unknown>>
requireProof(opts?): (req, res) => Promise<boolean>          // true = passed; false = 403 already written
createDbsc(opts): {
  handler(), getSession(req),
  bind(res, sessionId, opts), bind(res, { userId, req }),   // second form derives a per-device id
  requireProof(opts?), requireDpop(opts?),
  protect(patterns, opts?): (req, res) => Promise<boolean>,  // true = continue (not protected, or passed)
  clientScript(opts?)
}
```

Generic raw `node:http`. No `install()` — branch on the handler's boolean return. The kit's `handler()` also serves the browser SDK at `/dbsc-client` and runs the `bindOnLogin` step; it returns `true` when it answered the request. The guard caches the verified raw body on the request so a downstream handler can re-read it via `readJsonBody`.

---

## `dbsc-toolkit/electron`

Electron main-process adapter. Re-exports the whole `dbsc-toolkit/node` surface (`dbsc`, `bindSession`, `getDbscSession`, `readJsonBody`, `requireProof`, `requireDpop`, `createDbsc`) for running a localhost server in the main process, and adds a bridge onto Electron's `protocol.handle` Web `Request`/`Response` shape.

```ts
createElectronDbsc(opts: CreateDbscOptions): ElectronDbscKit
// ElectronDbscKit extends the node kit with:
//   protocolHandler(): (request: Request) => Promise<Response>   // 404 Response when not a protocol route
//   protocolRoute(request: Request): Promise<{ handled, response, session }>

handleDbscProtocol(request: Request, handler: DbscNodeHandler): Promise<{
  handled: boolean;          // true when the request was a DBSC protocol route
  response: Response;        // the Response to send (or a 404 when not handled)
  session: DbscNodeSession | undefined;
}>
```

The bridge builds a minimal request/response shim and runs the same node handler, so no protocol logic is duplicated. Expected tier in a stock Electron build is `bound` (Web Crypto polyfill): native DBSC is on by default in Chrome, but the Electron renderer usually lacks the `https` origin and hardware key store it needs, so it falls back. `initBoundDbsc()` still uses native `dbsc` if the build provides it. See [adapters.md](./adapters.md#electron-main-process).

---

## `dbsc-toolkit/client`

Browser-side SDK. Load it on every page users reach after signing in, on every browser, Chromium included: it registers the polyfill key that per-request proofs use.

### `startDbsc` (start here)

```ts
interface StartDbscOptions extends InitBoundDbscOptions {
  sign?: string[];        // path prefixes to sign; default: every same-origin request
  signQuery?: boolean;    // match the server's signQuery
}

interface DbscClient {
  readonly ready: Promise<BoundDbscOutcome>;          // the current registration run
  readonly outcome: BoundDbscOutcome | null;          // null while the first run is going
  subscribe(listener: (o: BoundDbscOutcome) => void): () => void;
  restart(): Promise<BoundDbscOutcome>;
  stop(): void;                                       // remove the interceptor, stop refresh
}

function startDbsc(options?: StartDbscOptions): DbscClient;   // idempotent: later calls return the first client
function getDbscClient(): DbscClient | null;
```

`startDbsc()` runs `initBoundDbsc()`, keeps the key refreshed, and replaces `globalThis.fetch` with an interceptor that signs same-origin requests under `sign` (cross-origin requests are never signed; the SDK's own protocol calls are skipped; `ReadableStream` bodies go out unsigned). When any same-origin response carries `Secure-Session-Registration` (a login done with `fetch`), it registers again on its own. Each new outcome is also dispatched as a `dbsc:change` event on `window`. Responses with `X-Dbsc-Debug` are logged with `console.warn`.

Without a bundler: `<script type="module" src="/dbsc-client/auto.js?sign=/api/,/account/&signQuery=1"></script>`. Query parameters are optional; the client is exposed as `window.dbsc`. A kit's `clientScript()` builds this tag for you. With a bundler, `import "dbsc-toolkit/client/auto"` does the same with defaults.

### Lower-level pieces

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

// Per-request signing for sensitive routes — see docs/request-signing.md.
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

`wrapFetch` sends the exact bytes it hashed and keeps the Content-Type fetch would have set (multipart boundary included for `FormData`). A `Request` passed as input is signed with its own method, headers and body.

See [polyfill.md](./polyfill.md) for the wire protocol and threat coverage.

---

## `dbsc-toolkit/react`

```ts
interface DbscState {
  status: "starting" | "bound" | "unbound" | "error";
  tier: "dbsc" | "bound" | null;
  skipReason: string | undefined;
  outcome: BoundDbscOutcome | null;
}
function useDbsc(options?: StartDbscOptions): DbscState;
```

Calls `startDbsc(options)` on first subscribe (options apply to the first call per page) and re-renders on each outcome. Renders as `starting` on the server. React 18+ is an optional peer dependency.

---

## CLI

```sh
npx dbsc-toolkit doctor <url> [--cookie "<Cookie header>"] [--guard /path] [--client-path /dbsc-client] [--timeout 30]
npx dbsc-toolkit init [--framework express|fastify|hono|koa|nextjs|sveltekit|nestjs|node|better-auth] [--write <file>]
```

`doctor` checks HTTPS, `GET /dbsc-bound/state`, server clock skew (`X-Server-Time`), the client SDK, and `POST /dbsc/refresh` without a session. With `--cookie` it reports the session's state; with `--cookie` and `--guard` it requests the guarded path with the cookie and no proof and fails unless the answer is `403` (a `401` from the app's own login check is a warning: add the app's session cookie to `--cookie`). `--timeout` is per request, in seconds, default 30. A failed request reports its cause (`ECONNREFUSED`, a timeout, ...). Exit code 1 on any failure, 2 on bad arguments. In Git Bash on Windows, set `MSYS_NO_PATHCONV=1` (or write `//api/route`), or the shell turns `--guard /api/route` into a Windows path.

`init` picks the framework and storage from `package.json` (Better Auth first, then Next.js, SvelteKit, NestJS, Fastify, Hono, Koa, Express, plain node; `ioredis` then `pg` then memory; the Passport preset when `passport` and `express-session` are both present) and prints the setup. `--write` saves it to a new file and refuses to overwrite.

---

## `dbsc-toolkit/storage/memory`

```ts
class MemoryStorage implements StorageAdapter {
  // Map-based, periodic TTL sweep, dev/test only
}
```

No constructor arguments. Lives in process memory only. Has `ephemeral = true`, which makes `createDbsc()` warn under `NODE_ENV=production`. A custom `StorageAdapter` can set `readonly ephemeral?: boolean` the same way.

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

## Added in 2.15.0

Middleware options (every adapter):

| Option | Default | Meaning |
|---|---|---|
| `boundRegistrationWindowMs` | `300000` | How long after `bind()` (or after Chrome's native registration) a polyfill key may still register. Later attempts fail with `REGISTRATION_WINDOW_CLOSED`; the user signs in again. |
| `replayCache` | `new MemoryReplayCache()` | Replay defense is now on by default. Use `RedisReplayCache` with more than one instance. |
| `ipExtractor` (node, Koa, Electron) | socket address | Rate-limiter key. Behind a reverse proxy, return the client IP the proxy reports. |

DPoP guards accept `origin` (`requireDpop({ origin: "https://api.example.com", getBoundJkt })`). The `htu` claim is then checked against that origin instead of the request's Host header. Set it in production. A `Bearer` Authorization header on a DPoP-guarded route is now rejected (`DPOP_TOKEN_BINDING_REQUIRED`) unless `requireTokenBinding: false`.

Core exports: `startBinding(storage, { sessionId, userId, sessionTtlMs })` (what every `bindSession()` now calls: it drops old keys and resets the row), `sessionBindingMatches`, `proofTarget`, `proofBodyBytes`, `readJsonObject`. Error codes: `SESSION_MISMATCH`, `REGISTRATION_WINDOW_CLOSED`.

Storage: `StorageAdapter.setBoundKeyIfAbsent?(key)` is optional; when present, registration uses it so two racing registrations cannot overwrite each other. Memory, Redis and Postgres implement it. `PostgresStorage.deleteExpired()` removes expired sessions and challenges; run it on a schedule.

Client: `wrapFetch({ signQuery })`, `installFetchInterceptor({ signQuery })`. `initBoundDbsc()` can now resolve with `skipReason: "local-key-missing"` when the server holds a polyfill key this browser lost (site data cleared). Treat it as signed out.

Electron: `protocolRoute(request)` results carry `guard(kit.requireProof())`, which resolves `null` when the request may proceed or the error `Response` to return.

## Added in the next release

- Kits: `expectSessionId`, `expectUserId`, `bindOnLogin`, `maxProofBodyBytes`, `clientPath` (Fastify, Koa, node); methods `protect()`, `clientScript()`, `loginMiddleware()` (Express), `guard()` (Next.js); `protect` option on Next.js and SvelteKit. See [the kit](#the-kit-createdbsc).
- `secure` defaults to `false` when `NODE_ENV === "development"`.
- Express `captureProofBody()` and Fastify body capture: guarded routes no longer need a raw parser.
- `passportSession()` preset.
- Koa and node `bind()` derive a per-device id when no session id is given.
- Diagnostics: `code` + `hint` on every guard 403, `X-Dbsc-Debug`, `NO_BINDING`.
- Client: `startDbsc()`, `getDbscClient()`, `/dbsc-client/auto.js`, `dbsc-toolkit/client/auto`; `wrapFetch` encodes `FormData`, `URLSearchParams` and `Request` bodies correctly.
- `dbsc-toolkit/react` (`useDbsc`), `npx dbsc-toolkit doctor|init`.
- `autoBind` is deprecated in favor of `bindOnLogin`.
