# DPoP (RFC 9449)

DBSC binds a session cookie to a device key. DPoP solves the sibling problem:
**bearer access tokens** replay just as easily as cookies — copy the
`Authorization` header and it works from anywhere. [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
binds the token to a device key and demands a fresh `DPoP` proof on every call.

This is an **optional, opt-in** layer. It ships at `dbsc-toolkit/dpop` and as a
`requireDpop` guard on each adapter. A project that doesn't import it pulls in
nothing extra and behaves exactly as before.

## DBSC vs DPoP

|  | DBSC | DPoP |
|---|---|---|
| Binds | the session **cookie** | a bearer **access token** |
| Driven by | the browser (native) or a client SDK (bound) | your app's client |
| Proof sent | on refresh, and on guarded requests | on **every** request, in a `DPoP` header |
| Proof carries | a signature over the session + request | `htm` (method), `htu` (URI), `iat`, `jti`, and `ath` when a token is bound |
| Failure status | **403** (native refresh must stay 403) | **401** + `WWW-Authenticate: DPoP` |

Same underlying idea — a device keypair and a per-request signature — different
object and a different verification surface. They are independent; use either,
both, or neither.

## How a request is verified

For every DPoP-guarded request the server checks, in order (RFC 9449 §4.3):

1. exactly one well-formed `DPoP` JWT, `typ=dpop+jwt`, an asymmetric `alg`, a
   **public-only** `jwk`;
2. the JWS signature against that embedded key;
3. `htm` equals the request method;
4. `htu` equals the request URI after normalization (default port dropped, query
   and fragment stripped, **trailing slash significant**);
5. `iat` is inside the acceptance window;
6. the `jti` has not been replayed;
7. when a token is presented: `ath` equals the token hash **and** the proof key's
   RFC 7638 thumbprint equals the token's `cnf.jkt`.

## Getting started

### 1. Bind a token at issue time

Embed the device key's thumbprint as the token's `cnf.jkt`. The token can be any
format you already sign — `dpopConfirmation` just gives you the `jkt`.

```ts
import { dpopConfirmation } from "dbsc-toolkit/dpop";

const { jkt } = await dpopConfirmation(deviceJwk);   // RFC 7638 thumbprint
const accessToken = await signJwt({ sub: userId, cnf: { jkt } });
```

`deviceJwk` is the public JWK of the key the client holds. In a browser, generate
a non-extractable ECDSA P-256 key with Web Crypto and send its public JWK at
login; the server thumbprints it.

### 2. Guard the resource route

```ts
import { requireDpop } from "dbsc-toolkit/express";

// getBoundJkt tells the guard which jkt the presented token was issued against
// (decode the bearer, read cnf.jkt).
function getBoundJkt(req) {
  const token = parseDpopAuthorization(req.headers.authorization);
  return token ? decodeJwt(token).cnf?.jkt : undefined;
}

app.get("/api/resource", requireDpop({ getBoundJkt }), (req, res) => {
  res.json({ ok: true });
});
```

The client sends `Authorization: DPoP <token>` and a freshly minted `DPoP: <proof>`
header on each call. On any failure the guard answers `401` with
`WWW-Authenticate: DPoP error="invalid_dpop_proof"`.

### 3. Mint a proof on the client

```js
// browser, per request:
const proof = await signDpopProof({
  privateKey,                 // the device key
  publicJwk,                  // its public half, embedded in the proof header
  htm: "GET",
  htu: "https://api.example.com/resource",   // no query/fragment
  iat: Math.floor(Date.now() / 1000),
  jti: crypto.randomUUID(),
});
fetch(url, { headers: { Authorization: `DPoP ${token}`, DPoP: proof } });
```

The demo (`examples/express`) carries a complete self-contained browser
implementation of this in `public/index.html` — generate a key, get a bound
token, call the API with a proof, and watch a stolen token without a proof get a
401.

## Per adapter

`requireDpop` is exported from `dbsc-toolkit/express`, `/fastify`, `/hono`,
`/nextjs`, `/koa`, `/sveltekit`, and `/node`; NestJS exposes
`createDbscDpopGuard`. Each follows that adapter's existing guard style — see
[adapters.md](./adapters.md).

## Token binding is required by default

If a bearer token is presented but you do **not** supply `getBoundJkt` (or it
returns nothing), the guard rejects with `DPOP_TOKEN_BINDING_REQUIRED` rather
than silently accepting an unbound proof. Verifying a token without binding it to
its key is **strictly weaker** — a stolen token paired with any self-minted proof
would pass. To opt into that (pure proof-of-possession), you must pass
`requireTokenBinding: false` explicitly. It can't happen by forgetting a hook.

## Replay defense and production

The `jti` is recorded in a replay cache after the cryptographic checks pass, so a
captured proof can't be reused inside the `iat` window. The guard reuses the same
replay cache the DBSC middleware was configured with. In a single process the
in-memory cache is fine; across replicas use Redis — otherwise a proof verified
on one instance can be replayed on another.

## Not in this version

The optional server-provided **nonce** (`DPoP-Nonce` / `use_dpop_nonce`) is not
implemented yet; the `jti` single-use check plus the `iat` window are the replay
defense. DPoP at the OAuth authorization server (issuance-time `dpop_jkt`,
token-request proofs) is also out of scope — this is the resource-server side.

See [spec/10-dpop.md](../spec/10-dpop.md) for the normative details and
[docs/security/best-practices.md](./security/best-practices.md) for when to reach
for DPoP versus the DBSC cookie binding.
