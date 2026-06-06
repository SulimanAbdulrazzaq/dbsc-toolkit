# 07 — Cookies

DBSC uses three cookies. Their names, prefixes, and attributes are
security-critical: the binding cookie's attributes must match what the JSON
config (02) advertises byte-for-byte, or the browser drops the session.

## The three cookies

| Role | Default name (secure host scope) | Holds | Typical Max-Age |
|---|---|---|---|
| Binding | `__Host-dbsc-session` | the session identifier | 10 min |
| Registration | `__Host-dbsc-reg` | the session identifier, before the binding cookie exists | 24 h |
| Challenge | `__Host-dbsc-challenge` | the current challenge JTI | 5 min |

The registration and challenge cookies carry state across the brief multi-leg
registration/refresh handshakes (the binding cookie does not exist yet, or has
just expired). The binding cookie is the one the session actually rides on once
bound.

A bound session identifies itself, in order of preference, by the binding cookie,
then the registration cookie (for the bound protocol's pre-binding requests).
Native refresh is the exception: it identifies the session by the
`Sec-Secure-Session-Id` header, because the binding cookie is gone at that point
(02).

## Prefix and scope

The cookie name prefix depends on whether the deployment is secure and on the
cookie scope.

| Scope | Secure? | Prefix | Names |
|---|---|---|---|
| `host` (default) | yes (default) | `__Host-` | `__Host-dbsc-session`, `__Host-dbsc-reg`, `__Host-dbsc-challenge` |
| `site` | yes (required) | `__Secure-` | `__Secure-dbsc-session`, `__Secure-dbsc-reg`, `__Secure-dbsc-challenge` |
| (dev) | no | none | `dbsc-session`, `dbsc-reg`, `dbsc-challenge` |

A server MUST NOT hardcode any cookie name. It derives the names from the prefix
implied by the secure flag and scope, so the binding cookie name written into
the registration header's `id=` (02) and the JSON config's `credentials[].name`
always matches the cookie actually set.

### `__Host-` rules (host scope)

The `__Host-` prefix is the strongest setting — origin-locked, immune to a
sibling subdomain overwriting the cookie. The browser enforces three constraints,
and violating any makes it **silently drop** the cookie:

1. `Secure` MUST be set.
2. `Path` MUST be `/`.
3. `Domain` MUST NOT be set.

### `__Secure-` rules (site scope)

Site scope shares the binding across subdomains of one registrable domain. It
requires `Secure` and a `Domain` attribute. A server using site scope:

- MUST set `secure` (a `__Secure-` cookie without the Secure flag is rejected);
- MUST set `Domain` to the registrable apex (e.g. `example.com`);
- MUST NOT use a leading-dot domain (`.example.com`).

Site scope trades away `__Host-`'s sibling-subdomain protection. Use it only when
single-origin (or proxying the DBSC endpoints through one origin) is genuinely
not workable.

### Insecure dev

With `secure` off (local HTTP only), cookies use no prefix. This MUST NOT be used
in production — without `Secure`, the binding cookie travels in cleartext.

## The attributes string

The JSON config's `credentials[0].attributes` (02) MUST equal the binding
cookie's actual `Set-Cookie` attributes, byte-for-byte, in this order:

```
Path=/; Secure; HttpOnly; SameSite=Lax
```

With site scope, a `Domain` is appended:

```
Path=/; Secure; HttpOnly; SameSite=Lax; Domain=example.com
```

Segments are joined by `"; "` (semicolon **and** a space). The browser re-reads
this string to know how to re-issue the bound cookie on refresh; any divergence
from the real `Set-Cookie` drops the binding.

`Max-Age` is part of the real `Set-Cookie` but is not required in the
`attributes` string. Note the unit difference: a raw `Set-Cookie` `Max-Age` is in
**seconds**, while many cookie APIs take milliseconds — convert at the boundary
and do not mix the two.
