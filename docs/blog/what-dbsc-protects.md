---
title: "What DBSC Does and Doesn't Protect You From"
published: true
description: "Device Bound Session Credentials kill remote cookie theft. They don't stop in-browser malware, they don't cover PRTs or Kerberos tickets, and the polyfill tier is weaker than the TPM one. An honest threat boundary."
tags: security, authentication, threatmodeling, webdev
canonical_url: https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/docs/blog/what-dbsc-protects.md
---

Most writing about DBSC is either a spec or a pitch. This is neither. DBSC is a genuinely good defense against the most common session attack on the internet, and it has a precise boundary that the marketing language tends to blur. If you're deciding whether to adopt it — or trying to explain to a security review what it does and doesn't buy you — the boundary is the whole conversation.

Short version: DBSC kills *remote* cookie theft and replay. It does not turn a session into a hardware token for every threat, and exactly how much it protects depends on which tier the user lands in.

## The attack it's built for

A session cookie is a bearer token: hold it, be the user. The dominant way that goes wrong at scale is **steal the cookie, replay it from somewhere else**. Infostealer malware lifts cookies out of the browser profile and ships them off. XSS exfiltrates them. A malicious extension reads them. A misconfigured proxy logs them. In every case the attacker ends up with the cookie value on *their* machine and uses it to ride your session — no password, no MFA prompt, because the cookie already cleared both.

DBSC binds the session to a private key that lives on the user's device and never travels. When the attacker replays the cookie from their machine, the next refresh demands a signature their machine can't produce. The session dies. That's the core win, and it's a big one: it neutralizes the single most common takeover path.

## The tiers protect different amounts

This is the part that matters most and gets glossed over. DBSC binding comes in two strengths.

| Threat | `dbsc` (native, TPM/Secure Enclave) | `bound` (Web Crypto polyfill, IndexedDB) |
|---|---|---|
| Remote cookie theft + replay | Stopped | Stopped |
| MFA bypass via stolen cookie | Stopped | Stopped |
| Infostealer reading the browser profile on disk | Stopped (key is in hardware) | **Not stopped** (encrypted blob on disk is recoverable) |
| Malware running inside the browser process | Not stopped | Not stopped |

The native tier (`dbsc`) puts the private key inside a TPM or Secure Enclave. No software on the machine — including malware running as the user — can read it. That's the strong form, and it's Chromium on supported hardware: Windows from Chrome 145 (TPM), Apple Silicon macOS from Chrome 147 (Secure Enclave).

The `bound` tier is a polyfill for everyone else (Firefox, Safari, older Chromium). It uses a non-extractable Web Crypto key in IndexedDB. The JavaScript API genuinely can't export that key — so XSS can't steal it, which is why remote theft is still defeated. But the encrypted key blob does sit in the browser profile directory on disk. Infostealer malware running with the victim's privileges can read that directory and, depending on the OS keystore, decrypt it. So the polyfill defends against *remote* theft but not against *on-device* malware with disk access.

If you treat `bound` as if it were `dbsc`, you've overstated your protection to the one audience (security reviewers) who will check. Be precise: `bound` defeats remote cookie theft; only `dbsc` additionally defeats local infostealers.

## What it does not protect, at any tier

**Malware inside the browser process.** If the attacker is executing in the page or the browser itself, they have the live, authenticated session the same way the user does. They don't need to steal a cookie; they *are* the session. DBSC binds the cookie to the device — and the malware is on the device, in the browser. No cookie-binding scheme fixes this; it's a different problem (endpoint security).

**Non-cookie credentials.** DBSC binds session *cookies*. It says nothing about Primary Refresh Tokens (PRTs), Kerberos tickets, OAuth refresh tokens stored outside the cookie jar, or API keys in a config file. If your real session-bearing secret isn't the cookie DBSC bound, DBSC isn't protecting it. This catches people in enterprise SSO setups where the cookie is only one link in the chain.

**Devices without the hardware.** No TPM, no Secure Enclave, no native tier — the user falls back to the polyfill (weaker, as above) or to nothing. You don't get hardware binding on hardware that can't do it.

**Authentication itself.** A session exists *before* DBSC binds it. DBSC protects an already-authenticated session; it is not a login mechanism and not a replacement for MFA. It makes a stolen post-login cookie useless — it does nothing about phishing the login itself.

## The window between refreshes

Session-level binding (registration + refresh) re-checks the key on a cycle — say every ten minutes. Between two checks, a cookie stolen *just now* is still valid, because the next signature check hasn't happened yet. That's a real, if small, window.

Closing it requires the optional per-request proof: a signature on individual sensitive requests, not just on refresh. With that in place on a guarded route, a stolen cookie fails on the *first* such request rather than surviving until the next refresh. It's opt-in per route because it has a cost (the client signs each guarded call), and many apps accept the refresh-cycle window for everything except payments and credential changes. The point is to know the window exists and decide deliberately, route by route, rather than assume binding is instantaneous everywhere.

## How to think about adopting it

DBSC isn't a silver bullet and it isn't snake oil. It's a sharp tool with a clean edge:

- It eliminates the most common real-world takeover (remote cookie replay) for essentially all modern browsers.
- It gives you a *stronger* guarantee on Chromium-with-TPM (defeats local infostealers too) and an honest, weaker-but-still-useful one everywhere else.
- It does not absolve you of endpoint security, MFA, protecting non-cookie credentials, or guarding the login itself.

The right mental model is defense in depth, not replacement. DBSC closes the cookie-replay door — the door attackers walk through most often — while leaving the others exactly where they were. That's worth a lot, precisely because it's a specific, verifiable claim and not a vague "more secure."

If you want the mechanics behind these guarantees, I wrote up [how the protocol actually works](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/docs/blog/dbsc-explained.md) and the [full server-side threat model](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/blob/main/docs/security/threat-model.md) is public. The honest boundary is the selling point: you can hand it to a security team and every line holds up.
