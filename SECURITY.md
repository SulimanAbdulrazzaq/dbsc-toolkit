# Security

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Use [GitHub's private vulnerability reporting](https://github.com/SulimanAbdulrazzaq/dbsc-toolkit/security/advisories/new) on this repository. That gives the maintainer a private channel and an audit trail without exposing the issue while it's being fixed.

Include:
- A description of the vulnerability.
- Steps to reproduce.
- An impact assessment if you have one.

I will try to acknowledge within a few days. Fix timelines depend on severity. You will be credited in the release notes unless you prefer to remain anonymous.

## Threat model

DBSC Toolkit mitigates session hijacking via cookie theft. It assumes:

- TLS is enforced end-to-end.
- The server itself is not compromised.
- The user's device TPM is functional and not tampered with.

It does not protect against:

- Server-side session store compromise. Use encrypted storage at rest and treat the bound JWK store like password hashes.
- Malware with kernel-level access that can interface with the TPM directly. That is an OS-level concern, not a library-level one.
- Phishing attacks that intercept the initial authentication step. DBSC binds an existing session — it does not authenticate the user.
- HMAC tier signal spoofing. An attacker who can replicate the browser signal bundle can forge HMAC-tier tokens. The HMAC tier is best-effort context binding, not hardware binding.

See [docs/security/threat-model.md](./docs/security/threat-model.md) for the STRIDE analysis.

## Dependency policy

Direct dependencies are kept to a minimum (`jose`, `@simplewebauthn/server`). All framework and database integrations are optional peer dependencies, so the consumer controls those versions.

CodeQL runs on every push to `main` via GitHub Actions.
