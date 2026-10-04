# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **keyurkhant@gmail.com** with:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept (no live PII please)
- The affected versions

You will receive an acknowledgement within 48 hours and a resolution timeline within 5 business days.

## Scope

In scope:
- Timing side-channels in token comparison or key derivation
- Key material leaking into logs, exceptions, or audit events
- Policy guard bypasses — operations that succeed when they should be denied
- Normalization collisions that link unrelated records

Out of scope:
- Issues requiring physical access to the host machine
- Social engineering
- Vulnerabilities in optional dependencies (`argon2-cffi`, `cryptography`, `jellyfish`)

## Security design

See the [architecture spec](docs/superpowers/specs/2026-10-04-tokenvault-architecture-design.md) for the full threat model. Key invariants:

- All token comparisons use `hmac.compare_digest()` — constant-time, timing-attack resistant
- All cryptographic randomness via `secrets` module only
- Minimum key length of 32 bytes (256 bits) enforced at construction
- No raw PII in `AuditEvent`, logs, exceptions, or `repr` output
- `AESSIVTokenizer._detokenize()` is only reachable via `TokenVault.detokenize()`, which requires a `PolicyGuard` allow decision
