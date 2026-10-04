# Changelog

All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-10-04

### Added

- `TokenVault` facade with `tokenize`, `tokenize_record`, `match`, and `detokenize` operations
- `VaultConfig` dataclass wiring key store, tokenizer, matchers, policy guard, audit sink, and normalizers
- **Tokenizers**: `HMACTokenizer` (HMAC-SHA256, deterministic), `AESSIVTokenizer` (AES-256-SIV, reversible, policy-gated), `Argon2OpaqueTokenizer` (Argon2id, non-deterministic), `UUIDRandomTokenizer` (opaque reference)
- **Normalizers**: `EmailNormalizer`, `NameNormalizer`, `PhoneNormalizer`, `DateOfBirthNormalizer`, `AddressNormalizer`, `NationalIDNormalizer`, `PassthroughNormalizer`
- **Key stores**: `DirectKeyStore`, `EnvKeyStore`, `FileKeyStore` — all enforce 256-bit (32-byte) minimum key entropy
- **Matchers**: `ExactTokenMatcher`, `NgramSimilarityMatcher`, `JaroWinklerMatcher`, `LevenshteinMatcher`, `SoundexMatcher`, `MetaphoneMatcher`, `CompositeMatcher` (weighted average)
- **Policy engine**: `PolicyEngine`, `FieldRule`, `RegionRule`, `PurposeRule`, `PIPEDA_DEFAULT_RULESET`
- **Audit system**: `AuditEvent` (frozen dataclass, auto UUID4 event ID, auto UTC timestamp, `MappingProxyType` metadata), `PythonLoggingAuditSink`, `StdoutAuditSink`, `FileAuditSink`, `Redactor`
- **Transfer utilities**: `TransferPayload`, `TransferManifest`, `FieldMapping`, `PrivateSetIntersectionMatcher` (OPRF stub)
- **CLI**: `tokenvault tokenize` (CSV in → CSV out), `tokenvault audit` (JSONL pretty-print)
- `py.typed` marker for PEP 561 typed-package compliance
- GitHub Actions CI workflow across Python 3.10 – 3.13
- Architecture diagrams: `docs/diagrams/hld.excalidraw`, `docs/diagrams/lld.excalidraw`

### Security

- All token comparisons use `hmac.compare_digest()` — constant-time
- All cryptographic randomness via `secrets` module only
- `AESSIVTokenizer._detokenize()` only reachable through the policy-gated `TokenVault.detokenize()`
- No raw PII in `AuditEvent`, logs, exceptions, or `repr` output (`PIIField.__repr__` redacts value)
- `AuditEvent.metadata` is a `MappingProxyType` — immutable after construction

[Unreleased]: https://github.com/keyurkhant/tokenvault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/keyurkhant/tokenvault/releases/tag/v0.1.0
