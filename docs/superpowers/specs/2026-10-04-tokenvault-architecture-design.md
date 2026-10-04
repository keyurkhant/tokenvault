# TokenVault — Architecture Design Spec

**Date:** 2026-10-04  
**Status:** Approved  
**Author:** Keyur Khant  

---

## 1. Purpose and Scope

TokenVault is a Python library for privacy-preserving tokenization and matching of personally identifiable information (PII), with first-class support for cross-border data transfer scenarios and PIPEDA compliance.

This document covers the full architectural design: package structure, core protocols, tokenization algorithms, matching strategies, key management, policy/governance engine, audit system, CLI, and security model. It is the authoritative reference for the implementation plan.

**In scope:** Python library (`tokenvault`), CLI, PIPEDA governance module, cross-border transfer utilities, audit sink system.  
**Out of scope:** hosted service, UI, biometric recognition, full identity platform, legal privacy review.

---

## 2. Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Core pattern | Protocol ABCs + thin Facade | Pluggable, testable, no forced inheritance |
| Key management | `KeyStore` abstraction (Option C) | Caller can pass key directly OR use pluggable backend |
| Matching scope | Within-system MVP + cross-system extension point | Ships useful immediately; PSI hook for future |
| Audit output | Python `logging` default + `AuditSink` ABC | Zero-config for existing apps; enterprise teams wire their own sink |
| Irreversibility default | HMAC-SHA256 + Argon2id | One-way by default; reversibility is an explicit opt-in under policy |
| Python target | 3.10+ | `match` statements, `typing.Protocol`, `dataclasses` |
| Packaging | Single pip install with optional dependency groups | `tokenvault[cli]`, `tokenvault[argon2]`, `tokenvault[aes-siv]` |

---

## 3. Package Structure

```
tokenvault/
├── tokenvault/
│   ├── __init__.py              # public re-exports, __version__
│   ├── vault.py                 # TokenVault facade
│   ├── config.py                # VaultConfig, FieldPolicy, RegionPolicy
│   │
│   ├── protocols/               # Python Protocol ABCs — zero implementation
│   │   ├── __init__.py
│   │   ├── tokenizer.py         # Tokenizer, TokenResult
│   │   ├── normalizer.py        # Normalizer
│   │   ├── matcher.py           # Matcher, MatchResult
│   │   ├── key_store.py         # KeyStore
│   │   ├── audit_sink.py        # AuditSink, AuditEvent
│   │   └── policy_guard.py      # PolicyGuard, PolicyDecision
│   │
│   ├── fields/                  # PII field type definitions + built-in normalizers
│   │   ├── __init__.py
│   │   ├── base.py              # FieldType enum, PIIField dataclass
│   │   ├── email.py             # EmailNormalizer
│   │   ├── name.py              # NameNormalizer
│   │   ├── phone.py             # PhoneNormalizer (E.164)
│   │   ├── address.py           # AddressNormalizer
│   │   ├── dob.py               # DateOfBirthNormalizer (ISO-8601)
│   │   ├── national_id.py       # NationalIDNormalizer
│   │   └── custom.py            # CustomField, UserDefinedNormalizer
│   │
│   ├── tokenizers/              # Tokenization strategy implementations
│   │   ├── __init__.py
│   │   ├── hmac_sha256.py       # Deterministic keyed HMAC-SHA256
│   │   ├── aes_siv.py           # Format-preserving AES-SIV (reversible, policy-gated)
│   │   ├── argon2_opaque.py     # Non-deterministic Argon2id (truly irreversible)
│   │   └── uuid_random.py       # Non-deterministic UUIDv4 (opaque reference)
│   │
│   ├── matchers/                # Matching strategy implementations
│   │   ├── __init__.py
│   │   ├── exact.py             # ExactTokenMatcher
│   │   ├── jaro_winkler.py      # JaroWinklerMatcher
│   │   ├── levenshtein.py       # LevenshteinMatcher
│   │   ├── phonetic.py          # SoundexMatcher, MetaphoneMatcher
│   │   ├── ngram.py             # NgramSimilarityMatcher
│   │   └── composite.py        # CompositeMatcher (weighted multi-algorithm)
│   │
│   ├── keys/                    # KeyStore implementations
│   │   ├── __init__.py
│   │   ├── direct.py            # DirectKeyStore (caller passes raw bytes)
│   │   ├── env.py               # EnvKeyStore (reads from env vars)
│   │   └── file.py              # FileKeyStore (reads from encrypted file)
│   │
│   ├── policy/                  # Policy engine + PIPEDA governance
│   │   ├── __init__.py
│   │   ├── engine.py            # PolicyEngine, RuleSet
│   │   ├── rules.py             # FieldRule, RegionRule, PurposeRule
│   │   ├── pipeda.py            # PIPEDA_DEFAULT_RULESET (conservative defaults)
│   │   └── decision.py          # PolicyDecision, DecisionReason
│   │
│   ├── audit/                   # Audit event system
│   │   ├── __init__.py
│   │   ├── event.py             # AuditEvent dataclass (no raw PII fields)
│   │   ├── redactor.py          # PII redactor for safe log surfaces
│   │   └── sinks/
│   │       ├── __init__.py
│   │       ├── stdout.py        # StdoutAuditSink
│   │       ├── file.py          # FileAuditSink (JSONL append-only)
│   │       └── logging.py       # PythonLoggingAuditSink (default)
│   │
│   ├── transfer/                # Cross-border transfer utilities
│   │   ├── __init__.py
│   │   ├── payload.py           # TransferPayload builder (token-only export)
│   │   ├── manifest.py          # TransferManifest (field map, policy ref)
│   │   └── psi.py               # PSI hook stub (cross-system matching)
│   │
│   └── cli/                     # CLI entry point
│       ├── __init__.py
│       └── commands.py          # tokenize, match, audit subcommands
│
├── tests/
│   ├── unit/                    # per-module unit tests
│   ├── integration/             # end-to-end vault + pipeline tests
│   └── fixtures/                # synthetic PII only — no real data ever committed
│
├── docs/
│   ├── superpowers/specs/       # architecture design docs (this file)
│   └── usage/                   # consumer-facing usage guides
│
├── pyproject.toml
├── SPEC.md
└── README.md
```

**Architectural invariant:** nothing inside `tokenizers/`, `matchers/`, `keys/`, `policy/`, or `audit/` imports from any other domain module. All cross-domain wiring lives exclusively in `vault.py` and `config.py`. This enforces independent testability and prevents circular imports.

---

## 4. Core Protocols

All capabilities are expressed as Python `typing.Protocol` (structural subtyping). No forced inheritance. Any class satisfying the shape qualifies — including third-party classes the library has never seen.

### 4.1 `TokenResult`

```python
@dataclass(frozen=True)
class TokenResult:
    token: str           # opaque base64url-encoded string, safe to log
    field_type: str
    algorithm: str       # "hmac-sha256" | "aes-siv" | "argon2id" | "uuid-v4"
    key_version: str     # for rotation tracking
    is_deterministic: bool
```

Frozen dataclass — immutable after creation.

### 4.2 `Tokenizer`

```python
class Tokenizer(Protocol):
    def tokenize(self, value: str, field_type: str) -> TokenResult: ...
    def supports_field(self, field_type: str) -> bool: ...
```

### 4.3 `Normalizer`

```python
class Normalizer(Protocol):
    def normalize(self, value: str) -> str: ...
```

### 4.4 `Matcher` and `MatchResult`

```python
@dataclass(frozen=True)
class MatchResult:
    score: float         # 0.0–1.0
    algorithm: str
    threshold: float
    matched: bool
    # raw values are never stored here

class Matcher(Protocol):
    def match(self, token_a: str, token_b: str) -> MatchResult: ...
```

### 4.5 `KeyStore`

```python
class KeyStore(Protocol):
    def get_key(self, key_id: str) -> bytes: ...
    def get_current_key_id(self) -> str: ...
```

### 4.6 `AuditEvent` and `AuditSink`

```python
@dataclass(frozen=True)
class AuditEvent:
    event_id: str        # UUID4
    timestamp: datetime
    operation: str       # "tokenize" | "match" | "transfer" | "policy_deny"
    field_type: str
    algorithm: str
    key_version: str
    policy_id: str
    outcome: str         # "success" | "denied" | "error"
    metadata: dict       # safe key/value only — no raw PII ever

class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...
```

### 4.7 `PolicyGuard` and `PolicyDecision`

```python
@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    policy_id: str
    reason: str

class PolicyGuard(Protocol):
    def evaluate(self, field_type: str, operation: str, context: dict) -> PolicyDecision: ...
```

---

## 5. Tokenization Algorithms and Irreversibility Model

### 5.1 `HMACTokenizer` — Deterministic, keyed, irreversible

```
token = base64url( HMAC-SHA256( key, field_type + ":" + normalize(value) ) )
```

- **Irreversibility:** HMAC-SHA256 is a one-way PRF. Without the 256-bit key, brute force requires `2^256` operations — computationally infeasible.
- **Domain separation:** `field_type + ":"` prefix prevents cross-field correlation attacks. An email token can never collide with a name token for the same raw value.
- **Deterministic:** same key + same normalized input → identical token. Enables exact matching.
- **Use for:** record linkage, cross-border transfer, exact-match workflows.

### 5.2 `AESSIVTokenizer` — Format-preserving, reversible (policy-gated)

```
ciphertext = AES-SIV-256( key, normalize(value) )
```

- **Reversibility:** explicitly reversible — requires the key. `detokenize()` is only callable when `PolicyGuard` returns `allow_reversible=True`.
- **AES-SIV** (not AES-CBC or AES-GCM): nonce-misuse-resistant. Safe against nonce reuse bugs. Deterministic.
- **Use for:** cases where the original value must be recoverable within a trust boundary under strict policy control.

### 5.3 `Argon2OpaqueTokenizer` — Non-deterministic, memory-hard, truly irreversible

```
token = base64url( Argon2id(
    password = normalize(value),
    salt     = secrets.token_bytes(32),   # random per call
    time_cost    = 3,
    memory_cost  = 65536,                 # 64 MiB
    parallelism  = 4
) )
```

- **Irreversibility:** Argon2id is memory-hard and computationally expensive. Designed to defeat GPU/ASIC brute-force attacks.
- **Non-deterministic:** random salt → different token every call. Verification requires re-computing with the stored salt.
- **Use for:** storing tokens where you only ever need to verify ("does this email match?"), never link or join. Highest privacy mode.

### 5.4 `UUIDRandomTokenizer` — Non-deterministic, opaque reference

```
token = str( uuid.UUID(bytes=secrets.token_bytes(16), version=4) )
```

- **Irreversibility:** UUID has no mathematical relationship to the input. Only reversible via a caller-managed lookup table.
- **Use for:** creating opaque reference IDs where the library carries zero information about the original value.

### 5.5 Security Hardening Applied to All Strategies

| Concern | Mitigation |
|---|---|
| Key entropy | `KeyStore` enforces minimum 256-bit (32-byte) keys; raises `KeyEntropyError` if below threshold |
| Timing attacks | All token comparisons use `hmac.compare_digest()` — never `==` |
| Secure randomness | Only `secrets` module in all crypto paths; `random` is never imported |
| Memory safety | Raw PII stored in `memoryview` during processing; explicit `del` after use |
| PII in exceptions | `TokenizationError` stores `field_type` + `operation` only — never the raw value |
| Key rotation | Every `TokenResult` carries `key_version`; `Vault.rotate(batch)` re-tokenizes under new key |
| Per-field key isolation | `KeyStore.get_key(key_id)` receives `field_type` as part of `key_id`; email and name keys are always separate |
| Token opacity | All tokens are fixed-length base64url strings — no structure leaks field type or algorithm |
| No raw PII in logs | `redactor.py` scrubs strings matching PII patterns before they reach any log surface |
| Safe defaults | `HMACTokenizer` is the default; reversible `AESSIVTokenizer` requires explicit `allow_reversible=True` in policy |

---

## 6. Matching Strategies

### 6.1 Exact Matching

`ExactTokenMatcher` compares two `TokenResult.token` values using `hmac.compare_digest()`. Only valid for tokens from the same deterministic strategy and key. Cross-system exact matching requires both systems to share a key and normalization contract.

### 6.2 Fuzzy Matching

Fuzzy matching always operates on **normalized values**, never on raw values. `MatchResult` carries only a score — raw values are never stored in results or audit events.

| Matcher | Best for | Algorithm |
|---|---|---|
| `JaroWinklerMatcher` | Name similarity | Jaro-Winkler; weights prefix agreement |
| `LevenshteinMatcher` | General edit distance, typos | Classic Levenshtein with configurable max distance |
| `PhoneticMatcher` | Name pronunciation variants | Soundex + Double Metaphone combined |
| `NgramMatcher` | Short strings, addresses | Character n-gram Jaccard similarity |
| `CompositeMatcher` | High-stakes identity matching | Weighted average of multiple matchers; weights configurable per field type |

All matchers accept a `threshold: float` at construction time. `MatchResult.matched` is `True` only when `score >= threshold`.

### 6.3 Cross-System Matching (PSI Extension Point)

`transfer/psi.py` ships as a documented stub implementing the `Matcher` protocol. It defines the interface for an Oblivious Pseudo-Random Function (OPRF) based Private Set Intersection protocol — the cryptographic foundation for two parties to find common records without revealing their full sets.

The stub raises `NotImplementedError` with full docstring explaining the OPRF handshake expected, so future implementers have a clear contract. The MVP cross-system approach (shared HMAC key + normalization contract) works through `ExactTokenMatcher` with a shared `KeyStore`.

---

## 7. Key Management

### 7.1 `DirectKeyStore`
Caller passes key bytes directly. No lifecycle management. Simplest option.

```python
store = DirectKeyStore(keys={"email-v1": b"<32 bytes>"})
```

### 7.2 `EnvKeyStore`
Reads keys from environment variables. Variable names follow the pattern `TOKENVAULT_KEY_{KEY_ID}` (uppercased, hyphens replaced with underscores).

```python
store = EnvKeyStore(prefix="TOKENVAULT_KEY_")
```

### 7.3 `FileKeyStore`
Reads keys from an encrypted TOML file. File is decrypted using a master passphrase from an env var. Ships with a `tokenvault keys generate` CLI command to create and manage key files.

### 7.4 Key Rotation
Every `TokenResult` carries a `key_version` string. When a key rotates, old tokens remain valid (old key is retained in the store under the old version ID). `TokenVault.rotate_batch(records, new_key_id)` re-tokenizes a batch and emits a `AuditEvent` per record with `operation="key_rotation"`.

---

## 8. Policy Engine and PIPEDA Governance

### 8.1 Rule Types

- **`FieldRule`**: declares which field types are allowed for which operations (`tokenize`, `match`, `transfer`, `detokenize`).
- **`RegionRule`**: maps ISO 3166-1 country codes to allowed operations. Cross-border transfers from `CA` origin require PIPEDA rules.
- **`PurposeRule`**: requires a declared `purpose` string in the operation context. Operations without a matching purpose are denied.

### 8.2 `PolicyEngine`

Composes one or more `RuleSet` objects. Evaluates them in order; first denial wins. Returns a `PolicyDecision` with `allowed`, `policy_id`, and `reason`.

### 8.3 PIPEDA Default Rule Set

`policy/pipeda.py` ships `PIPEDA_DEFAULT_RULESET` — conservative defaults aligned with PIPEDA's 10 Fair Information Principles:

| PIPEDA Principle | Library Response |
|---|---|
| Accountability | `AuditEvent` per operation; `TransferManifest` for cross-border export |
| Identifying Purposes | `PurposeRule` — tokenization only permitted for declared purpose |
| Consent | `VaultConfig.consent_reference` field for caller to populate; library cannot enforce consent |
| Limiting Collection | `FieldPolicy` declares permitted fields; all others rejected |
| Limiting Use/Disclosure | `PolicyGuard` blocks operations not matching declared purpose |
| Accuracy | Normalization pipeline corrects formatting before tokenization |
| Safeguards | Key entropy enforcement, no PII in logs, secure defaults |
| Openness | `TransferManifest` documents transformation rules in machine-readable form |
| Individual Access | `detokenize()` path (AES-SIV only) gated by `allow_reversible=True` policy |
| Challenging Compliance | `AuditSink` provides evidence for compliance review |

Teams start with `PIPEDA_DEFAULT_RULESET` and selectively relax rules. GDPR and CCPA rule sets are designed as additional `RuleSet` modules.

---

## 9. Audit System

### 9.1 Event Structure
Every operation touching a `PIIField` emits exactly one `AuditEvent`. The event carries operation metadata only — never raw field values.

### 9.2 Sinks

| Sink | Behavior |
|---|---|
| `PythonLoggingAuditSink` | Routes to `logging.getLogger("tokenvault.audit")` at INFO level. **Default.** Zero config for apps that already configure logging. |
| `FileAuditSink` | Appends JSONL (one JSON object per line) to a specified file. Ingestible by any SIEM. |
| `StdoutAuditSink` | Prints formatted events to stdout. Useful for CLI and development. |

Custom sinks implement the single-method `AuditSink` protocol.

### 9.3 `Redactor`
`audit/redactor.py` provides a `Redactor` utility that pattern-matches strings against known PII signatures (email regex, phone regex, numeric sequences) and replaces them with `[REDACTED]`. Applied defensively inside exception handlers and all debug paths.

---

## 10. Cross-Border Transfer Utilities

### 10.1 `TransferPayload`
Builder that assembles a transfer-ready record from `TokenResult` objects. Guarantees no raw PII fields are present in the output. Serializes to JSON or CSV.

### 10.2 `TransferManifest`
Machine-readable document describing: source region, destination region, field map (field name → tokenization algorithm + key version), policy ID, timestamp, and consent reference. Attached to every cross-border transfer for PIPEDA accountability.

### 10.3 PSI Stub
`transfer/psi.py` documents the OPRF-based Private Set Intersection interface. MVP cross-system matching uses shared HMAC key + `ExactTokenMatcher`. Full PSI is a post-MVP extension.

---

## 11. CLI

Three subcommands via `argparse` (no heavy framework dependency):

```bash
# Tokenize a CSV of PII records under a policy
tokenvault tokenize --config policy.toml --input records.csv --output tokens.csv

# Match two tokenized datasets
tokenvault match --config policy.toml --left a.csv --right b.csv --fields name,email

# Query an audit log
tokenvault audit --log audit.jsonl --from 2024-01-01 --to 2024-01-31 --field email
```

Installed via `tokenvault[cli]` optional dependency group.

---

## 12. Testing Strategy

| Layer | Tool | What it covers |
|---|---|---|
| Unit | `pytest` | Per-module, mocked dependencies |
| Property-based | `hypothesis` | "normalized email is always lowercase and stripped", "HMAC of same input is always same output", etc. |
| Integration | `pytest` | `TokenVault.from_config()` end-to-end with synthetic PII fixtures |
| Security | `pytest` | Timing attack resistance, key entropy rejection, no-PII-in-logs assertion on every audit path |

**Rule:** no real PII ever committed to the repository. `tests/fixtures/` contains only programmatically generated synthetic data.

`conftest.py` provides:
- `vault_fixture`: `TokenVault` with a `DirectKeyStore` pre-loaded with a 256-bit test key
- `synthetic_pii_record`: generates realistic-looking but fabricated PII records
- `audit_capture`: in-memory `AuditSink` that collects events for assertion

---

## 13. `pyproject.toml` Dependency Groups

```toml
[project]
name = "tokenvault"
requires-python = ">=3.10"
dependencies = []  # zero required runtime dependencies

[project.optional-dependencies]
argon2    = ["argon2-cffi>=23.0"]
aes-siv   = ["cryptography>=42.0"]
cli       = ["tomllib"]         # stdlib in 3.11+; backport for 3.10
fuzzy     = ["jellyfish>=1.0"]  # Jaro-Winkler, Levenshtein, Soundex, Metaphone
phone     = ["phonenumbers>=8.0"]
all       = ["tokenvault[argon2,aes-siv,cli,fuzzy,phone]"]
dev       = ["pytest", "hypothesis", "pytest-cov", "ruff", "mypy"]
```

Core library has **zero required runtime dependencies**. `HMACTokenizer` and `UUIDRandomTokenizer` use only stdlib (`hmac`, `hashlib`, `secrets`, `uuid`). Heavier algorithms are opt-in.

---

## 14. Facade: `TokenVault`

The public entry point for the 80% use case:

```python
# Simple path
vault = TokenVault.from_config("policy.toml")
result = vault.tokenize({"email": "jane@example.com", "name": "Jane Smith"})
# → {"email": TokenResult(...), "name": TokenResult(...)}

match = vault.match(result_a["name"], result_b["name"])
# → MatchResult(score=0.94, matched=True, algorithm="jaro-winkler")

payload = vault.build_transfer_payload(result, destination_region="US")
# → TransferPayload (no raw PII, manifest attached)

# Power-user path (bypass facade, use protocols directly)
normalizer = EmailNormalizer()
tokenizer = HMACTokenizer(key_store=EnvKeyStore())
token = tokenizer.tokenize(normalizer.normalize("Jane@Example.COM"), "email")
```

`TokenVault` is the only class that wires across domain boundaries. All other modules are independently usable.

---

## 15. What Comes Next (Post-MVP Extension Points)

| Feature | Extension Point |
|---|---|
| Full PSI cross-system matching | `psi.py` stub → implement OPRF handshake |
| GDPR/CCPA rule sets | New `RuleSet` in `policy/` |
| KMS key backends | Implement `KeyStore` protocol (AWS KMS, HashiCorp Vault) |
| Multi-tenant policy | `PolicyEngine` already accepts multiple `RuleSet` objects |
| OpenTelemetry audit sink | Implement `AuditSink` protocol |
| Async batch pipeline | `TokenVault.tokenize_batch_async()` using `asyncio` |
| Additional field normalizers | Implement `Normalizer` protocol per new field type |
