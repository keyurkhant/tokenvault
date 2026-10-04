# TokenVault — Roadmap & Future Work

This document covers every planned improvement, the technical background behind advanced privacy-preserving techniques, and a daily-commit breakdown so progress is always visible.

---

## Table of Contents

1. [Current State (v0.1)](#current-state-v01)
2. [v0.2 — Core Hardening](#v02--core-hardening-2-weeks)
3. [v0.3 — Advanced Privacy Techniques](#v03--advanced-privacy-techniques)
   - [Dual Hashing](#dual-hashing-hmac--bloom-filter)
   - [Bloom Filter PPRL / CLK](#bloom-filter-pprl--cryptographic-linkage-keys-clk)
   - [Full PSI Implementation](#full-private-set-intersection-psi)
   - [Differential Privacy](#differential-privacy-noise)
4. [v0.4 — Enterprise Key Management](#v04--enterprise-key-management)
5. [v0.5 — Governance Packs](#v05--governance-packs-gdpr-hipaa-ccpa)
6. [v0.6 — Ecosystem Integrations](#v06--ecosystem-integrations)
7. [v0.7 — Observability & Operations](#v07--observability--operations)
8. [Daily Commit Plan](#daily-commit-plan)

---

## Current State (v0.1)

| Area | What exists |
|---|---|
| Tokenizers | HMAC-SHA256 · AES-SIV · Argon2id · UUID |
| Normalizers | Email · Name · Phone · DOB · Address · NatID · Custom |
| Matchers | Exact · Ngram · Jaro-Winkler · Levenshtein · Soundex · Metaphone · Composite |
| Key stores | Direct · Env · File (plaintext JSON) |
| Policy | FieldRule · RegionRule · PurposeRule · PIPEDA default ruleset |
| Audit | PythonLogging · Stdout · File (JSONL) · Redactor |
| Transfer | TransferPayload · TransferManifest · PSI stub |
| CLI | `tokenize` (CSV→CSV) · `audit` (JSONL pretty-print) |

**Known gaps carried from review:** `from_config()` classmethod · `rotate_batch()` · `match` CLI subcommand · encrypted FileKeyStore · CLI transfer manifest sidecar.

---

## v0.2 — Core Hardening (2 weeks)

Fixes gaps from v0.1 review. Every item below maps to one daily commit.

### Day 1 — `TokenVault.from_config(path)`

```python
vault = TokenVault.from_config("policy.toml")
```

TOML schema:
```toml
[vault]
region = "CA"
consent_reference = "consent-v2"

[key_store]
backend = "env"          # "direct" | "env" | "file"
prefix  = "TV_KEY_"

[tokenizer]
algorithm = "hmac-sha256"  # "hmac-sha256" | "aes-siv" | "argon2" | "uuid"

[[matchers]]
name      = "exact"
algorithm = "exact"

[[matchers]]
name      = "fuzzy"
algorithm = "jaro-winkler"
threshold = 0.85

[policy]
ruleset = "pipeda"       # "pipeda" | "none" | path to custom module

[audit]
sink    = "logging"      # "logging" | "stdout" | "file"
path    = "audit.jsonl"  # only for sink = "file"
```

**Files:** `tokenvault/config.py` (add `from_config`), `tokenvault/config_loader.py` (new), `tests/unit/test_config_loader.py`

---

### Day 2 — `TokenVault.rotate_batch(records, new_key_id)`

Re-tokenizes a list of `TokenResult` objects under a new key without requiring access to the original raw values. Only works for deterministic tokenizers (HMAC-SHA256, AES-SIV).

```python
old_results: list[TokenResult] = [...]
new_results = vault.rotate_batch(old_results, new_key_id="v2")
# Emits operation="key_rotation" audit event per record
```

For HMAC (deterministic): re-derive by fetching original field — impossible without raw values. So `rotate_batch` works only on AES-SIV (detokenize → re-tokenize under new key). For HMAC, expose a `retoken(field, old_key_id, new_key_id)` that requires the original `PIIField`.

**Files:** `tokenvault/vault.py`, `tests/unit/test_vault.py`

---

### Day 3 — Encrypted `FileKeyStore`

Replace the plaintext JSON backend with an AES-256-GCM encrypted file. Master passphrase comes from an env var; key is derived via scrypt.

```python
store = FileKeyStore(
    path="keys.enc",
    passphrase_env="TOKENVAULT_MASTER_PASS",  # read at load time
)
```

File format (binary): `[4-byte version][16-byte scrypt salt][12-byte GCM nonce][ciphertext]`

The plaintext inside ciphertext is the same JSON schema as today.

**Files:** `tokenvault/keys/file.py` (add `EncryptedFileKeyStore`), keep old `FileKeyStore` with deprecation warning, `tests/unit/test_key_stores.py`

---

### Day 4 — CLI `match` subcommand

```bash
tokenvault match \
  --tokens-a tokens_a.csv \
  --tokens-b tokens_b.csv \
  --algorithm exact \
  --threshold 0.9 \
  --output matches.csv
```

Reads two CSV files of tokens (produced by `tokenvault tokenize`), runs the matcher, outputs matching pairs with scores.

**Files:** `tokenvault/cli/commands.py`, `tests/unit/test_cli.py`

---

### Day 5 — Transfer manifest sidecar from CLI

When `tokenvault tokenize` runs, emit a `<output>_manifest.json` sidecar describing `{column: FieldMapping}` for every tokenized column. This makes the output cross-border-ready without manual manifest construction.

**Files:** `tokenvault/cli/commands.py`, `tokenvault/transfer/manifest.py` (add `from_tokenize_run`)

---

### Day 6 — `EnvKeyStore` explicit encoding

Replace the hex-vs-raw heuristic with an explicit `TOKENVAULT_KEY_ENCODING` env var (`hex` | `base64` | `raw`). Default `hex` for backward compatibility.

```bash
TOKENVAULT_KEY_ENCODING=base64
TOKENVAULT_KEY_V1=<base64-encoded 32-byte key>
```

**Files:** `tokenvault/keys/env.py`, `tests/unit/test_key_stores.py`

---

### Day 7 — `TokenizationError` wrapper

Wrap all tokenizer internals so backend errors (`InvalidTag`, `ValueError`, `binascii.Error`) never propagate raw exception messages that could include ciphertext fragments or key material.

```python
class TokenizationError(Exception):
    field_type: str
    operation: str  # "tokenize" | "detokenize"
    # cause is suppressed: raise TokenizationError(...) from None
```

**Files:** `tokenvault/protocols/tokenizer.py`, all tokenizer implementations, `tests/`

---

### Day 8 — `DirectKeyStore` multi-key rotation helper

```python
store = DirectKeyStore.from_rotation(
    keys={"v1": old_key, "v2": new_key},
    current_key_id="v2",
)
```

Plus a `list_key_ids()` method on all KeyStore implementations for introspection.

**Files:** `tokenvault/keys/direct.py`, `tokenvault/protocols/key_store.py`

---

### Day 9 — Hypothesis property tests for all normalizers

Extend the existing hypothesis tests (currently only email + name) to cover phone, DOB, address, and national ID. Assert that:
- Normalizers are idempotent: `norm(norm(v)) == norm(v)` for all field types
- Empty string always returns empty string
- Non-ASCII Unicode does not raise

**Files:** `tests/unit/test_normalizers.py`

---

### Day 10 — `audit` CLI filter flags

```bash
tokenvault audit events.jsonl \
  --operation tokenize \
  --field-type email \
  --outcome denied \
  --since 2026-10-01T00:00:00Z \
  --until 2026-10-31T23:59:59Z
```

Parse JSONL and filter by these fields before pretty-printing.

**Files:** `tokenvault/cli/commands.py`, `tests/unit/test_cli.py`

---

## v0.3 — Advanced Privacy Techniques

### Dual Hashing: HMAC + Bloom Filter

**Why dual hashing?**

HMAC-SHA256 alone gives deterministic exact-match tokens: same input → same output. This is great for exact record linkage but useless when records differ due to typos, formatting, or transcription errors. Fuzzy matchers (Jaro-Winkler, Levenshtein) work on raw normalized values, which means both parties need to share raw or normalized PII to run them.

Dual hashing solves this by producing **two representations per field**:

| Representation | Use case | Reveals raw value? |
|---|---|---|
| `HMAC(key, "field_type:normalized_value")` | Exact match across systems | No |
| Bloom filter bit vector of n-grams | Approximate match across systems | No (one-way) |

Both are derived from the same normalized value under a shared secret key, so two systems with the same key and the same source record will produce the same HMAC token AND the same Bloom filter bit vector — without ever sharing the raw value.

---

### Bloom Filter PPRL / Cryptographic Linkage Keys (CLK)

**Algorithm:**

1. For a field value `v` (already normalized), extract character bigrams and trigrams:
   ```
   "john" → {"jo", "oh", "hn", "joh", "ohn"}
   ```
2. For each n-gram `g`, compute `k` HMAC digests using `k` different keys (or a single key with `g||0`, `g||1`, … `g||k-1` as inputs). Each digest maps to a bit position in a filter of length `l`.
3. Set those bit positions to 1. The result is an `l`-bit Bloom filter `BF(v)`.
4. To compare two records: compute **Dice coefficient**:
   ```
   dice(BF1, BF2) = 2 × popcount(BF1 AND BF2) / (popcount(BF1) + popcount(BF2))
   ```
5. Dice ≥ threshold → approximate match.

**Security properties:**
- One-way: cannot recover `v` from `BF(v)` (hashing is irreversible)
- Keyed: `k` HMAC keys are the secret; without them the filter cannot be reproduced
- Resistant to frequency analysis if `l` is large enough relative to the universe size
- CLK mode: each party holds their own key; filters are only compared in a secure enclave or via PSI

**Limitations:**
- Bloom filters are probabilistic: false positives possible (tunable via `l` and `k`)
- Vulnerable to re-identification attacks if `l` is too small or the universe is small (e.g., phone numbers)
- Padding and record-level salt recommended to prevent frequency analysis

**Planned implementation:**

```python
from tokenvault.matchers.bloom import BloomFilterEncoder, BloomFilterMatcher

# Encode a field value into a Bloom filter bit vector
encoder = BloomFilterEncoder(
    filter_length=1024,   # bits
    num_hash_functions=30,
    ngram_sizes=(2, 3),   # bigrams + trigrams
    key=shared_key,
)
bf = encoder.encode("john smith")  # → bytes (128 bytes for 1024-bit filter)

# Match two encoded fields
matcher = BloomFilterMatcher(threshold=0.75)
result = matcher.match_encoded(bf_a, bf_b)
# result.score = Dice coefficient
# result.matched = score >= threshold
```

**Files to create:**
- `tokenvault/matchers/bloom.py` — `BloomFilterEncoder`, `BloomFilterMatcher`
- `tokenvault/matchers/clk.py` — `CLKEncoder` (multi-party variant with per-party keys)
- `tests/unit/test_matcher_bloom.py`

---

### Full Private Set Intersection (PSI)

The PSI stub currently raises `NotImplementedError`. Full PSI enables two parties to find common records without either party learning which records the other has beyond the intersection.

**OPRF-based protocol (planned):**

```
Party A (querier)           Party B (server)
──────────────────          ─────────────────
1. Blind each token:
   r = random scalar
   blinded = H(token)^r     

2. Send blinded set ──────→ 3. Evaluate PRF:
                               evaluated = blinded^server_key

                    ←─────── 4. Return evaluated set +
                               server_tokens = H(token)^server_key
                               for each server token

5. Unblind:
   result = evaluated^(1/r)  = H(token)^server_key

6. Intersection = {token : result ∈ server_tokens}
```

This requires elliptic curve arithmetic (e.g., Curve25519 via `cryptography` library).

**Planned API:**

```python
from tokenvault.transfer.psi import OPRFClient, OPRFServer

# Server setup (done once)
server = OPRFServer(key=server_key)
server_evaluated = server.evaluate(server_token_set)

# Client query
client = OPRFClient()
blinded, blindings = client.blind(query_tokens)
evaluated = server.evaluate_query(blinded)   # sent over wire
intersection = client.finalize(evaluated, blindings, server_evaluated)
```

**Files:** `tokenvault/transfer/psi.py` (replace stub), `tokenvault/transfer/psi_server.py`, `tests/unit/test_psi.py`

---

### Differential Privacy Noise

Add calibrated Laplace or Gaussian noise to fuzzy match scores before returning them, so that even the match scores don't reveal whether a near-miss record exists.

```python
from tokenvault.matchers.dp import DifferentialPrivacyWrapper

matcher = DifferentialPrivacyWrapper(
    base_matcher=JaroWinklerMatcher(threshold=0.85),
    epsilon=1.0,       # privacy budget
    sensitivity=0.1,   # max change in score per record substitution
)
result = matcher.match(token_a, token_b)
# result.score has calibrated Laplace noise added
```

**Files:** `tokenvault/matchers/dp.py`, `tests/unit/test_matcher_dp.py`

---

## v0.4 — Enterprise Key Management

### HashiCorp Vault backend

```python
from tokenvault.keys.vault import HashiCorpVaultKeyStore

store = HashiCorpVaultKeyStore(
    url="https://vault.internal:8200",
    mount="secret",
    path="tokenvault/keys",
    token_env="VAULT_TOKEN",
)
```

**Files:** `tokenvault/keys/vault_backend.py` (optional dep: `hvac`)

---

### AWS KMS / GCP KMS / Azure Key Vault adapters

Each implements `KeyStore` and wraps the respective SDK's envelope encryption pattern: the data key is stored encrypted by the KMS CMK and decrypted at runtime.

```python
from tokenvault.keys.aws_kms import AWSKMSKeyStore
from tokenvault.keys.gcp_kms import GCPKMSKeyStore
from tokenvault.keys.azure_kv import AzureKeyVaultKeyStore
```

**Optional deps:** `boto3`, `google-cloud-kms`, `azure-keyvault-secrets`

---

### Key lifecycle management

```python
store.rotate(old_key_id="v1", new_key_id="v2")
store.retire(key_id="v1", effective_date=datetime(...))
store.list_keys()           # → [KeyMetadata(id, created_at, retired_at)]
store.get_active_keys()     # → keys not yet retired
```

**Files:** `tokenvault/protocols/key_store.py` (extend protocol), `tokenvault/keys/lifecycle.py`

---

## v0.5 — Governance Packs (GDPR, HIPAA, CCPA)

Each pack is a `PolicyEngine` configuration + documentation of the legal basis.

### GDPR Pack

```python
from tokenvault.policy.gdpr import GDPR_DEFAULT_RULESET

# Enforces:
# - Explicit purpose declaration required (Art. 5(1)(b))
# - Cross-border transfers only to adequacy-listed countries (Art. 45)
#   or with standard contractual clauses declared in context
# - Special category data (health, biometric) requires explicit consent
# - Right to erasure: token invalidation via key rotation
```

### HIPAA Pack

```python
from tokenvault.policy.hipaa import HIPAA_SAFE_HARBOR_RULESET

# Enforces Safe Harbor de-identification:
# - 18 PHI identifiers must be tokenized before transfer
# - Date fields reduced to year only
# - Geographic data suppressed below county level
# - Age > 89 suppressed
```

### CCPA Pack

```python
from tokenvault.policy.ccpa import CCPA_DEFAULT_RULESET
# California Consumer Privacy Act rules
```

**Files:** `tokenvault/policy/gdpr.py`, `tokenvault/policy/hipaa.py`, `tokenvault/policy/ccpa.py`, plus tests

---

## v0.6 — Ecosystem Integrations

### Pandas / Polars UDFs

```python
import pandas as pd
from tokenvault.integrations.pandas import tokenize_series

df["email_token"] = tokenize_series(
    df["email"],
    field_type=FieldType.EMAIL,
    vault=vault,
)
```

### Apache Spark connector

```python
from tokenvault.integrations.spark import TokenVaultUDF

tokenize_udf = TokenVaultUDF(vault=vault, field_type=FieldType.EMAIL)
df = df.withColumn("email_token", tokenize_udf(df["email"]))
```

### dbt macro

```sql
-- macros/tokenize_pii.sql
{{ tokenvault.tokenize(column='email', field_type='email') }}
```

### FastAPI service wrapper

```python
# tokenvault serve --host 0.0.0.0 --port 8080 --config policy.toml
# POST /tokenize  { "field_type": "email", "value": "..." }
# POST /match     { "token_a": "...", "token_b": "...", "algorithm": "exact" }
```

---

## v0.7 — Observability & Operations

### Prometheus metrics

```python
from tokenvault.audit.sinks.prometheus import PrometheusSink

# Exposes:
# tokenvault_tokenize_total{field_type, algorithm, outcome}
# tokenvault_match_total{algorithm, matched}
# tokenvault_policy_denied_total{policy_id, field_type}
# tokenvault_key_version{key_id} (gauge)
```

### OpenTelemetry traces

```python
from tokenvault.audit.sinks.otel import OTelAuditSink
# Emits spans: tokenize, match, policy_check, key_fetch
```

### Audit log query API

```python
from tokenvault.audit.query import AuditLog

log = AuditLog("audit.jsonl")
denied = log.query(operation="tokenize", outcome="denied", since=datetime(...))
by_field = log.group_by("field_type")
```

---

## Daily Commit Plan

Sized so each item is one focused commit. Start at v0.2 Day 1 and work through in order.

```
Week 1
  Day 1  feat: add from_config() classmethod with TOML schema (config_loader.py)
  Day 2  feat: add rotate_batch() and retoken() for key rotation workflows
  Day 3  feat: add EncryptedFileKeyStore with AES-256-GCM + scrypt passphrase
  Day 4  feat: add CLI match subcommand (token CSV × token CSV → matches CSV)
  Day 5  feat: emit transfer manifest sidecar from CLI tokenize command

Week 2
  Day 6  feat: add explicit encoding flag to EnvKeyStore (hex|base64|raw)
  Day 7  feat: add TokenizationError wrapper — suppress backend exception details
  Day 8  feat: add DirectKeyStore.from_rotation() + list_key_ids() on all stores
  Day 9  test: extend hypothesis property tests to all six normalizer types
  Day 10 feat: add --operation/--field-type/--since/--until filters to audit CLI

Week 3 (v0.3 starts)
  Day 11 feat: add BloomFilterEncoder — keyed n-gram Bloom filter for PPRL
  Day 12 feat: add BloomFilterMatcher — Dice coefficient comparison of BF vectors
  Day 13 feat: add CLKEncoder — per-party keyed Bloom filter (Cryptographic Linkage Key)
  Day 14 feat: add DifferentialPrivacyWrapper — Laplace noise on match scores
  Day 15 feat: add OPRF primitives for PSI (Curve25519 blinding/unblinding)

Week 4
  Day 16 feat: complete OPRFServer and OPRFClient for full PSI protocol
  Day 17 feat: add integration test — two-party PSI over shared HMAC token set
  Day 18 feat: add GDPR policy pack (purpose, adequacy, special-category rules)
  Day 19 feat: add HIPAA Safe Harbor policy pack (18 PHI identifier rules)
  Day 20 feat: add CCPA policy pack + governance pack docs

Week 5 (v0.4)
  Day 21 feat: add HashiCorp Vault key store backend
  Day 22 feat: add AWS KMS key store adapter
  Day 23 feat: add GCP KMS key store adapter
  Day 24 feat: add key lifecycle management (rotate, retire, list)
  Day 25 docs: update README, CHANGELOG for v0.2 + v0.3 releases

Week 6 (v0.6 integrations)
  Day 26 feat: add Pandas tokenize_series and match_series UDFs
  Day 27 feat: add Polars plugin (LazyFrame expression)
  Day 28 feat: add Apache Spark TokenVaultUDF
  Day 29 feat: add FastAPI service wrapper (tokenvault serve)
  Day 30 feat: add Prometheus audit sink + metrics endpoint
```

---

## Technique Reference

### Bloom Filter PPRL — parameter selection

| Parameter | Recommendation | Notes |
|---|---|---|
| Filter length `l` | 1024 bits | Larger = fewer false positives, larger payload |
| Hash functions `k` | 30 | `k = (l/n) × ln 2` where n = expected set bits |
| N-gram sizes | bigrams + trigrams | Trigrams catch more typos in names |
| HMAC key | 32 bytes per hash function | Rotate with the field key |
| Padding | Add 3–5 random n-grams | Prevents frequency analysis on short values |

**False positive rate** at l=1024, k=30, n=50 set bits: ≈ 0.4%  
**Collision resistance**: 2^(l/2) = 2^512 for l=1024 — computationally infeasible

### PSI vs Bloom Filter — when to use which

| Criterion | Bloom Filter PPRL | OPRF-based PSI |
|---|---|---|
| Approximate matching | Yes (Dice coefficient) | No (exact only) |
| Cryptographic security | Probabilistic | Proven secure |
| Performance (n records) | O(n) | O(n log n) |
| Network rounds | 1 (send BF vectors) | 2–3 (OPRF protocol) |
| Key management | Shared HMAC key | Asymmetric (server key) |
| Re-ID risk | Present if l too small | None by construction |
| Best for | Name/address fuzzy linkage | Exact ID matching at scale |

### CLK vs standard Bloom filter

CLK (Cryptographic Linkage Key) adds per-party secret keys to the Bloom filter. Party A and Party B each hold different HMAC keys. They independently encode their records, then exchange BF vectors. Because neither party has the other's key, the BF vectors cannot be decoded — but the Dice coefficient between them remains computable and meaningful.

This removes the need for a shared secret while preserving approximate matching. It is the standard used in Australian Population Linkage Network (APLN) research and is described in Schnell et al. (2009).
