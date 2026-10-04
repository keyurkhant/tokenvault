# TokenVault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `tokenvault` Python library — privacy-preserving PII tokenization, fuzzy matching, PIPEDA governance, audit sinks, cross-border transfer utilities, and CLI.

**Architecture:** Protocol ABCs define every capability boundary; concrete implementations live in domain modules; a thin `TokenVault` facade wires them for the 80% use case. Nothing in `tokenizers/`, `matchers/`, `keys/`, `policy/`, or `audit/` imports from any other domain module — all cross-domain wiring lives in `vault.py` and `config.py`.

**Tech Stack:** Python 3.10+, stdlib-only core (`hmac`, `hashlib`, `secrets`, `uuid`, `logging`, `argparse`), optional: `argon2-cffi`, `cryptography`, `jellyfish`, `phonenumbers`, `pytest`, `hypothesis`.

**Spec:** `docs/superpowers/specs/2026-10-04-tokenvault-architecture-design.md`

## Global Constraints

- Python >= 3.10 everywhere; use `match` statements, `typing.Protocol`, `dataclasses`
- Zero required runtime dependencies — core works with stdlib only
- All token comparisons use `hmac.compare_digest()` — never `==`
- Only `secrets` module in crypto paths — `random` is never imported in any tokenizer
- Raw PII must never appear in `TokenResult`, `MatchResult`, `AuditEvent`, exceptions, or logs
- Minimum key size: 32 bytes (256 bits); `KeyEntropyError` raised if below
- Every `TokenResult` carries `key_version` for rotation tracking
- Domain separation: HMAC input always prefixed with `field_type + ":"`
- Frozen dataclasses for all value types (`TokenResult`, `MatchResult`, `AuditEvent`, `PolicyDecision`)
- `tests/fixtures/` contains only programmatically generated synthetic data — no real PII ever committed

## Review Focus

- **Empty string inputs to normalizers** — should return empty string, not raise; normalizers are pure transforms
- **Sub-32-byte keys passed to DirectKeyStore** — must raise `KeyEntropyError` at construction, not silently truncate
- **Same Argon2id value tokenized twice** — must produce different tokens (non-deterministic); verify with `!=`
- **Policy denial must emit an AuditEvent** — even when the operation is blocked, one event with `outcome="denied"` must fire
- **Cross-field token collision resistance** — `HMAC(key, "email:foo")` must never equal `HMAC(key, "name:foo")` for the same raw value

---

## Task 1: Project Scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `tokenvault/__init__.py`
- Create: `tokenvault/protocols/__init__.py`
- Create: `tokenvault/fields/__init__.py`
- Create: `tokenvault/tokenizers/__init__.py`
- Create: `tokenvault/matchers/__init__.py`
- Create: `tokenvault/keys/__init__.py`
- Create: `tokenvault/policy/__init__.py`
- Create: `tokenvault/audit/__init__.py`
- Create: `tokenvault/audit/sinks/__init__.py`
- Create: `tokenvault/transfer/__init__.py`
- Create: `tokenvault/cli/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/unit/__init__.py`
- Create: `tests/integration/__init__.py`
- Create: `tests/conftest.py`

**Interfaces:**
- Produces: installable package skeleton; `pytest` runs without import errors

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "tokenvault"
version = "0.1.0"
description = "Privacy-preserving PII tokenization and matching for cross-border data transfer"
requires-python = ">=3.10"
license = {text = "MIT"}
readme = "README.md"
dependencies = []

[project.optional-dependencies]
argon2   = ["argon2-cffi>=23.1"]
aes-siv  = ["cryptography>=42.0"]
fuzzy    = ["jellyfish>=1.1"]
phone    = ["phonenumbers>=8.13"]
all      = ["tokenvault[argon2,aes-siv,fuzzy,phone]"]
dev      = [
    "pytest>=8.0",
    "hypothesis>=6.100",
    "pytest-cov>=5.0",
    "ruff>=0.4",
    "mypy>=1.10",
    "tokenvault[all]",
]

[project.scripts]
tokenvault = "tokenvault.cli.commands:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts   = "-v --tb=short"

[tool.ruff]
target-version = "py310"
line-length    = 100

[tool.ruff.lint]
select = ["E", "F", "I", "UP"]

[tool.mypy]
python_version = "3.10"
strict         = true
```

- [ ] **Step 2: Create package `__init__.py` stubs**

`tokenvault/__init__.py`:
```python
__version__ = "0.1.0"
```

All other `__init__.py` files (protocols, fields, tokenizers, matchers, keys, policy, audit, audit/sinks, transfer, cli, tests, tests/unit, tests/integration): create as empty files.

- [ ] **Step 3: Create `tests/conftest.py`**

All imports are lazy (inside fixture bodies) so `pytest --collect-only` succeeds before any domain modules exist.

```python
import secrets
import pytest


@pytest.fixture()
def test_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture()
def test_key_store(test_key: bytes):
    from tokenvault.keys.direct import DirectKeyStore
    return DirectKeyStore(keys={"test-v1": test_key}, current_key_id="test-v1")


@pytest.fixture()
def hmac_tokenizer(test_key_store):
    from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
    return HMACTokenizer(key_store=test_key_store)


@pytest.fixture()
def vault(test_key_store, hmac_tokenizer):
    from tokenvault.config import VaultConfig
    from tokenvault.vault import TokenVault
    from tokenvault.matchers.exact import ExactTokenMatcher
    from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
    return TokenVault(
        VaultConfig(
            key_store=test_key_store,
            tokenizer=hmac_tokenizer,
            matchers={"exact": ExactTokenMatcher()},
            audit_sink=PythonLoggingAuditSink(),
        )
    )
```

- [ ] **Step 4: Install in editable mode and verify pytest collects**

```bash
pip install -e ".[dev]"
pytest --collect-only
```

Expected: 0 errors, 0 tests collected yet.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml tokenvault/ tests/
git commit -m "feat: scaffold package structure and pyproject.toml"
```

---

## Task 2: Core Protocols

**Files:**
- Create: `tokenvault/protocols/tokenizer.py`
- Create: `tokenvault/protocols/normalizer.py`
- Create: `tokenvault/protocols/matcher.py`
- Create: `tokenvault/protocols/key_store.py`
- Create: `tokenvault/protocols/audit_sink.py`
- Create: `tokenvault/protocols/policy_guard.py`
- Create: `tests/unit/test_protocols.py`

**Interfaces:**
- Produces: `TokenResult`, `MatchResult`, `AuditEvent`, `PolicyDecision`, `KeyEntropyError`, `MIN_KEY_BYTES`; all Protocol classes for structural typing

- [ ] **Step 1: Write failing tests**

`tests/unit/test_protocols.py`:
```python
from dataclasses import fields
from tokenvault.protocols.tokenizer import TokenResult
from tokenvault.protocols.matcher import MatchResult
from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.protocols.policy_guard import PolicyDecision
from tokenvault.protocols.key_store import KeyEntropyError, MIN_KEY_BYTES


def test_token_result_is_frozen():
    r = TokenResult(token="abc", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", is_deterministic=True)
    try:
        r.token = "x"  # type: ignore
        assert False, "should be immutable"
    except Exception:
        pass


def test_token_result_repr_safe():
    r = TokenResult(token="abc", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", is_deterministic=True)
    assert "abc" in repr(r)  # token itself is opaque, safe to show


def test_match_result_is_frozen():
    r = MatchResult(score=0.9, algorithm="jaro-winkler", threshold=0.85, matched=True)
    try:
        r.score = 0.1  # type: ignore
        assert False
    except Exception:
        pass


def test_audit_event_has_no_value_field():
    event_fields = {f.name for f in fields(AuditEvent)}
    assert "value" not in event_fields
    assert "raw" not in event_fields


def test_audit_event_auto_id_and_timestamp():
    e1 = AuditEvent(operation="tokenize", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", policy_id="p1", outcome="success")
    e2 = AuditEvent(operation="tokenize", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", policy_id="p1", outcome="success")
    assert e1.event_id != e2.event_id


def test_policy_decision_frozen():
    d = PolicyDecision(allowed=True, policy_id="p1", reason="ok")
    try:
        d.allowed = False  # type: ignore
        assert False
    except Exception:
        pass


def test_min_key_bytes():
    assert MIN_KEY_BYTES == 32
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
pytest tests/unit/test_protocols.py -v
```

- [ ] **Step 3: Implement `protocols/key_store.py`**

```python
from typing import Protocol, runtime_checkable

MIN_KEY_BYTES = 32


class KeyEntropyError(ValueError):
    """Raised when a key does not meet the minimum 256-bit entropy requirement."""


@runtime_checkable
class KeyStore(Protocol):
    def get_key(self, key_id: str) -> bytes: ...
    def get_current_key_id(self) -> str: ...
```

- [ ] **Step 4: Implement `protocols/tokenizer.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class TokenResult:
    token: str
    field_type: str
    algorithm: str
    key_version: str
    is_deterministic: bool


@runtime_checkable
class Tokenizer(Protocol):
    def tokenize(self, value: str, field_type: str) -> TokenResult: ...
    def supports_field(self, field_type: str) -> bool: ...
```

- [ ] **Step 5: Implement `protocols/normalizer.py`**

```python
from typing import Protocol, runtime_checkable


@runtime_checkable
class Normalizer(Protocol):
    def normalize(self, value: str) -> str: ...
```

- [ ] **Step 6: Implement `protocols/matcher.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class MatchResult:
    score: float
    algorithm: str
    threshold: float
    matched: bool


@runtime_checkable
class Matcher(Protocol):
    def match(self, token_a: str, token_b: str) -> MatchResult: ...
```

- [ ] **Step 7: Implement `protocols/audit_sink.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable
import uuid


@dataclass(frozen=True)
class AuditEvent:
    operation: str
    field_type: str
    algorithm: str
    key_version: str
    policy_id: str
    outcome: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...
```

- [ ] **Step 8: Implement `protocols/policy_guard.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    policy_id: str
    reason: str


@runtime_checkable
class PolicyGuard(Protocol):
    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision: ...
```

- [ ] **Step 9: Run tests — expect all pass**

```bash
pytest tests/unit/test_protocols.py -v
```

- [ ] **Step 10: Commit**

```bash
git add tokenvault/protocols/ tests/unit/test_protocols.py
git commit -m "feat: add core Protocol ABCs and frozen value types"
```

---

## Task 3: PII Field Types

**Files:**
- Create: `tokenvault/fields/base.py`
- Create: `tests/unit/test_fields_base.py`

**Interfaces:**
- Produces: `FieldType` (str enum), `PIIField(name, field_type, value)` — repr must not show value

- [ ] **Step 1: Write failing tests**

`tests/unit/test_fields_base.py`:
```python
from tokenvault.fields.base import FieldType, PIIField


def test_field_type_values():
    assert FieldType.EMAIL == "email"
    assert FieldType.NAME == "name"
    assert FieldType.PHONE == "phone"
    assert FieldType.ADDRESS == "address"
    assert FieldType.DATE_OF_BIRTH == "date_of_birth"
    assert FieldType.NATIONAL_ID == "national_id"
    assert FieldType.CUSTOM == "custom"


def test_pii_field_repr_hides_value():
    f = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    r = repr(f)
    assert "jane@example.com" not in r
    assert "[REDACTED]" in r


def test_pii_field_is_frozen():
    f = PIIField(name="email", field_type=FieldType.EMAIL, value="x")
    try:
        f.value = "y"  # type: ignore
        assert False
    except Exception:
        pass


def test_field_type_from_string():
    ft = FieldType("email")
    assert ft is FieldType.EMAIL
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_fields_base.py -v
```

- [ ] **Step 3: Implement `fields/base.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class FieldType(str, Enum):
    EMAIL = "email"
    NAME = "name"
    PHONE = "phone"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    NATIONAL_ID = "national_id"
    CUSTOM = "custom"


@dataclass(frozen=True)
class PIIField:
    name: str
    field_type: FieldType
    value: str

    def __repr__(self) -> str:
        return (
            f"PIIField(name={self.name!r}, "
            f"field_type={self.field_type!r}, value='[REDACTED]')"
        )
```

- [ ] **Step 4: Run — expect all pass**

```bash
pytest tests/unit/test_fields_base.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tokenvault/fields/base.py tests/unit/test_fields_base.py
git commit -m "feat: add FieldType enum and PIIField dataclass with redacted repr"
```

---

## Task 4: Field Normalizers

**Files:**
- Create: `tokenvault/fields/email.py`
- Create: `tokenvault/fields/name.py`
- Create: `tokenvault/fields/phone.py`
- Create: `tokenvault/fields/dob.py`
- Create: `tokenvault/fields/address.py`
- Create: `tokenvault/fields/national_id.py`
- Create: `tokenvault/fields/custom.py`
- Create: `tests/unit/test_normalizers.py`

**Interfaces:**
- Consumes: nothing from other domain modules
- Produces: one `normalize(value: str) -> str` method per class; all satisfy `Normalizer` protocol

- [ ] **Step 1: Write failing tests**

`tests/unit/test_normalizers.py`:
```python
import pytest
from hypothesis import given, strategies as st

from tokenvault.fields.email import EmailNormalizer
from tokenvault.fields.name import NameNormalizer
from tokenvault.fields.phone import PhoneNormalizer
from tokenvault.fields.dob import DateOfBirthNormalizer
from tokenvault.fields.address import AddressNormalizer
from tokenvault.fields.national_id import NationalIDNormalizer
from tokenvault.fields.custom import PassthroughNormalizer


# --- Email ---
def test_email_lowercase():
    assert EmailNormalizer().normalize("Jane@Example.COM") == "jane@example.com"

def test_email_strips_subaddress():
    assert EmailNormalizer().normalize("jane+promo@example.com") == "jane@example.com"

def test_email_strips_whitespace():
    assert EmailNormalizer().normalize("  jane @example.com  ") == "jane@example.com"

def test_email_empty():
    assert EmailNormalizer().normalize("") == ""

@given(st.emails())
def test_email_idempotent(email: str):
    n = EmailNormalizer()
    once = n.normalize(email)
    assert n.normalize(once) == once


# --- Name ---
def test_name_lowercase_strip():
    assert NameNormalizer().normalize("  JANE  SMITH  ") == "jane smith"

def test_name_removes_punctuation():
    assert NameNormalizer().normalize("O'Brien") == "obrien"

def test_name_empty():
    assert NameNormalizer().normalize("") == ""

@given(st.text(min_size=0, max_size=50))
def test_name_idempotent(s: str):
    n = NameNormalizer()
    once = n.normalize(s)
    assert n.normalize(once) == once


# --- Phone ---
def test_phone_strips_formatting():
    assert PhoneNormalizer().normalize("(416) 555-1234") == "+4165551234"

def test_phone_keeps_plus():
    assert PhoneNormalizer().normalize("+14165551234") == "+14165551234"

def test_phone_empty():
    assert PhoneNormalizer().normalize("") == "+"


# --- DOB ---
def test_dob_iso_passthrough():
    assert DateOfBirthNormalizer().normalize("1990-05-21") == "1990-05-21"

def test_dob_slash_ddmmyyyy():
    assert DateOfBirthNormalizer().normalize("21/05/1990") == "1990-05-21"


# --- Address ---
def test_address_lowercase():
    assert AddressNormalizer().normalize("123 Main St") == "123 main st"

def test_address_collapses_spaces():
    assert AddressNormalizer().normalize("123  Main   St") == "123 main st"


# --- National ID ---
def test_national_id_strips_separators():
    assert NationalIDNormalizer().normalize("123-456-789") == "123456789"

def test_national_id_uppercase():
    assert NationalIDNormalizer().normalize("ab 12 cd") == "AB12CD"


# --- Passthrough ---
def test_passthrough_strips():
    assert PassthroughNormalizer().normalize("  hello  ") == "hello"
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_normalizers.py -v
```

- [ ] **Step 3: Implement `fields/email.py`**

```python
from __future__ import annotations
import re


class EmailNormalizer:
    _WHITESPACE = re.compile(r"\s+")

    def normalize(self, value: str) -> str:
        if not value:
            return ""
        value = self._WHITESPACE.sub("", value).lower()
        local, sep, domain = value.partition("@")
        if not sep:
            return value
        local = local.split("+")[0]
        return f"{local}@{domain}"
```

- [ ] **Step 4: Implement `fields/name.py`**

```python
from __future__ import annotations
import re
import unicodedata


class NameNormalizer:
    _PUNCT = re.compile(r"[^\w\s]", re.UNICODE)
    _MULTI_SPACE = re.compile(r"\s+")

    def normalize(self, value: str) -> str:
        if not value:
            return ""
        value = unicodedata.normalize("NFC", value)
        value = self._PUNCT.sub("", value)
        return self._MULTI_SPACE.sub(" ", value).strip().lower()
```

- [ ] **Step 5: Implement `fields/phone.py`**

```python
from __future__ import annotations
import re


class PhoneNormalizer:
    _NON_DIGIT = re.compile(r"[^\d]")

    def normalize(self, value: str) -> str:
        digits = self._NON_DIGIT.sub("", value)
        return f"+{digits}"
```

- [ ] **Step 6: Implement `fields/dob.py`**

```python
from __future__ import annotations
import re


class DateOfBirthNormalizer:
    _SEP = re.compile(r"[-/.]")

    def normalize(self, value: str) -> str:
        parts = self._SEP.split(value.strip())
        if len(parts) != 3:
            return value.strip()
        if len(parts[0]) == 4:
            y, m, d = parts[0], parts[1], parts[2]
        else:
            d, m, y = parts[0], parts[1], parts[2]
        return f"{y}-{m.zfill(2)}-{d.zfill(2)}"
```

- [ ] **Step 7: Implement `fields/address.py`**

```python
from __future__ import annotations
import re
import unicodedata


class AddressNormalizer:
    _MULTI_SPACE = re.compile(r"\s+")

    def normalize(self, value: str) -> str:
        if not value:
            return ""
        value = unicodedata.normalize("NFC", value)
        return self._MULTI_SPACE.sub(" ", value).strip().lower()
```

- [ ] **Step 8: Implement `fields/national_id.py`**

```python
from __future__ import annotations
import re


class NationalIDNormalizer:
    _NON_ALNUM = re.compile(r"[^a-zA-Z0-9]")

    def normalize(self, value: str) -> str:
        return self._NON_ALNUM.sub("", value).upper()
```

- [ ] **Step 9: Implement `fields/custom.py`**

```python
from __future__ import annotations
from tokenvault.protocols.normalizer import Normalizer


class PassthroughNormalizer:
    def normalize(self, value: str) -> str:
        return value.strip()


class UserDefinedNormalizer:
    def __init__(self, fn: Normalizer) -> None:
        self._fn = fn

    def normalize(self, value: str) -> str:
        return self._fn.normalize(value)
```

- [ ] **Step 10: Run — expect all pass**

```bash
pytest tests/unit/test_normalizers.py -v
```

- [ ] **Step 11: Commit**

```bash
git add tokenvault/fields/ tests/unit/test_normalizers.py
git commit -m "feat: add PII field normalizers (email, name, phone, dob, address, national_id)"
```

---

## Task 5: Key Store Implementations

**Files:**
- Create: `tokenvault/keys/direct.py`
- Create: `tokenvault/keys/env.py`
- Create: `tokenvault/keys/file.py`
- Create: `tests/unit/test_key_stores.py`

**Interfaces:**
- Consumes: `KeyEntropyError`, `MIN_KEY_BYTES` from `protocols/key_store.py`
- Produces: `DirectKeyStore`, `EnvKeyStore`, `FileKeyStore` — all satisfy `KeyStore` protocol

- [ ] **Step 1: Write failing tests**

`tests/unit/test_key_stores.py`:
```python
import json
import os
import secrets
import tempfile
import pytest

from tokenvault.protocols.key_store import KeyEntropyError, MIN_KEY_BYTES
from tokenvault.keys.direct import DirectKeyStore
from tokenvault.keys.env import EnvKeyStore
from tokenvault.keys.file import FileKeyStore


KEY = secrets.token_bytes(32)


# --- DirectKeyStore ---
def test_direct_returns_key():
    store = DirectKeyStore(keys={"v1": KEY}, current_key_id="v1")
    assert store.get_key("v1") == KEY
    assert store.get_current_key_id() == "v1"

def test_direct_rejects_short_key():
    with pytest.raises(KeyEntropyError):
        DirectKeyStore(keys={"v1": b"tooshort"}, current_key_id="v1")

def test_direct_missing_key():
    store = DirectKeyStore(keys={"v1": KEY}, current_key_id="v1")
    with pytest.raises(KeyError):
        store.get_key("missing")


# --- EnvKeyStore ---
def test_env_reads_key(monkeypatch):
    hex_key = KEY.hex()
    monkeypatch.setenv("TOKENVAULT_KEY_TEST_V1", hex_key)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "test-v1")
    store = EnvKeyStore()
    assert store.get_key("test-v1") == bytes.fromhex(hex_key)
    assert store.get_current_key_id() == "test-v1"

def test_env_missing_var(monkeypatch):
    monkeypatch.delenv("TOKENVAULT_KEY_MISSING", raising=False)
    store = EnvKeyStore()
    with pytest.raises(KeyError):
        store.get_key("missing")


# --- FileKeyStore ---
def test_file_reads_keys():
    data = {
        "current_key_id": "v1",
        "keys": {"v1": KEY.hex()}
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    store = FileKeyStore(path=path)
    assert store.get_key("v1") == KEY
    assert store.get_current_key_id() == "v1"
    os.unlink(path)

def test_file_rejects_short_key():
    data = {"current_key_id": "v1", "keys": {"v1": b"short".hex()}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    with pytest.raises(KeyEntropyError):
        FileKeyStore(path=path)
    os.unlink(path)
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_key_stores.py -v
```

- [ ] **Step 3: Implement `keys/direct.py`**

```python
from __future__ import annotations
from tokenvault.protocols.key_store import KeyEntropyError, MIN_KEY_BYTES


class DirectKeyStore:
    def __init__(self, keys: dict[str, bytes], current_key_id: str) -> None:
        for kid, key in keys.items():
            if len(key) < MIN_KEY_BYTES:
                raise KeyEntropyError(
                    f"Key '{kid}' is {len(key)} bytes; minimum is {MIN_KEY_BYTES} (256-bit)."
                )
        self._keys = dict(keys)
        self._current = current_key_id

    def get_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(f"Key ID '{key_id}' not found in DirectKeyStore.") from None

    def get_current_key_id(self) -> str:
        return self._current
```

- [ ] **Step 4: Implement `keys/env.py`**

```python
from __future__ import annotations
import os
from tokenvault.protocols.key_store import KeyEntropyError, MIN_KEY_BYTES


class EnvKeyStore:
    def __init__(
        self,
        prefix: str = "TOKENVAULT_KEY_",
        current_key_env: str = "TOKENVAULT_CURRENT_KEY_ID",
    ) -> None:
        self._prefix = prefix.upper()
        self._current_key_env = current_key_env

    def get_key(self, key_id: str) -> bytes:
        env_name = self._prefix + key_id.upper().replace("-", "_")
        raw = os.environ.get(env_name)
        if raw is None:
            raise KeyError(f"Environment variable '{env_name}' not set.")
        key = bytes.fromhex(raw) if all(c in "0123456789abcdefABCDEF" for c in raw) else raw.encode()
        if len(key) < MIN_KEY_BYTES:
            raise KeyEntropyError(f"Key from '{env_name}' is {len(key)} bytes; minimum is {MIN_KEY_BYTES}.")
        return key

    def get_current_key_id(self) -> str:
        val = os.environ.get(self._current_key_env)
        if val is None:
            raise KeyError(f"Environment variable '{self._current_key_env}' not set.")
        return val
```

- [ ] **Step 5: Implement `keys/file.py`**

```python
from __future__ import annotations
import json
import os
from pathlib import Path
from tokenvault.protocols.key_store import KeyEntropyError, MIN_KEY_BYTES


class FileKeyStore:
    """Loads keys from a JSON file.

    File format:
        {
            "current_key_id": "v1",
            "keys": {
                "v1": "<hex-encoded 32+ byte key>"
            }
        }
    """

    def __init__(self, path: str | Path | None = None) -> None:
        resolved = path or os.environ.get("TOKENVAULT_KEY_FILE")
        if not resolved:
            raise ValueError("FileKeyStore requires a path or TOKENVAULT_KEY_FILE env var.")
        data = json.loads(Path(resolved).read_text())
        self._current: str = data["current_key_id"]
        self._keys: dict[str, bytes] = {}
        for kid, hex_val in data["keys"].items():
            key = bytes.fromhex(hex_val)
            if len(key) < MIN_KEY_BYTES:
                raise KeyEntropyError(
                    f"Key '{kid}' in file is {len(key)} bytes; minimum is {MIN_KEY_BYTES}."
                )
            self._keys[kid] = key

    def get_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(f"Key ID '{key_id}' not found in FileKeyStore.") from None

    def get_current_key_id(self) -> str:
        return self._current
```

- [ ] **Step 6: Run — expect all pass**

```bash
pytest tests/unit/test_key_stores.py -v
```

- [ ] **Step 7: Commit**

```bash
git add tokenvault/keys/ tests/unit/test_key_stores.py
git commit -m "feat: add DirectKeyStore, EnvKeyStore, FileKeyStore with 256-bit enforcement"
```

---

## Task 6: HMAC-SHA256 Tokenizer

**Files:**
- Create: `tokenvault/tokenizers/hmac_sha256.py`
- Create: `tests/unit/test_tokenizer_hmac.py`

**Interfaces:**
- Consumes: `KeyStore` from `protocols/key_store.py`; `TokenResult` from `protocols/tokenizer.py`
- Produces: `HMACTokenizer` satisfying `Tokenizer` protocol

- [ ] **Step 1: Write failing tests**

`tests/unit/test_tokenizer_hmac.py`:
```python
import secrets
import pytest
from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer


@pytest.fixture()
def store() -> DirectKeyStore:
    return DirectKeyStore(keys={"v1": secrets.token_bytes(32)}, current_key_id="v1")


def test_hmac_deterministic(store):
    t = HMACTokenizer(key_store=store)
    r1 = t.tokenize("jane@example.com", "email")
    r2 = t.tokenize("jane@example.com", "email")
    assert r1.token == r2.token
    assert r1.is_deterministic is True


def test_hmac_different_values_differ(store):
    t = HMACTokenizer(key_store=store)
    r1 = t.tokenize("jane@example.com", "email")
    r2 = t.tokenize("john@example.com", "email")
    assert r1.token != r2.token


def test_hmac_domain_separation(store):
    t = HMACTokenizer(key_store=store)
    r_email = t.tokenize("jane", "email")
    r_name = t.tokenize("jane", "name")
    assert r_email.token != r_name.token


def test_hmac_token_is_url_safe(store):
    t = HMACTokenizer(key_store=store)
    token = t.tokenize("test@example.com", "email").token
    assert "+" not in token
    assert "/" not in token
    assert "=" not in token


def test_hmac_carries_key_version(store):
    t = HMACTokenizer(key_store=store)
    r = t.tokenize("x", "email")
    assert r.key_version == "v1"


def test_hmac_supports_field_default(store):
    t = HMACTokenizer(key_store=store)
    assert t.supports_field("email") is True
    assert t.supports_field("anything") is True


def test_hmac_supports_field_restricted(store):
    t = HMACTokenizer(key_store=store, allowed_fields=frozenset({"email"}))
    assert t.supports_field("email") is True
    assert t.supports_field("name") is False


def test_hmac_different_keys_differ():
    k1 = secrets.token_bytes(32)
    k2 = secrets.token_bytes(32)
    s1 = DirectKeyStore(keys={"v1": k1}, current_key_id="v1")
    s2 = DirectKeyStore(keys={"v1": k2}, current_key_id="v1")
    r1 = HMACTokenizer(key_store=s1).tokenize("same", "email")
    r2 = HMACTokenizer(key_store=s2).tokenize("same", "email")
    assert r1.token != r2.token
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_tokenizer_hmac.py -v
```

- [ ] **Step 3: Implement `tokenizers/hmac_sha256.py`**

```python
from __future__ import annotations
import base64
import hashlib
import hmac as _hmac

from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.tokenizer import TokenResult


class HMACTokenizer:
    algorithm = "hmac-sha256"

    def __init__(
        self,
        key_store: KeyStore,
        allowed_fields: frozenset[str] | None = None,
    ) -> None:
        self._key_store = key_store
        self._allowed = allowed_fields

    def supports_field(self, field_type: str) -> bool:
        return self._allowed is None or field_type in self._allowed

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        key_id = self._key_store.get_current_key_id()
        key = self._key_store.get_key(key_id)
        domain_input = f"{field_type}:{value}".encode()
        digest = _hmac.new(key, domain_input, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return TokenResult(
            token=token,
            field_type=field_type,
            algorithm=self.algorithm,
            key_version=key_id,
            is_deterministic=True,
        )
```

- [ ] **Step 4: Run — expect all pass**

```bash
pytest tests/unit/test_tokenizer_hmac.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tokenvault/tokenizers/hmac_sha256.py tests/unit/test_tokenizer_hmac.py
git commit -m "feat: add HMACTokenizer with domain separation and URL-safe base64 output"
```

---

## Task 7: UUID + Argon2id Tokenizers

**Files:**
- Create: `tokenvault/tokenizers/uuid_random.py`
- Create: `tokenvault/tokenizers/argon2_opaque.py`
- Create: `tests/unit/test_tokenizer_nondeterministic.py`

**Interfaces:**
- Produces: `UUIDRandomTokenizer`, `Argon2OpaqueTokenizer` (with `verify()` method)

- [ ] **Step 1: Write failing tests**

`tests/unit/test_tokenizer_nondeterministic.py`:
```python
import pytest
from tokenvault.tokenizers.uuid_random import UUIDRandomTokenizer


def test_uuid_nondeterministic():
    t = UUIDRandomTokenizer()
    r1 = t.tokenize("same@example.com", "email")
    r2 = t.tokenize("same@example.com", "email")
    assert r1.token != r2.token


def test_uuid_is_not_deterministic():
    t = UUIDRandomTokenizer()
    r = t.tokenize("x", "email")
    assert r.is_deterministic is False


def test_uuid_no_key_version():
    t = UUIDRandomTokenizer()
    r = t.tokenize("x", "email")
    assert r.key_version == "none"


def test_uuid_supports_all_fields():
    t = UUIDRandomTokenizer()
    assert t.supports_field("email") is True
    assert t.supports_field("custom") is True


# Argon2 tests only run if argon2-cffi is installed
argon2 = pytest.importorskip("argon2")


def test_argon2_nondeterministic():
    from tokenvault.tokenizers.argon2_opaque import Argon2OpaqueTokenizer
    t = Argon2OpaqueTokenizer(time_cost=1, memory_cost=8192, parallelism=1)
    r1 = t.tokenize("same@example.com", "email")
    r2 = t.tokenize("same@example.com", "email")
    assert r1.token != r2.token


def test_argon2_verify_correct_value():
    from tokenvault.tokenizers.argon2_opaque import Argon2OpaqueTokenizer
    t = Argon2OpaqueTokenizer(time_cost=1, memory_cost=8192, parallelism=1)
    r = t.tokenize("jane@example.com", "email")
    assert t.verify("jane@example.com", r) is True


def test_argon2_verify_wrong_value():
    from tokenvault.tokenizers.argon2_opaque import Argon2OpaqueTokenizer
    t = Argon2OpaqueTokenizer(time_cost=1, memory_cost=8192, parallelism=1)
    r = t.tokenize("jane@example.com", "email")
    assert t.verify("other@example.com", r) is False
```

- [ ] **Step 2: Run — expect ImportError on uuid tokenizer**

```bash
pytest tests/unit/test_tokenizer_nondeterministic.py -v
```

- [ ] **Step 3: Implement `tokenizers/uuid_random.py`**

```python
from __future__ import annotations
import secrets
import uuid as _uuid

from tokenvault.protocols.tokenizer import TokenResult


class UUIDRandomTokenizer:
    algorithm = "uuid-v4"

    def supports_field(self, field_type: str) -> bool:
        return True

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        token = str(_uuid.UUID(bytes=secrets.token_bytes(16), version=4))
        return TokenResult(
            token=token,
            field_type=field_type,
            algorithm=self.algorithm,
            key_version="none",
            is_deterministic=False,
        )
```

- [ ] **Step 4: Implement `tokenizers/argon2_opaque.py`**

```python
from __future__ import annotations
import base64
import hmac as _hmac
import secrets

from tokenvault.protocols.tokenizer import TokenResult

try:
    from argon2.low_level import Type, hash_secret_raw
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_SALT_BYTES = 32


class Argon2OpaqueTokenizer:
    algorithm = "argon2id"

    def __init__(
        self,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32,
    ) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[argon2] to use Argon2OpaqueTokenizer.")
        self._time_cost = time_cost
        self._memory_cost = memory_cost
        self._parallelism = parallelism
        self._hash_len = hash_len

    def supports_field(self, field_type: str) -> bool:
        return True

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        salt = secrets.token_bytes(_SALT_BYTES)
        domain_input = f"{field_type}:{value}".encode()
        raw = hash_secret_raw(
            secret=domain_input,
            salt=salt,
            time_cost=self._time_cost,
            memory_cost=self._memory_cost,
            parallelism=self._parallelism,
            hash_len=self._hash_len,
            type=Type.ID,
        )
        token = base64.urlsafe_b64encode(salt + raw).rstrip(b"=").decode()
        return TokenResult(
            token=token,
            field_type=field_type,
            algorithm=self.algorithm,
            key_version="none",
            is_deterministic=False,
        )

    def verify(self, value: str, token_result: TokenResult) -> bool:
        combined = base64.urlsafe_b64decode(token_result.token + "==")
        salt = combined[:_SALT_BYTES]
        stored = combined[_SALT_BYTES:]
        domain_input = f"{token_result.field_type}:{value}".encode()
        candidate = hash_secret_raw(
            secret=domain_input,
            salt=salt,
            time_cost=self._time_cost,
            memory_cost=self._memory_cost,
            parallelism=self._parallelism,
            hash_len=len(stored),
            type=Type.ID,
        )
        return _hmac.compare_digest(stored, candidate)
```

- [ ] **Step 5: Run — expect all pass**

```bash
pytest tests/unit/test_tokenizer_nondeterministic.py -v
```

- [ ] **Step 6: Commit**

```bash
git add tokenvault/tokenizers/uuid_random.py tokenvault/tokenizers/argon2_opaque.py tests/unit/test_tokenizer_nondeterministic.py
git commit -m "feat: add UUIDRandomTokenizer and Argon2OpaqueTokenizer (memory-hard, non-deterministic)"
```

---

## Task 8: AES-SIV Tokenizer (Reversible, Policy-Gated)

**Files:**
- Create: `tokenvault/tokenizers/aes_siv.py`
- Create: `tests/unit/test_tokenizer_aes_siv.py`

**Interfaces:**
- Consumes: `KeyStore`
- Produces: `AESSIVTokenizer` with `tokenize()` + `detokenize()` methods

- [ ] **Step 1: Write failing tests**

`tests/unit/test_tokenizer_aes_siv.py`:
```python
import secrets
import pytest

cryptography = pytest.importorskip("cryptography")

from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.aes_siv import AESSIVTokenizer


@pytest.fixture()
def store():
    # AES-SIV-256 needs a 64-byte key (two 256-bit keys internally)
    return DirectKeyStore(keys={"v1": secrets.token_bytes(64)}, current_key_id="v1")


def test_aes_siv_deterministic(store):
    t = AESSIVTokenizer(key_store=store)
    r1 = t.tokenize("jane@example.com", "email")
    r2 = t.tokenize("jane@example.com", "email")
    assert r1.token == r2.token


def test_aes_siv_roundtrip(store):
    t = AESSIVTokenizer(key_store=store)
    original = "jane@example.com"
    result = t.tokenize(original, "email")
    recovered = t.detokenize(result)
    assert recovered == original


def test_aes_siv_domain_separation(store):
    t = AESSIVTokenizer(key_store=store)
    r_email = t.tokenize("jane", "email")
    r_name = t.tokenize("jane", "name")
    assert r_email.token != r_name.token


def test_aes_siv_is_deterministic_flag(store):
    t = AESSIVTokenizer(key_store=store)
    r = t.tokenize("x", "email")
    assert r.is_deterministic is True
    assert r.algorithm == "aes-siv"
```

- [ ] **Step 2: Run — expect skip (cryptography not installed) or ImportError**

```bash
pytest tests/unit/test_tokenizer_aes_siv.py -v
```

- [ ] **Step 3: Implement `tokenizers/aes_siv.py`**

```python
from __future__ import annotations
import base64

from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.tokenizer import TokenResult

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class AESSIVTokenizer:
    algorithm = "aes-siv"

    def __init__(
        self,
        key_store: KeyStore,
        allowed_fields: frozenset[str] | None = None,
    ) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[aes-siv] to use AESSIVTokenizer.")
        self._key_store = key_store
        self._allowed = allowed_fields

    def supports_field(self, field_type: str) -> bool:
        return self._allowed is None or field_type in self._allowed

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        key_id = self._key_store.get_current_key_id()
        key = self._key_store.get_key(key_id)
        aes = AESSIV(key)
        ciphertext = aes.encrypt(value.encode(), [field_type.encode()])
        token = base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode()
        return TokenResult(
            token=token,
            field_type=field_type,
            algorithm=self.algorithm,
            key_version=key_id,
            is_deterministic=True,
        )

    def detokenize(self, token_result: TokenResult) -> str:
        key = self._key_store.get_key(token_result.key_version)
        ciphertext = base64.urlsafe_b64decode(token_result.token + "==")
        aes = AESSIV(key)
        return aes.decrypt(ciphertext, [token_result.field_type.encode()]).decode()
```

- [ ] **Step 4: Run — expect pass (or skip if cryptography unavailable)**

```bash
pytest tests/unit/test_tokenizer_aes_siv.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tokenvault/tokenizers/aes_siv.py tests/unit/test_tokenizer_aes_siv.py
git commit -m "feat: add AESSIVTokenizer (format-preserving, reversible, nonce-misuse-resistant)"
```

---

## Task 9: Matchers

**Files:**
- Create: `tokenvault/matchers/exact.py`
- Create: `tokenvault/matchers/jaro_winkler.py`
- Create: `tokenvault/matchers/levenshtein.py`
- Create: `tokenvault/matchers/phonetic.py`
- Create: `tokenvault/matchers/ngram.py`
- Create: `tests/unit/test_matchers.py`

**Interfaces:**
- Consumes: `MatchResult` from `protocols/matcher.py`
- Produces: all matchers satisfy `Matcher` protocol; fuzzy matchers operate on normalized strings (not tokens)

- [ ] **Step 1: Write failing tests**

`tests/unit/test_matchers.py`:
```python
import pytest
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.matchers.ngram import NgramSimilarityMatcher


# --- Exact ---
def test_exact_same_token():
    m = ExactTokenMatcher()
    r = m.match("abc123", "abc123")
    assert r.matched is True
    assert r.score == 1.0


def test_exact_different_token():
    m = ExactTokenMatcher()
    r = m.match("abc123", "xyz789")
    assert r.matched is False
    assert r.score == 0.0


def test_exact_constant_time_safe():
    # both comparisons must complete without raising
    m = ExactTokenMatcher()
    m.match("a" * 1000, "b" * 1000)
    m.match("a" * 1000, "a" * 1000)


# --- Ngram (stdlib, no optional dep) ---
def test_ngram_identical():
    m = NgramSimilarityMatcher(n=2, threshold=0.7)
    r = m.match("smith", "smith")
    assert r.score == pytest.approx(1.0)
    assert r.matched is True


def test_ngram_similar():
    m = NgramSimilarityMatcher(n=2, threshold=0.5)
    r = m.match("smith", "smyth")
    assert r.score > 0.4


def test_ngram_dissimilar():
    m = NgramSimilarityMatcher(n=2, threshold=0.7)
    r = m.match("smith", "jones")
    assert r.matched is False


def test_ngram_empty_strings():
    m = NgramSimilarityMatcher(n=2)
    r = m.match("", "")
    assert r.score == pytest.approx(1.0)


# --- Optional fuzzy matchers (skip if jellyfish not installed) ---
jellyfish = pytest.importorskip("jellyfish")


def test_jaro_winkler_high_similarity():
    from tokenvault.matchers.jaro_winkler import JaroWinklerMatcher
    m = JaroWinklerMatcher(threshold=0.85)
    r = m.match("jane smith", "jane smyth")
    assert r.score > 0.85
    assert r.matched is True


def test_jaro_winkler_dissimilar():
    from tokenvault.matchers.jaro_winkler import JaroWinklerMatcher
    m = JaroWinklerMatcher(threshold=0.85)
    r = m.match("jane smith", "robert jones")
    assert r.matched is False


def test_levenshtein_typo():
    from tokenvault.matchers.levenshtein import LevenshteinMatcher
    m = LevenshteinMatcher(threshold=0.80)
    r = m.match("johnsen", "johnson")
    assert r.matched is True


def test_soundex_same_sound():
    from tokenvault.matchers.phonetic import SoundexMatcher
    m = SoundexMatcher()
    r = m.match("smith", "smyth")
    assert r.matched is True


def test_metaphone_same_sound():
    from tokenvault.matchers.phonetic import MetaphoneMatcher
    m = MetaphoneMatcher()
    r = m.match("john", "jon")
    assert r.matched is True
```

- [ ] **Step 2: Run — expect ImportError on exact/ngram**

```bash
pytest tests/unit/test_matchers.py -v
```

- [ ] **Step 3: Implement `matchers/exact.py`**

```python
from __future__ import annotations
import hmac as _hmac

from tokenvault.protocols.matcher import MatchResult


class ExactTokenMatcher:
    algorithm = "exact"

    def __init__(self, threshold: float = 1.0) -> None:
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        matched = _hmac.compare_digest(token_a.encode(), token_b.encode())
        score = 1.0 if matched else 0.0
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=matched,
        )
```

- [ ] **Step 4: Implement `matchers/ngram.py`**

```python
from __future__ import annotations
from tokenvault.protocols.matcher import MatchResult


class NgramSimilarityMatcher:
    algorithm = "ngram"

    def __init__(self, n: int = 2, threshold: float = 0.7) -> None:
        self._n = n
        self._threshold = threshold

    def _ngrams(self, s: str) -> set[str]:
        pad = "$" * (self._n - 1)
        padded = f"{pad}{s}{pad}"
        return {padded[i : i + self._n] for i in range(len(padded) - self._n + 1)}

    def match(self, token_a: str, token_b: str) -> MatchResult:
        set_a = self._ngrams(token_a)
        set_b = self._ngrams(token_b)
        union = set_a | set_b
        score = len(set_a & set_b) / len(union) if union else 1.0
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
```

- [ ] **Step 5: Implement `matchers/jaro_winkler.py`**

```python
from __future__ import annotations
from tokenvault.protocols.matcher import MatchResult

try:
    import jellyfish as _jf
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class JaroWinklerMatcher:
    algorithm = "jaro-winkler"

    def __init__(self, threshold: float = 0.85) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use JaroWinklerMatcher.")
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        score = float(_jf.jaro_winkler_similarity(token_a, token_b))
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
```

- [ ] **Step 6: Implement `matchers/levenshtein.py`**

```python
from __future__ import annotations
from tokenvault.protocols.matcher import MatchResult

try:
    import jellyfish as _jf
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class LevenshteinMatcher:
    algorithm = "levenshtein"

    def __init__(self, threshold: float = 0.80, max_distance: int | None = None) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use LevenshteinMatcher.")
        self._threshold = threshold
        self._max_distance = max_distance

    def match(self, token_a: str, token_b: str) -> MatchResult:
        dist = _jf.levenshtein_distance(token_a, token_b)
        max_len = max(len(token_a), len(token_b), 1)
        score = 1.0 - (dist / max_len)
        if self._max_distance is not None and dist > self._max_distance:
            score = 0.0
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
```

- [ ] **Step 7: Implement `matchers/phonetic.py`**

```python
from __future__ import annotations
import hmac as _hmac

from tokenvault.protocols.matcher import MatchResult

try:
    import jellyfish as _jf
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class SoundexMatcher:
    algorithm = "soundex"

    def __init__(self, threshold: float = 1.0) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use SoundexMatcher.")
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        code_a = _jf.soundex(token_a)
        code_b = _jf.soundex(token_b)
        matched = _hmac.compare_digest(code_a.encode(), code_b.encode())
        return MatchResult(
            score=1.0 if matched else 0.0,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=matched,
        )


class MetaphoneMatcher:
    algorithm = "metaphone"

    def __init__(self, threshold: float = 1.0) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use MetaphoneMatcher.")
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        code_a = _jf.metaphone(token_a)
        code_b = _jf.metaphone(token_b)
        matched = _hmac.compare_digest(code_a.encode(), code_b.encode())
        return MatchResult(
            score=1.0 if matched else 0.0,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=matched,
        )
```

- [ ] **Step 8: Run — expect all pass**

```bash
pytest tests/unit/test_matchers.py -v
```

- [ ] **Step 9: Commit**

```bash
git add tokenvault/matchers/ tests/unit/test_matchers.py
git commit -m "feat: add ExactTokenMatcher, NgramMatcher, JaroWinkler, Levenshtein, Phonetic matchers"
```

---

## Task 10: CompositeMatcher

**Files:**
- Create: `tokenvault/matchers/composite.py`
- Create: `tests/unit/test_matcher_composite.py`

**Interfaces:**
- Consumes: `Matcher` protocol, `MatchResult`
- Produces: `WeightedMatcher`, `CompositeMatcher`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_matcher_composite.py`:
```python
import pytest
from tokenvault.matchers.composite import CompositeMatcher, WeightedMatcher
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.matchers.ngram import NgramSimilarityMatcher


def test_composite_weights_must_sum_to_one():
    with pytest.raises(ValueError, match="1.0"):
        CompositeMatcher(
            matchers=[
                WeightedMatcher(ExactTokenMatcher(), 0.3),
                WeightedMatcher(NgramSimilarityMatcher(), 0.3),
            ]
        )


def test_composite_weighted_score():
    m = CompositeMatcher(
        matchers=[
            WeightedMatcher(ExactTokenMatcher(), 0.5),
            WeightedMatcher(NgramSimilarityMatcher(n=2), 0.5),
        ],
        threshold=0.5,
    )
    r = m.match("smith", "smith")
    assert r.score == pytest.approx(1.0)
    assert r.matched is True
    assert r.algorithm == "composite"


def test_composite_partial_match():
    m = CompositeMatcher(
        matchers=[
            WeightedMatcher(ExactTokenMatcher(), 0.5),
            WeightedMatcher(NgramSimilarityMatcher(n=2, threshold=0.5), 0.5),
        ],
        threshold=0.4,
    )
    r = m.match("smith", "smyth")
    assert 0.0 < r.score < 1.0
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_matcher_composite.py -v
```

- [ ] **Step 3: Implement `matchers/composite.py`**

```python
from __future__ import annotations
from dataclasses import dataclass

from tokenvault.protocols.matcher import Matcher, MatchResult


@dataclass
class WeightedMatcher:
    matcher: Matcher
    weight: float


class CompositeMatcher:
    algorithm = "composite"

    def __init__(
        self,
        matchers: list[WeightedMatcher],
        threshold: float = 0.80,
    ) -> None:
        total = sum(wm.weight for wm in matchers)
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total:.6f}.")
        self._matchers = matchers
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        score = sum(
            wm.matcher.match(token_a, token_b).score * wm.weight
            for wm in self._matchers
        )
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
```

- [ ] **Step 4: Run — expect all pass**

```bash
pytest tests/unit/test_matcher_composite.py -v
```

- [ ] **Step 5: Commit**

```bash
git add tokenvault/matchers/composite.py tests/unit/test_matcher_composite.py
git commit -m "feat: add CompositeMatcher with weighted multi-algorithm scoring"
```

---

## Task 11: Audit System

**Files:**
- Create: `tokenvault/audit/event.py`
- Create: `tokenvault/audit/redactor.py`
- Create: `tokenvault/audit/sinks/logging.py`
- Create: `tokenvault/audit/sinks/stdout.py`
- Create: `tokenvault/audit/sinks/file.py`
- Create: `tests/unit/test_audit.py`

**Interfaces:**
- Consumes: `AuditEvent`, `AuditSink` from `protocols/audit_sink.py`
- Produces: `PythonLoggingAuditSink` (default), `StdoutAuditSink`, `FileAuditSink`, `Redactor`, `redact()`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_audit.py`:
```python
import json
import logging
import tempfile
import os
import pytest

from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.audit.redactor import Redactor, redact
from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
from tokenvault.audit.sinks.stdout import StdoutAuditSink
from tokenvault.audit.sinks.file import FileAuditSink


def _make_event(**kwargs) -> AuditEvent:
    defaults = dict(
        operation="tokenize", field_type="email", algorithm="hmac-sha256",
        key_version="v1", policy_id="test", outcome="success",
    )
    return AuditEvent(**{**defaults, **kwargs})


# --- Redactor ---
def test_redactor_masks_email():
    r = Redactor()
    assert "jane@example.com" not in r.redact("user jane@example.com logged in")
    assert "[REDACTED]" in r.redact("user jane@example.com logged in")


def test_redactor_leaves_safe_text():
    r = Redactor()
    assert r.redact("hello world") == "hello world"


def test_module_level_redact():
    result = redact("contact jane@example.com for info")
    assert "[REDACTED]" in result


# --- PythonLoggingAuditSink ---
def test_logging_sink_emits(caplog):
    sink = PythonLoggingAuditSink()
    event = _make_event()
    with caplog.at_level(logging.INFO, logger="tokenvault.audit"):
        sink.emit(event)
    assert event.event_id in caplog.text
    assert "tokenize" in caplog.text


def test_logging_sink_no_raw_value(caplog):
    sink = PythonLoggingAuditSink()
    event = _make_event()
    with caplog.at_level(logging.INFO, logger="tokenvault.audit"):
        sink.emit(event)
    assert "jane@example.com" not in caplog.text


# --- FileAuditSink ---
def test_file_sink_writes_jsonl():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as f:
        path = f.name
    sink = FileAuditSink(path=path)
    sink.emit(_make_event())
    sink.emit(_make_event(operation="match"))
    lines = open(path).readlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["operation"] == "tokenize"
    os.unlink(path)


def test_file_sink_appends():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as f:
        path = f.name
    sink = FileAuditSink(path=path)
    for _ in range(5):
        sink.emit(_make_event())
    assert len(open(path).readlines()) == 5
    os.unlink(path)


# --- StdoutAuditSink ---
def test_stdout_sink_emits(capsys):
    sink = StdoutAuditSink()
    sink.emit(_make_event())
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["operation"] == "tokenize"
    assert "value" not in data
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_audit.py -v
```

- [ ] **Step 3: Implement `audit/event.py`**

```python
from tokenvault.protocols.audit_sink import AuditEvent

__all__ = ["AuditEvent"]
```

- [ ] **Step 4: Implement `audit/redactor.py`**

```python
from __future__ import annotations
import re

_PATTERNS = [
    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    re.compile(r"\b\+?[\d\s\-(). ]{7,15}\d\b"),
    re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
]
_REDACTED = "[REDACTED]"


class Redactor:
    def redact(self, text: str) -> str:
        for pattern in _PATTERNS:
            text = pattern.sub(_REDACTED, text)
        return text


_default = Redactor()


def redact(text: str) -> str:
    return _default.redact(text)
```

- [ ] **Step 5: Implement `audit/sinks/logging.py`**

```python
from __future__ import annotations
import logging

from tokenvault.protocols.audit_sink import AuditEvent

_logger = logging.getLogger("tokenvault.audit")


class PythonLoggingAuditSink:
    def emit(self, event: AuditEvent) -> None:
        _logger.info(
            "event_id=%s operation=%s field_type=%s algorithm=%s "
            "key_version=%s policy_id=%s outcome=%s timestamp=%s",
            event.event_id,
            event.operation,
            event.field_type,
            event.algorithm,
            event.key_version,
            event.policy_id,
            event.outcome,
            event.timestamp.isoformat(),
        )
```

- [ ] **Step 6: Implement `audit/sinks/stdout.py`**

```python
from __future__ import annotations
import json

from tokenvault.protocols.audit_sink import AuditEvent


class StdoutAuditSink:
    def emit(self, event: AuditEvent) -> None:
        print(json.dumps({
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "operation": event.operation,
            "field_type": event.field_type,
            "algorithm": event.algorithm,
            "key_version": event.key_version,
            "policy_id": event.policy_id,
            "outcome": event.outcome,
            "metadata": event.metadata,
        }))
```

- [ ] **Step 7: Implement `audit/sinks/file.py`**

```python
from __future__ import annotations
import json
from pathlib import Path

from tokenvault.protocols.audit_sink import AuditEvent


class FileAuditSink:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def emit(self, event: AuditEvent) -> None:
        record = json.dumps({
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "operation": event.operation,
            "field_type": event.field_type,
            "algorithm": event.algorithm,
            "key_version": event.key_version,
            "policy_id": event.policy_id,
            "outcome": event.outcome,
            "metadata": event.metadata,
        })
        with self._path.open("a") as fh:
            fh.write(record + "\n")
```

- [ ] **Step 8: Run — expect all pass**

```bash
pytest tests/unit/test_audit.py -v
```

- [ ] **Step 9: Commit**

```bash
git add tokenvault/audit/ tests/unit/test_audit.py
git commit -m "feat: add audit system — AuditEvent, Redactor, Logging/Stdout/File sinks"
```

---

## Task 12: Policy Engine + PIPEDA Ruleset

**Files:**
- Create: `tokenvault/policy/rules.py`
- Create: `tokenvault/policy/engine.py`
- Create: `tokenvault/policy/pipeda.py`
- Create: `tests/unit/test_policy.py`

**Interfaces:**
- Consumes: `PolicyDecision` from `protocols/policy_guard.py`; `FieldType` from `fields/base.py`
- Produces: `FieldRule`, `RegionRule`, `PurposeRule`, `RuleSet`, `PolicyEngine`, `PIPEDA_DEFAULT_RULESET`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_policy.py`:
```python
import pytest
from tokenvault.protocols.policy_guard import PolicyDecision
from tokenvault.policy.rules import FieldRule, RegionRule, PurposeRule
from tokenvault.policy.engine import PolicyEngine, RuleSet


# --- FieldRule ---
def test_field_rule_allows_matching_operation():
    rule = FieldRule(
        field_type="email",
        allowed_operations=frozenset({"tokenize", "match"}),
        policy_id="test",
    )
    decision = rule.evaluate("email", "tokenize", {})
    assert decision is not None
    assert decision.allowed is True


def test_field_rule_denies_unlisted_operation():
    rule = FieldRule(
        field_type="email",
        allowed_operations=frozenset({"tokenize"}),
        policy_id="test",
    )
    decision = rule.evaluate("email", "detokenize", {})
    assert decision is not None
    assert decision.allowed is False


def test_field_rule_skips_other_field():
    rule = FieldRule(
        field_type="email",
        allowed_operations=frozenset({"tokenize"}),
        policy_id="test",
    )
    assert rule.evaluate("name", "tokenize", {}) is None


# --- RegionRule ---
def test_region_rule_allows_valid_destination():
    rule = RegionRule(
        origin_region="CA",
        allowed_destinations=frozenset({"US", "EU"}),
        policy_id="test",
    )
    d = rule.evaluate("email", "transfer", {"destination_region": "US"})
    assert d is not None and d.allowed is True


def test_region_rule_denies_invalid_destination():
    rule = RegionRule(
        origin_region="CA",
        allowed_destinations=frozenset({"US"}),
        policy_id="test",
    )
    d = rule.evaluate("email", "transfer", {"destination_region": "CN"})
    assert d is not None and d.allowed is False


def test_region_rule_skips_non_transfer():
    rule = RegionRule("CA", frozenset({"US"}), "test")
    assert rule.evaluate("email", "tokenize", {}) is None


# --- PurposeRule ---
def test_purpose_rule_allows_matching_purpose():
    rule = PurposeRule(required_purpose="data_transfer", policy_id="test")
    d = rule.evaluate("email", "tokenize", {"purpose": "data_transfer"})
    assert d is not None and d.allowed is True


def test_purpose_rule_denies_no_purpose():
    rule = PurposeRule(required_purpose="data_transfer", policy_id="test")
    d = rule.evaluate("email", "tokenize", {})
    assert d is not None and d.allowed is False


# --- PolicyEngine ---
def test_engine_default_deny_no_rules():
    engine = PolicyEngine(rule_sets=[RuleSet(rules=[], default_allow=False)])
    d = engine.evaluate("email", "tokenize", {})
    assert d.allowed is False


def test_engine_first_deny_wins():
    deny_rule = FieldRule("email", frozenset(), "deny")
    allow_rule = FieldRule("email", frozenset({"tokenize"}), "allow")
    engine = PolicyEngine(rule_sets=[
        RuleSet(rules=[deny_rule], default_allow=True),
        RuleSet(rules=[allow_rule], default_allow=True),
    ])
    d = engine.evaluate("email", "tokenize", {})
    assert d.allowed is False


# --- PIPEDA ---
def test_pipeda_ruleset_denies_without_purpose():
    from tokenvault.policy.pipeda import PIPEDA_DEFAULT_RULESET
    engine = PolicyEngine(rule_sets=[PIPEDA_DEFAULT_RULESET])
    d = engine.evaluate("email", "tokenize", {})
    assert d.allowed is False


def test_pipeda_ruleset_allows_with_purpose():
    from tokenvault.policy.pipeda import PIPEDA_DEFAULT_RULESET
    engine = PolicyEngine(rule_sets=[PIPEDA_DEFAULT_RULESET])
    d = engine.evaluate("email", "tokenize", {"purpose": "data_transfer"})
    assert d.allowed is True
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_policy.py -v
```

- [ ] **Step 3: Implement `policy/rules.py`**

```python
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from tokenvault.protocols.policy_guard import PolicyDecision


@dataclass(frozen=True)
class FieldRule:
    field_type: str
    allowed_operations: frozenset[str]
    policy_id: str = "field-rule"

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision | None:
        if field_type != self.field_type:
            return None
        if operation in self.allowed_operations:
            return PolicyDecision(
                allowed=True,
                policy_id=self.policy_id,
                reason=f"'{operation}' allowed for field '{field_type}'.",
            )
        return PolicyDecision(
            allowed=False,
            policy_id=self.policy_id,
            reason=f"'{operation}' not permitted for field '{field_type}'.",
        )


@dataclass(frozen=True)
class RegionRule:
    origin_region: str
    allowed_destinations: frozenset[str]
    policy_id: str = "region-rule"

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision | None:
        if operation != "transfer":
            return None
        dest = context.get("destination_region")
        if dest is None:
            return None
        if dest in self.allowed_destinations:
            return PolicyDecision(
                allowed=True,
                policy_id=self.policy_id,
                reason=f"Transfer to '{dest}' allowed from '{self.origin_region}'.",
            )
        return PolicyDecision(
            allowed=False,
            policy_id=self.policy_id,
            reason=f"Transfer to '{dest}' not allowed from '{self.origin_region}'.",
        )


@dataclass(frozen=True)
class PurposeRule:
    required_purpose: str
    policy_id: str = "purpose-rule"

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision | None:
        purpose = context.get("purpose")
        if purpose is None:
            return PolicyDecision(
                allowed=False,
                policy_id=self.policy_id,
                reason="No purpose declared in context.",
            )
        if purpose == self.required_purpose:
            return PolicyDecision(
                allowed=True,
                policy_id=self.policy_id,
                reason=f"Purpose '{purpose}' matches.",
            )
        return PolicyDecision(
            allowed=False,
            policy_id=self.policy_id,
            reason=f"Purpose '{purpose}' != required '{self.required_purpose}'.",
        )
```

- [ ] **Step 4: Implement `policy/engine.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Protocol

from tokenvault.protocols.policy_guard import PolicyDecision

_ALLOW_ALL = PolicyDecision(
    allowed=True, policy_id="default-allow", reason="No rules matched; default allow."
)
_DENY_ALL = PolicyDecision(
    allowed=False, policy_id="default-deny", reason="No rules matched; default deny."
)


class _Rule(Protocol):
    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision | None: ...


@dataclass
class RuleSet:
    rules: list[_Rule] = field(default_factory=list)
    default_allow: bool = True

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision:
        for rule in self.rules:
            decision = rule.evaluate(field_type, operation, context)
            if decision is not None and not decision.allowed:
                return decision
        return _ALLOW_ALL if self.default_allow else _DENY_ALL


class PolicyEngine:
    def __init__(self, rule_sets: list[RuleSet]) -> None:
        self._rule_sets = rule_sets

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision:
        for rs in self._rule_sets:
            decision = rs.evaluate(field_type, operation, context)
            if not decision.allowed:
                return decision
        return _ALLOW_ALL
```

- [ ] **Step 5: Implement `policy/pipeda.py`**

```python
from __future__ import annotations
from tokenvault.fields.base import FieldType
from tokenvault.policy.engine import RuleSet
from tokenvault.policy.rules import FieldRule, PurposeRule

_STANDARD_OPS = frozenset({"tokenize", "match", "transfer"})

PIPEDA_DEFAULT_RULESET = RuleSet(
    rules=[
        *(
            FieldRule(
                field_type=ft.value,
                allowed_operations=_STANDARD_OPS,
                policy_id=f"pipeda-{ft.value}",
            )
            for ft in FieldType
        ),
        PurposeRule(required_purpose="data_transfer", policy_id="pipeda-purpose"),
    ],
    default_allow=False,
)
```

- [ ] **Step 6: Run — expect all pass**

```bash
pytest tests/unit/test_policy.py -v
```

- [ ] **Step 7: Commit**

```bash
git add tokenvault/policy/ tests/unit/test_policy.py
git commit -m "feat: add PolicyEngine, FieldRule/RegionRule/PurposeRule, PIPEDA_DEFAULT_RULESET"
```

---

## Task 13: Transfer Utilities + PSI Stub

**Files:**
- Create: `tokenvault/transfer/payload.py`
- Create: `tokenvault/transfer/manifest.py`
- Create: `tokenvault/transfer/psi.py`
- Create: `tests/unit/test_transfer.py`

**Interfaces:**
- Consumes: `TokenResult` from `protocols/tokenizer.py`
- Produces: `TransferPayload`, `TransferManifest`, `FieldMapping`, `PrivateSetIntersectionMatcher`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_transfer.py`:
```python
import secrets
import pytest

from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.transfer.payload import TransferPayload
from tokenvault.transfer.manifest import FieldMapping, TransferManifest
from tokenvault.transfer.psi import PrivateSetIntersectionMatcher


@pytest.fixture()
def token_result():
    store = DirectKeyStore(keys={"v1": secrets.token_bytes(32)}, current_key_id="v1")
    t = HMACTokenizer(key_store=store)
    return t.tokenize("jane@example.com", "email")


def test_payload_contains_no_raw_pii(token_result):
    payload = TransferPayload()
    payload.add_record({"email": token_result})
    data = payload.to_dict()
    assert "jane@example.com" not in str(data)
    assert token_result.token in str(data)


def test_payload_multiple_records(token_result):
    payload = TransferPayload()
    payload.add_record({"email": token_result})
    payload.add_record({"email": token_result})
    assert len(payload.to_dict()["records"]) == 2


def test_manifest_to_dict(token_result):
    manifest = TransferManifest(
        source_region="CA",
        destination_region="US",
        policy_id="pipeda-default",
        consent_reference="consent-abc-123",
        field_mappings=[
            FieldMapping(
                field_name="email",
                field_type="email",
                algorithm=token_result.algorithm,
                key_version=token_result.key_version,
            )
        ],
    )
    d = manifest.to_dict()
    assert d["source_region"] == "CA"
    assert d["destination_region"] == "US"
    assert len(d["field_mappings"]) == 1
    assert "jane@example.com" not in str(d)


def test_psi_stub_raises():
    m = PrivateSetIntersectionMatcher()
    with pytest.raises(NotImplementedError):
        m.match("token_a", "token_b")
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_transfer.py -v
```

- [ ] **Step 3: Implement `transfer/payload.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from tokenvault.protocols.tokenizer import TokenResult


@dataclass
class TransferPayload:
    records: list[dict[str, str]] = field(default_factory=list)

    def add_record(self, tokenized: dict[str, TokenResult]) -> None:
        self.records.append({k: v.token for k, v in tokenized.items()})

    def to_dict(self) -> dict[str, Any]:
        return {"records": self.records}
```

- [ ] **Step 4: Implement `transfer/manifest.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class FieldMapping:
    field_name: str
    field_type: str
    algorithm: str
    key_version: str


@dataclass(frozen=True)
class TransferManifest:
    source_region: str
    destination_region: str
    policy_id: str
    consent_reference: str
    field_mappings: list[FieldMapping]
    created_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_region": self.source_region,
            "destination_region": self.destination_region,
            "policy_id": self.policy_id,
            "consent_reference": self.consent_reference,
            "created_at": self.created_at.isoformat(),
            "field_mappings": [
                {
                    "field_name": fm.field_name,
                    "field_type": fm.field_type,
                    "algorithm": fm.algorithm,
                    "key_version": fm.key_version,
                }
                for fm in self.field_mappings
            ],
        }
```

- [ ] **Step 5: Implement `transfer/psi.py`**

```python
from __future__ import annotations
from tokenvault.protocols.matcher import MatchResult


class PrivateSetIntersectionMatcher:
    """Stub for OPRF-based Private Set Intersection cross-system matching.

    Satisfies the Matcher protocol but raises NotImplementedError.

    Expected OPRF-PSI protocol (RFC draft, EPRINT 2016/799):
      1. Party A blinds elements: blinded_i = H(elem_i)^r  mod p
      2. Party B evaluates:       eval_i    = blinded_i^sk  mod p
      3. Party A unblinds:        final_i   = eval_i^(1/r) mod p
                                             = H(elem_i)^sk mod p
      4. Both parties sort and intersect on final_i values.
    Neither party learns the other's raw set.
    """

    algorithm = "psi-oprf-stub"

    def __init__(self, threshold: float = 1.0) -> None:
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        raise NotImplementedError(
            "PSI cross-system matching is not yet implemented. "
            "See tokenvault/transfer/psi.py for the expected OPRF contract."
        )
```

- [ ] **Step 6: Run — expect all pass**

```bash
pytest tests/unit/test_transfer.py -v
```

- [ ] **Step 7: Commit**

```bash
git add tokenvault/transfer/ tests/unit/test_transfer.py
git commit -m "feat: add TransferPayload, TransferManifest, PSI stub with OPRF contract"
```

---

## Task 14: VaultConfig + TokenVault Facade

**Files:**
- Create: `tokenvault/config.py`
- Create: `tokenvault/vault.py`
- Create: `tests/unit/test_vault.py`

**Interfaces:**
- Consumes: all protocol types, `PIIField`, `PythonLoggingAuditSink`, `ExactTokenMatcher`
- Produces: `VaultConfig`, `TokenVault`, `PolicyDeniedError`

- [ ] **Step 1: Write failing tests**

`tests/unit/test_vault.py`:
```python
import secrets
import pytest

from tokenvault.fields.base import FieldType, PIIField
from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.config import VaultConfig
from tokenvault.vault import TokenVault, PolicyDeniedError
from tokenvault.protocols.audit_sink import AuditEvent


class _CaptureSink:
    def __init__(self):
        self.events: list[AuditEvent] = []
    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


@pytest.fixture()
def capture():
    return _CaptureSink()


@pytest.fixture()
def vault(capture):
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    tokenizer = HMACTokenizer(key_store=store)
    return TokenVault(VaultConfig(
        key_store=store,
        tokenizer=tokenizer,
        matchers={"exact": ExactTokenMatcher()},
        audit_sink=capture,
    )), capture


def test_tokenize_returns_token_result(vault):
    tv, _ = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    result = tv.tokenize(field)
    assert result.token
    assert result.field_type == "email"


def test_tokenize_emits_audit_event(vault):
    tv, capture = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    tv.tokenize(field)
    assert len(capture.events) == 1
    assert capture.events[0].operation == "tokenize"
    assert capture.events[0].outcome == "success"


def test_audit_event_never_contains_raw_value(vault):
    tv, capture = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="sensitive@secret.com")
    tv.tokenize(field)
    for event in capture.events:
        assert "sensitive@secret.com" not in str(event)


def test_match_same_token(vault):
    tv, _ = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    r1 = tv.tokenize(field)
    r2 = tv.tokenize(field)
    match = tv.match(r1, r2, algorithm="exact")
    assert match.matched is True


def test_match_different_tokens(vault):
    tv, _ = vault
    f1 = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    f2 = PIIField(name="email", field_type=FieldType.EMAIL, value="john@example.com")
    r1 = tv.tokenize(f1)
    r2 = tv.tokenize(f2)
    match = tv.match(r1, r2, algorithm="exact")
    assert match.matched is False


def test_tokenize_record(vault):
    tv, _ = vault
    record = {
        "email": PIIField("email", FieldType.EMAIL, "jane@example.com"),
        "name": PIIField("name", FieldType.NAME, "Jane Smith"),
    }
    results = tv.tokenize_record(record)
    assert set(results.keys()) == {"email", "name"}


def test_policy_denied_emits_audit_event():
    from tokenvault.policy.engine import PolicyEngine, RuleSet
    from tokenvault.policy.rules import FieldRule

    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    tokenizer = HMACTokenizer(key_store=store)
    capture = _CaptureSink()
    deny_engine = PolicyEngine([
        RuleSet(rules=[FieldRule("email", frozenset(), "deny-all")], default_allow=False)
    ])
    tv = TokenVault(VaultConfig(
        key_store=store, tokenizer=tokenizer,
        policy_guard=deny_engine, audit_sink=capture,
    ))
    field = PIIField("email", FieldType.EMAIL, "jane@example.com")
    with pytest.raises(PolicyDeniedError):
        tv.tokenize(field)
    denied = [e for e in capture.events if e.outcome == "denied"]
    assert len(denied) == 1
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_vault.py -v
```

- [ ] **Step 3: Implement `config.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field

from tokenvault.protocols.audit_sink import AuditSink
from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.matcher import Matcher
from tokenvault.protocols.policy_guard import PolicyGuard
from tokenvault.protocols.tokenizer import Tokenizer


@dataclass
class VaultConfig:
    key_store: KeyStore
    tokenizer: Tokenizer
    matchers: dict[str, Matcher] = field(default_factory=dict)
    policy_guard: PolicyGuard | None = None
    audit_sink: AuditSink | None = None
    consent_reference: str = ""
    region: str = "CA"
```

- [ ] **Step 4: Implement `vault.py`**

```python
from __future__ import annotations
from typing import Any

from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
from tokenvault.config import VaultConfig
from tokenvault.fields.base import PIIField
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.protocols.matcher import MatchResult
from tokenvault.protocols.tokenizer import TokenResult


class PolicyDeniedError(Exception):
    """Raised when PolicyGuard denies an operation."""


class TokenVault:
    def __init__(self, config: VaultConfig) -> None:
        self._config = config
        self._sink = config.audit_sink or PythonLoggingAuditSink()
        self._fallback_matcher = ExactTokenMatcher()

    def tokenize(
        self,
        field: PIIField,
        context: dict[str, Any] | None = None,
    ) -> TokenResult:
        ctx = {"purpose": "data_transfer", **(context or {})}
        self._check_policy(field.field_type.value, "tokenize", ctx)
        result = self._config.tokenizer.tokenize(field.value, field.field_type.value)
        self._emit("tokenize", field.field_type.value, result.algorithm, result.key_version, "success", ctx)
        return result

    def tokenize_record(
        self,
        record: dict[str, PIIField],
        context: dict[str, Any] | None = None,
    ) -> dict[str, TokenResult]:
        return {name: self.tokenize(f, context) for name, f in record.items()}

    def match(
        self,
        token_a: TokenResult,
        token_b: TokenResult,
        algorithm: str = "exact",
        context: dict[str, Any] | None = None,
    ) -> MatchResult:
        ctx = {"purpose": "data_transfer", **(context or {})}
        self._check_policy(token_a.field_type, "match", ctx)
        matcher = self._config.matchers.get(algorithm, self._fallback_matcher)
        result = matcher.match(token_a.token, token_b.token)
        self._emit("match", token_a.field_type, algorithm, token_a.key_version, "success", ctx)
        return result

    def _check_policy(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> None:
        guard = self._config.policy_guard
        if guard is None:
            return
        decision = guard.evaluate(field_type, operation, context)
        if not decision.allowed:
            self._emit(operation, field_type, "n/a", "n/a", "denied", context,
                       {"reason": decision.reason, "policy_id": decision.policy_id})
            raise PolicyDeniedError(
                f"Policy '{decision.policy_id}' denied '{operation}' "
                f"on '{field_type}': {decision.reason}"
            )

    def _emit(
        self,
        operation: str,
        field_type: str,
        algorithm: str,
        key_version: str,
        outcome: str,
        context: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> None:
        self._sink.emit(AuditEvent(
            operation=operation,
            field_type=field_type,
            algorithm=algorithm,
            key_version=key_version,
            policy_id=str(context.get("policy_id", "default")),
            outcome=outcome,
            metadata=dict(extra or {}),
        ))
```

- [ ] **Step 5: Run — expect all pass**

```bash
pytest tests/unit/test_vault.py -v
```

- [ ] **Step 6: Commit**

```bash
git add tokenvault/config.py tokenvault/vault.py tests/unit/test_vault.py
git commit -m "feat: add VaultConfig and TokenVault facade with policy enforcement and audit emission"
```

---

## Task 15: CLI

**Files:**
- Create: `tokenvault/cli/commands.py`
- Create: `tests/unit/test_cli.py`

**Interfaces:**
- Consumes: `TokenVault`, `VaultConfig`, `HMACTokenizer`, `EnvKeyStore`, `PIIField`, `FieldType`, `FileAuditSink`
- Produces: `main()` entrypoint; `tokenvault tokenize`, `tokenvault match`, `tokenvault audit` subcommands

- [ ] **Step 1: Write failing tests**

`tests/unit/test_cli.py`:
```python
import csv
import json
import os
import secrets
import sys
import tempfile
import pytest

from tokenvault.cli.commands import main


@pytest.fixture()
def env_key(monkeypatch):
    key_hex = secrets.token_bytes(32).hex()
    monkeypatch.setenv("TOKENVAULT_KEY_TEST_V1", key_hex)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "test-v1")
    return key_hex


@pytest.fixture()
def config_file():
    data = '[fields]\nemail = "email"\nfull_name = "name"\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(data)
    yield f.name
    os.unlink(f.name)


@pytest.fixture()
def input_csv():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["email", "full_name"])
        writer.writeheader()
        writer.writerow({"email": "jane@example.com", "full_name": "Jane Smith"})
    yield f.name
    os.unlink(f.name)


def test_tokenize_command(env_key, config_file, input_csv):
    output = tempfile.mktemp(suffix=".csv")
    sys.argv = ["tokenvault", "tokenize",
                "--config", config_file,
                "--input", input_csv,
                "--output", output]
    main()
    rows = list(csv.DictReader(open(output)))
    assert len(rows) == 1
    assert rows[0]["email"] != "jane@example.com"
    assert len(rows[0]["email"]) > 10
    os.unlink(output)


def test_audit_command_reads_jsonl(capsys):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"event_id": "abc", "operation": "tokenize"}) + "\n")
        path = f.name
    sys.argv = ["tokenvault", "audit", "--log", path]
    main()
    out = capsys.readouterr().out
    assert "tokenize" in out
    os.unlink(path)
```

- [ ] **Step 2: Run — expect ImportError**

```bash
pytest tests/unit/test_cli.py -v
```

- [ ] **Step 3: Implement `cli/commands.py`**

```python
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path


def cmd_tokenize(args: argparse.Namespace) -> None:
    try:
        import tomllib  # stdlib 3.11+
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]  # backport for 3.10
    from tokenvault.fields.base import FieldType, PIIField
    from tokenvault.keys.env import EnvKeyStore
    from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
    from tokenvault.config import VaultConfig
    from tokenvault.vault import TokenVault

    with open(args.config, "rb") as fh:
        config_data = tomllib.load(fh)

    field_map: dict[str, str] = config_data.get("fields", {})
    store = EnvKeyStore()
    tokenizer = HMACTokenizer(key_store=store)
    vault = TokenVault(VaultConfig(key_store=store, tokenizer=tokenizer))

    with (
        open(args.input, newline="") as infile,
        open(args.output, "w", newline="") as outfile,
    ):
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames or []
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in reader:
            out: dict[str, str] = {}
            for col, val in row.items():
                ft_str = field_map.get(col, "custom")
                try:
                    ft = FieldType(ft_str)
                except ValueError:
                    ft = FieldType.CUSTOM
                result = vault.tokenize(PIIField(name=col, field_type=ft, value=val))
                out[col] = result.token
            writer.writerow(out)


def cmd_match(args: argparse.Namespace) -> None:
    print("tokenvault match: not yet implemented.", file=sys.stderr)
    sys.exit(1)


def cmd_audit(args: argparse.Namespace) -> None:
    path = Path(args.log)
    if not path.exists():
        print(f"Log file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            print(json.dumps(json.loads(line), indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="tokenvault",
        description="TokenVault PII tokenization CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_tok = sub.add_parser("tokenize", help="Tokenize a CSV of PII records")
    p_tok.add_argument("--config", required=True, help="Path to TOML config")
    p_tok.add_argument("--input", required=True, help="Input CSV path")
    p_tok.add_argument("--output", required=True, help="Output CSV path")
    p_tok.set_defaults(func=cmd_tokenize)

    p_match = sub.add_parser("match", help="Match two tokenized datasets")
    p_match.add_argument("--config", required=True)
    p_match.add_argument("--left", required=True)
    p_match.add_argument("--right", required=True)
    p_match.add_argument("--fields", required=True)
    p_match.set_defaults(func=cmd_match)

    p_audit = sub.add_parser("audit", help="Query an audit JSONL log")
    p_audit.add_argument("--log", required=True, help="Path to JSONL audit log")
    p_audit.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Add `tomli` backport to pyproject.toml for Python 3.10**

In `pyproject.toml`, add under `[project.optional-dependencies]`:
```toml
cli = ["tomli>=2.0; python_version < '3.11'"]
```
Update `all` group to include `cli`.

- [ ] **Step 5: Run — expect all pass**

```bash
pytest tests/unit/test_cli.py -v
```

- [ ] **Step 6: Commit**

```bash
git add tokenvault/cli/commands.py tests/unit/test_cli.py pyproject.toml
git commit -m "feat: add CLI with tokenize and audit subcommands"
```

---

## Task 16: Integration Tests, Public API Exports, and README

**Files:**
- Create: `tests/integration/test_end_to_end.py`
- Modify: `tokenvault/__init__.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: all prior tasks
- Produces: clean public surface, end-to-end verified, updated README

- [ ] **Step 1: Write integration tests**

`tests/integration/test_end_to_end.py`:
```python
import secrets
import pytest

from tokenvault.fields.base import FieldType, PIIField
from tokenvault.fields.email import EmailNormalizer
from tokenvault.fields.name import NameNormalizer
from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.matchers.ngram import NgramSimilarityMatcher
from tokenvault.matchers.composite import CompositeMatcher, WeightedMatcher
from tokenvault.policy.engine import PolicyEngine, RuleSet
from tokenvault.policy.pipeda import PIPEDA_DEFAULT_RULESET
from tokenvault.audit.sinks.stdout import StdoutAuditSink
from tokenvault.transfer.payload import TransferPayload
from tokenvault.transfer.manifest import FieldMapping, TransferManifest
from tokenvault.config import VaultConfig
from tokenvault.vault import TokenVault, PolicyDeniedError
from tokenvault.protocols.audit_sink import AuditEvent


class _CaptureSink:
    def __init__(self): self.events: list[AuditEvent] = []
    def emit(self, e: AuditEvent): self.events.append(e)


@pytest.fixture()
def setup():
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    tokenizer = HMACTokenizer(key_store=store)
    capture = _CaptureSink()
    vault = TokenVault(VaultConfig(
        key_store=store,
        tokenizer=tokenizer,
        matchers={
            "exact": ExactTokenMatcher(),
            "composite": CompositeMatcher([
                WeightedMatcher(ExactTokenMatcher(), 0.4),
                WeightedMatcher(NgramSimilarityMatcher(n=2), 0.6),
            ], threshold=0.5),
        },
        audit_sink=capture,
    ))
    return vault, capture


def test_exact_match_same_value_after_normalization(setup):
    vault, capture = setup
    norm = EmailNormalizer()
    f1 = PIIField("email", FieldType.EMAIL, norm.normalize("Jane@Example.COM"))
    f2 = PIIField("email", FieldType.EMAIL, norm.normalize("jane@example.com"))
    r1 = vault.tokenize(f1)
    r2 = vault.tokenize(f2)
    result = vault.match(r1, r2, algorithm="exact")
    assert result.matched is True


def test_different_values_do_not_match(setup):
    vault, _ = setup
    norm = EmailNormalizer()
    f1 = PIIField("email", FieldType.EMAIL, norm.normalize("jane@example.com"))
    f2 = PIIField("email", FieldType.EMAIL, norm.normalize("john@example.com"))
    r1 = vault.tokenize(f1)
    r2 = vault.tokenize(f2)
    assert vault.match(r1, r2, algorithm="exact").matched is False


def test_audit_trail_no_pii(setup):
    vault, capture = setup
    vault.tokenize(PIIField("email", FieldType.EMAIL, "secret@example.com"))
    for event in capture.events:
        assert "secret@example.com" not in str(event)


def test_cross_field_tokens_never_collide(setup):
    vault, _ = setup
    f_email = PIIField("email", FieldType.EMAIL, "same")
    f_name = PIIField("name", FieldType.NAME, "same")
    r_email = vault.tokenize(f_email)
    r_name = vault.tokenize(f_name)
    assert r_email.token != r_name.token


def test_policy_deny_emits_audit_event():
    from tokenvault.policy.rules import FieldRule
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    capture = _CaptureSink()
    engine = PolicyEngine([RuleSet([FieldRule("email", frozenset(), "deny")], default_allow=False)])
    vault = TokenVault(VaultConfig(
        key_store=store,
        tokenizer=HMACTokenizer(key_store=store),
        policy_guard=engine,
        audit_sink=capture,
    ))
    with pytest.raises(PolicyDeniedError):
        vault.tokenize(PIIField("email", FieldType.EMAIL, "x"))
    assert any(e.outcome == "denied" for e in capture.events)


def test_pipeda_requires_purpose():
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    engine = PolicyEngine([PIPEDA_DEFAULT_RULESET])
    vault = TokenVault(VaultConfig(
        key_store=store,
        tokenizer=HMACTokenizer(key_store=store),
        policy_guard=engine,
    ))
    with pytest.raises(PolicyDeniedError):
        vault.tokenize(
            PIIField("email", FieldType.EMAIL, "jane@example.com"),
            context={}  # no purpose
        )
    result = vault.tokenize(
        PIIField("email", FieldType.EMAIL, "jane@example.com"),
        context={"purpose": "data_transfer"},
    )
    assert result.token


def test_transfer_payload_contains_no_raw_pii(setup):
    vault, _ = setup
    norm = EmailNormalizer()
    field = PIIField("email", FieldType.EMAIL, norm.normalize("jane@example.com"))
    token = vault.tokenize(field)
    payload = TransferPayload()
    payload.add_record({"email": token})
    assert "jane@example.com" not in str(payload.to_dict())


def test_full_cross_border_workflow(setup):
    vault, capture = setup
    email_norm = EmailNormalizer()
    name_norm = NameNormalizer()

    record = {
        "email": PIIField("email", FieldType.EMAIL, email_norm.normalize("Jane@Example.COM")),
        "name": PIIField("name", FieldType.NAME, name_norm.normalize("JANE SMITH")),
    }
    tokens = vault.tokenize_record(record, context={"purpose": "data_transfer"})

    payload = TransferPayload()
    payload.add_record(tokens)

    manifest = TransferManifest(
        source_region="CA",
        destination_region="US",
        policy_id="pipeda-default",
        consent_reference="consent-ref-001",
        field_mappings=[
            FieldMapping(
                field_name=k,
                field_type=v.field_type,
                algorithm=v.algorithm,
                key_version=v.key_version,
            )
            for k, v in tokens.items()
        ],
    )
    d = payload.to_dict()
    m = manifest.to_dict()

    assert "jane@example.com" not in str(d)
    assert "jane@example.com" not in str(m)
    assert m["source_region"] == "CA"
    assert len(d["records"]) == 1
    assert len(capture.events) == 2
```

- [ ] **Step 2: Run integration tests**

```bash
pytest tests/integration/test_end_to_end.py -v
```

- [ ] **Step 3: Update `tokenvault/__init__.py` with public surface**

```python
from tokenvault.vault import TokenVault, PolicyDeniedError
from tokenvault.config import VaultConfig
from tokenvault.fields.base import FieldType, PIIField
from tokenvault.protocols.tokenizer import TokenResult
from tokenvault.protocols.matcher import MatchResult
from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.protocols.policy_guard import PolicyDecision
from tokenvault.protocols.key_store import KeyEntropyError

__version__ = "0.1.0"

__all__ = [
    "TokenVault",
    "PolicyDeniedError",
    "VaultConfig",
    "FieldType",
    "PIIField",
    "TokenResult",
    "MatchResult",
    "AuditEvent",
    "PolicyDecision",
    "KeyEntropyError",
    "__version__",
]
```

- [ ] **Step 4: Update `README.md`**

Replace the entire file with a comprehensive README covering: install, quickstart, key management, normalizers, tokenization strategies, matching, PIPEDA policy, audit sinks, cross-border transfer, CLI usage, contributing, license. See spec section 11 for CLI examples.

- [ ] **Step 5: Run full test suite**

```bash
pytest --tb=short -q
```

Expected: all tests pass, 0 errors.

- [ ] **Step 6: Final commit**

```bash
git add tests/integration/ tokenvault/__init__.py README.md
git commit -m "feat: add integration tests, public API exports, and comprehensive README"
```
