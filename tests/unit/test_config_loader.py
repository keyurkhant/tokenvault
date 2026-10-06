"""Tests for config_loader.load_vault_config and TokenVault.from_config."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tokenvault.config_loader import ConfigError, load_vault_config
from tokenvault.keys.env import EnvKeyStore
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.matchers.ngram import NgramSimilarityMatcher
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.tokenizers.uuid_random import UUIDRandomTokenizer
from tokenvault.vault import TokenVault

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_toml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "vault.toml"
    p.write_text(textwrap.dedent(content))
    return p


def _env_key(monkeypatch: pytest.MonkeyPatch, key_id: str = "V1") -> None:
    """Inject a 32-byte key and matching current-key env var."""
    raw = "a" * 64  # 32 hex bytes
    monkeypatch.setenv(f"TOKENVAULT_KEY_{key_id}", raw)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", key_id.lower())


# ---------------------------------------------------------------------------
# minimal config
# ---------------------------------------------------------------------------

def test_minimal_config_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, "")
    config = load_vault_config(cfg_path)

    assert config.region == "CA"
    assert config.consent_reference == ""
    assert isinstance(config.key_store, EnvKeyStore)
    assert isinstance(config.tokenizer, HMACTokenizer)
    assert config.matchers == {}
    assert config.policy_guard is None
    # audit_sink defaults to PythonLoggingAuditSink; just verify not None
    assert config.audit_sink is not None


# ---------------------------------------------------------------------------
# [vault] section
# ---------------------------------------------------------------------------

def test_vault_section(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [vault]
        region = "EU"
        consent_reference = "gdpr-v3"
    """)
    config = load_vault_config(cfg_path)
    assert config.region == "EU"
    assert config.consent_reference == "gdpr-v3"


# ---------------------------------------------------------------------------
# [key_store] section
# ---------------------------------------------------------------------------

def test_key_store_env_custom_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TV_KEY_V1", "b" * 64)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "v1")
    cfg_path = _write_toml(tmp_path, """
        [key_store]
        backend = "env"
        prefix  = "TV_KEY_"
    """)
    config = load_vault_config(cfg_path)
    assert isinstance(config.key_store, EnvKeyStore)


def test_key_store_file_backend(tmp_path: Path) -> None:
    import json
    key_hex = "c" * 64
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"current_key_id": "v1", "keys": {"v1": key_hex}}))
    cfg_path = _write_toml(tmp_path, f"""
        [key_store]
        backend = "file"
        path    = "{key_file}"
    """)
    from tokenvault.keys.file import FileKeyStore
    config = load_vault_config(cfg_path)
    assert isinstance(config.key_store, FileKeyStore)


def test_key_store_file_missing_path_raises(tmp_path: Path) -> None:
    cfg_path = _write_toml(tmp_path, """
        [key_store]
        backend = "file"
    """)
    with pytest.raises(ConfigError, match="requires a 'path'"):
        load_vault_config(cfg_path)


def test_key_store_direct_raises(tmp_path: Path) -> None:
    cfg_path = _write_toml(tmp_path, """
        [key_store]
        backend = "direct"
    """)
    with pytest.raises(ConfigError, match="cannot be loaded from a file"):
        load_vault_config(cfg_path)


def test_key_store_unknown_backend_raises(tmp_path: Path) -> None:
    cfg_path = _write_toml(tmp_path, """
        [key_store]
        backend = "vault"
    """)
    with pytest.raises(ConfigError, match="unknown backend"):
        load_vault_config(cfg_path)


# ---------------------------------------------------------------------------
# [tokenizer] section
# ---------------------------------------------------------------------------

def test_tokenizer_hmac(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [tokenizer]
        algorithm = "hmac-sha256"
    """)
    config = load_vault_config(cfg_path)
    assert isinstance(config.tokenizer, HMACTokenizer)


def test_tokenizer_uuid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [tokenizer]
        algorithm = "uuid"
    """)
    config = load_vault_config(cfg_path)
    assert isinstance(config.tokenizer, UUIDRandomTokenizer)


def test_tokenizer_unknown_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [tokenizer]
        algorithm = "sha512"
    """)
    with pytest.raises(ConfigError, match="unknown algorithm"):
        load_vault_config(cfg_path)


# ---------------------------------------------------------------------------
# [[matchers]] section
# ---------------------------------------------------------------------------

def test_matchers_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [[matchers]]
        name      = "exact"
        algorithm = "exact"
    """)
    config = load_vault_config(cfg_path)
    assert "exact" in config.matchers
    assert isinstance(config.matchers["exact"], ExactTokenMatcher)


def test_matchers_ngram(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [[matchers]]
        name      = "ngram"
        algorithm = "ngram"
        n         = 3
        threshold = 0.6
    """)
    config = load_vault_config(cfg_path)
    assert isinstance(config.matchers["ngram"], NgramSimilarityMatcher)


def test_matchers_multiple(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [[matchers]]
        name      = "exact"
        algorithm = "exact"

        [[matchers]]
        name      = "similarity"
        algorithm = "ngram"
    """)
    config = load_vault_config(cfg_path)
    assert set(config.matchers.keys()) == {"exact", "similarity"}


def test_matchers_missing_name_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [[matchers]]
        algorithm = "exact"
    """)
    with pytest.raises(ConfigError, match="'name' and 'algorithm'"):
        load_vault_config(cfg_path)


def test_matchers_unknown_algo_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [[matchers]]
        name      = "x"
        algorithm = "cosine"
    """)
    with pytest.raises(ConfigError, match="unknown algorithm"):
        load_vault_config(cfg_path)


# ---------------------------------------------------------------------------
# [policy] section
# ---------------------------------------------------------------------------

def test_policy_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [policy]
        ruleset = "none"
    """)
    config = load_vault_config(cfg_path)
    assert config.policy_guard is None


def test_policy_pipeda(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [policy]
        ruleset = "pipeda"
    """)
    config = load_vault_config(cfg_path)
    assert config.policy_guard is not None


def test_policy_unknown_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [policy]
        ruleset = "hipaa"
    """)
    with pytest.raises(ConfigError, match="unknown ruleset"):
        load_vault_config(cfg_path)


# ---------------------------------------------------------------------------
# [audit] section
# ---------------------------------------------------------------------------

def test_audit_logging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [audit]
        sink = "logging"
    """)
    from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
    config = load_vault_config(cfg_path)
    assert isinstance(config.audit_sink, PythonLoggingAuditSink)


def test_audit_stdout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [audit]
        sink = "stdout"
    """)
    from tokenvault.audit.sinks.stdout import StdoutAuditSink
    config = load_vault_config(cfg_path)
    assert isinstance(config.audit_sink, StdoutAuditSink)


def test_audit_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, f"""
        [audit]
        sink = "file"
        path = "{tmp_path / 'audit.jsonl'}"
    """)
    from tokenvault.audit.sinks.file import FileAuditSink
    config = load_vault_config(cfg_path)
    assert isinstance(config.audit_sink, FileAuditSink)


def test_audit_file_missing_path_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [audit]
        sink = "file"
    """)
    with pytest.raises(ConfigError, match="requires a 'path'"):
        load_vault_config(cfg_path)


def test_audit_unknown_sink_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [audit]
        sink = "kafka"
    """)
    with pytest.raises(ConfigError, match="unknown sink"):
        load_vault_config(cfg_path)


# ---------------------------------------------------------------------------
# TokenVault.from_config integration
# ---------------------------------------------------------------------------

def test_from_config_returns_token_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [vault]
        region = "CA"

        [key_store]
        backend = "env"

        [tokenizer]
        algorithm = "hmac-sha256"

        [[matchers]]
        name      = "exact"
        algorithm = "exact"

        [policy]
        ruleset = "none"

        [audit]
        sink = "logging"
    """)
    vault = TokenVault.from_config(cfg_path)
    assert isinstance(vault, TokenVault)
    assert vault.config.region == "CA"


def test_from_config_tokenizes_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: vault built from TOML can tokenize a field."""
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, """
        [key_store]
        backend = "env"

        [tokenizer]
        algorithm = "hmac-sha256"
    """)
    from tokenvault.fields.base import FieldType, PIIField

    vault = TokenVault.from_config(cfg_path)
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="Alice@Example.com")
    result = vault.tokenize(field)
    # Normalizer lowercases → "alice@example.com" → deterministic token
    assert result.token
    assert result.algorithm == "hmac-sha256"
    # Idempotent: same normalised value produces same token
    result2 = vault.tokenize(field)
    assert result.token == result2.token


def test_from_config_accepts_string_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _env_key(monkeypatch)
    cfg_path = _write_toml(tmp_path, "")
    vault = TokenVault.from_config(str(cfg_path))
    assert isinstance(vault, TokenVault)
