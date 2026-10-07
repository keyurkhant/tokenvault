from __future__ import annotations

from pathlib import Path
from typing import Any

from tokenvault.config import VaultConfig
from tokenvault.keys.env import EnvKeyStore
from tokenvault.keys.file import FileKeyStore
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.protocols.audit_sink import AuditSink
from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.matcher import Matcher
from tokenvault.protocols.policy_guard import PolicyGuard
from tokenvault.protocols.tokenizer import Tokenizer
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.tokenizers.uuid_random import UUIDRandomTokenizer


class ConfigError(ValueError):
    """Raised when a TOML vault config is invalid or references an unsupported value."""


def load_vault_config(path: str | Path) -> VaultConfig:
    """Parse *path* (TOML) and return a fully wired :class:`VaultConfig`."""
    try:
        import tomllib  # type: ignore[import-not-found]  # stdlib 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found]  # backport 3.10
        except ImportError:
            raise ImportError(
                "TOML config requires 'tomli' on Python < 3.11. "
                "Install with: pip install 'tokenvault[cli]'"
            ) from None

    with open(path, "rb") as fh:
        data: dict[str, Any] = tomllib.load(fh)

    vault_section: dict[str, Any] = data.get("vault", {})
    ks_section: dict[str, Any] = data.get("key_store", {})
    tok_section: dict[str, Any] = data.get("tokenizer", {})
    matchers_list: list[dict[str, Any]] = data.get("matchers", [])
    policy_section: dict[str, Any] = data.get("policy", {})
    audit_section: dict[str, Any] = data.get("audit", {})

    key_store = _build_key_store(ks_section)
    tokenizer = _build_tokenizer(tok_section, key_store)
    matchers = _build_matchers(matchers_list)
    policy_guard = _build_policy_guard(policy_section)
    audit_sink = _build_audit_sink(audit_section)

    return VaultConfig(
        key_store=key_store,
        tokenizer=tokenizer,
        matchers=matchers,
        policy_guard=policy_guard,
        audit_sink=audit_sink,
        region=str(vault_section.get("region", "CA")),
        consent_reference=str(vault_section.get("consent_reference", "")),
    )


def _build_key_store(section: dict[str, Any]) -> KeyStore:
    backend = str(section.get("backend", "env"))
    if backend == "env":
        prefix = str(section.get("prefix", "TOKENVAULT_KEY_"))
        return EnvKeyStore(prefix=prefix)
    if backend == "file":
        file_path = section.get("path")
        if file_path is None:
            raise ConfigError("[key_store] backend='file' requires a 'path' entry")
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return FileKeyStore(path=str(file_path))
    if backend == "direct":
        raise ConfigError(
            "[key_store] backend='direct' cannot be loaded from a file; "
            "use 'env' or 'file' instead"
        )
    raise ConfigError(f"[key_store] unknown backend: {backend!r}")


def _build_tokenizer(section: dict[str, Any], key_store: KeyStore) -> Tokenizer:
    algorithm = str(section.get("algorithm", "hmac-sha256"))
    if algorithm == "hmac-sha256":
        return HMACTokenizer(key_store=key_store)
    if algorithm == "aes-siv":
        from tokenvault.tokenizers.aes_siv import AESSIVTokenizer
        return AESSIVTokenizer(key_store=key_store)
    if algorithm == "argon2":
        from tokenvault.tokenizers.argon2_opaque import Argon2OpaqueTokenizer
        return Argon2OpaqueTokenizer()
    if algorithm == "uuid":
        return UUIDRandomTokenizer()
    raise ConfigError(f"[tokenizer] unknown algorithm: {algorithm!r}")


def _build_matchers(matchers_list: list[dict[str, Any]]) -> dict[str, Matcher]:
    matchers: dict[str, Matcher] = {}
    for entry in matchers_list:
        name = entry.get("name")
        algo = entry.get("algorithm")
        if not name or not algo:
            raise ConfigError(
                "Each [[matchers]] entry must have both 'name' and 'algorithm'"
            )
        name = str(name)
        algo = str(algo)
        threshold = float(entry.get("threshold", 0.9))
        if algo == "exact":
            matchers[name] = ExactTokenMatcher(threshold=threshold)
        elif algo == "jaro-winkler":
            from tokenvault.matchers.jaro_winkler import JaroWinklerMatcher
            matchers[name] = JaroWinklerMatcher(threshold=threshold)
        elif algo == "levenshtein":
            from tokenvault.matchers.levenshtein import LevenshteinMatcher
            matchers[name] = LevenshteinMatcher(threshold=threshold)
        elif algo == "ngram":
            from tokenvault.matchers.ngram import NgramSimilarityMatcher
            n = int(entry.get("n", 2))
            matchers[name] = NgramSimilarityMatcher(n=n, threshold=threshold)
        elif algo == "soundex":
            from tokenvault.matchers.phonetic import SoundexMatcher
            matchers[name] = SoundexMatcher()
        elif algo == "metaphone":
            from tokenvault.matchers.phonetic import MetaphoneMatcher
            matchers[name] = MetaphoneMatcher()
        else:
            raise ConfigError(f"[[matchers]] unknown algorithm: {algo!r}")
    return matchers


def _build_policy_guard(section: dict[str, Any]) -> PolicyGuard | None:
    ruleset = str(section.get("ruleset", "none"))
    if ruleset in ("none", ""):
        return None
    if ruleset == "pipeda":
        from tokenvault.policy.pipeda import PIPEDA_DEFAULT_RULESET
        return PIPEDA_DEFAULT_RULESET
    raise ConfigError(
        f"[policy] unknown ruleset: {ruleset!r}. Supported values: 'none', 'pipeda'"
    )


def _build_audit_sink(section: dict[str, Any]) -> AuditSink | None:
    sink = str(section.get("sink", "logging"))
    if sink == "logging":
        from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
        return PythonLoggingAuditSink()
    if sink == "stdout":
        from tokenvault.audit.sinks.stdout import StdoutAuditSink
        return StdoutAuditSink()
    if sink == "file":
        file_path = section.get("path")
        if file_path is None:
            raise ConfigError("[audit] sink='file' requires a 'path' entry")
        from tokenvault.audit.sinks.file import FileAuditSink
        return FileAuditSink(path=str(file_path))
    raise ConfigError(f"[audit] unknown sink: {sink!r}. Supported: 'logging', 'stdout', 'file'")
