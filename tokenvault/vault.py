from __future__ import annotations

from pathlib import Path
from typing import Any

from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
from tokenvault.config import VaultConfig
from tokenvault.fields.base import FieldType, PIIField
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.matcher import MatchResult
from tokenvault.protocols.policy_guard import PolicyDecision
from tokenvault.protocols.tokenizer import TokenResult


class _FixedKeyStore:
    """Wraps a KeyStore but always reports a specific key_id as current.

    Used internally to re-tokenize under a target key without mutating the
    shared tokenizer or key store.
    """

    def __init__(self, delegate: KeyStore, key_id: str) -> None:
        self._delegate = delegate
        self._key_id = key_id

    def get_key(self, key_id: str) -> bytes:
        return self._delegate.get_key(key_id)

    def get_current_key_id(self) -> str:
        return self._key_id


class PolicyDeniedError(Exception):
    """Raised when PolicyGuard denies an operation."""


class UnsupportedOperationError(Exception):
    """Raised when the tokenizer does not support the requested operation."""


class TokenVault:
    def __init__(self, config: VaultConfig) -> None:
        self._config = config
        self._sink = config.audit_sink or PythonLoggingAuditSink()
        self._fallback_matcher = ExactTokenMatcher()

    @classmethod
    def from_config(cls, path: str | Path) -> TokenVault:
        """Construct a :class:`TokenVault` from a TOML config file."""
        from tokenvault.config_loader import load_vault_config
        return cls(load_vault_config(path))

    @property
    def config(self) -> VaultConfig:
        return self._config

    def tokenize(
        self,
        field: PIIField,
        context: dict[str, Any] | None = None,
    ) -> TokenResult:
        ctx = context if context is not None else {"purpose": "data_transfer"}
        decision = self._check_policy(field, "tokenize", ctx)
        if not decision.allowed:
            _sentinel = TokenResult(
                token="", field_type=field.field_type.value,
                algorithm="n/a", key_version="n/a", is_deterministic=False,
            )
            self._emit(
                field, _sentinel, "tokenize", ctx,
                outcome="denied",
                extra={"reason": decision.reason, "policy_id": decision.policy_id},
            )
            raise PolicyDeniedError(
                f"Policy '{decision.policy_id}' denied 'tokenize' "
                f"on '{field.field_type.value}': {decision.reason}"
            )
        # Normalize the field value before tokenizing
        normalizer = self._config.normalizers.get(field.field_type)
        if normalizer is not None:
            normalized_value = normalizer.normalize(field.value)
            field = PIIField(
                name=field.name,
                field_type=field.field_type,
                value=normalized_value,
            )
        result = self._config.tokenizer.tokenize(field.value, field.field_type.value)
        self._emit(field, result, "tokenize", ctx)
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
        ctx = context if context is not None else {"purpose": "data_transfer"}
        # Use a synthetic PIIField for policy check on match
        field_a = PIIField(
            name="<match>",
            field_type=FieldType(token_a.field_type),
            value="[REDACTED]",
        )
        decision = self._check_policy(field_a, "match", ctx)
        if not decision.allowed:
            self._emit(
                field_a, token_a, "match", ctx,
                outcome="denied",
                extra={"reason": decision.reason, "policy_id": decision.policy_id},
            )
            raise PolicyDeniedError(
                f"Policy '{decision.policy_id}' denied 'match' "
                f"on '{token_a.field_type}': {decision.reason}"
            )
        matcher = self._config.matchers.get(algorithm, self._fallback_matcher)
        result = matcher.match(token_a.token, token_b.token)
        self._emit(field_a, token_a, "match", ctx)
        return result

    def detokenize(
        self,
        token_result: TokenResult,
        context: dict[str, Any] | None = None,
    ) -> str:
        ctx = {**(context or {}), "operation": "detokenize", "allow_reversible": True}
        field = PIIField(
            name="<token>",
            field_type=FieldType(token_result.field_type),
            value="[REDACTED]",
        )
        decision = self._check_policy(field, "detokenize", ctx)
        if not decision.allowed:
            self._emit(
                field, token_result, "detokenize", ctx,
                outcome="denied",
                extra={"reason": decision.reason, "policy_id": decision.policy_id},
            )
            raise PolicyDeniedError(f"detokenize denied by policy: {decision.reason}")
        if not hasattr(self._config.tokenizer, "_detokenize"):
            raise UnsupportedOperationError("tokenizer does not support detokenization")
        raw: str = self._config.tokenizer._detokenize(token_result)
        self._emit(field, token_result, "detokenize", ctx)
        return raw

    def rotate_batch(
        self,
        records: list[TokenResult],
        new_key_id: str,
        context: dict[str, Any] | None = None,
    ) -> list[TokenResult]:
        """Re-tokenize *records* under *new_key_id*.

        Requires a reversible tokenizer (AES-SIV). Each record is decrypted
        with its stored key version, then re-encrypted under *new_key_id*.
        Emits one ``key_rotation`` audit event per record.

        Use :meth:`retoken` for HMAC-SHA256 when you have the original
        :class:`~tokenvault.fields.base.PIIField`.
        """
        tok = self._config.tokenizer
        if not hasattr(tok, "_detokenize"):
            raise UnsupportedOperationError(
                "rotate_batch requires a reversible tokenizer (e.g. aes-siv); "
                "use retoken() for HMAC-SHA256 when you have the original PIIField"
            )
        ctx = context if context is not None else {"purpose": "key_rotation"}
        # Validate new_key_id is accessible before touching any record
        self._config.key_store.get_key(new_key_id)
        fixed = _FixedKeyStore(self._config.key_store, new_key_id)
        new_tok = tok.__class__(key_store=fixed)  # type: ignore[call-arg]
        results: list[TokenResult] = []
        for old in records:
            raw: str = tok._detokenize(old)
            new = new_tok.tokenize(raw, old.field_type)
            self._emit_rotation(old, new, ctx)
            results.append(new)
        return results

    def retoken(
        self,
        field: PIIField,
        old_key_id: str,
        new_key_id: str,
        context: dict[str, Any] | None = None,
    ) -> TokenResult:
        """Re-tokenize *field* from *old_key_id* to *new_key_id*.

        Intended for HMAC-SHA256 (and any key-store-based tokenizer) where
        decryption of the existing token is not possible. The caller must
        supply the original :class:`~tokenvault.fields.base.PIIField`.
        Normalization is applied before tokenization. Emits one
        ``key_rotation`` audit event.
        """
        tok = self._config.tokenizer
        if not hasattr(tok, "_key_store"):
            raise UnsupportedOperationError(
                "retoken requires a key-store-based tokenizer (hmac-sha256 or aes-siv)"
            )
        ctx = context if context is not None else {"purpose": "key_rotation"}
        normalizer = self._config.normalizers.get(field.field_type)
        if normalizer is not None:
            field = PIIField(
                name=field.name,
                field_type=field.field_type,
                value=normalizer.normalize(field.value),
            )
        fixed = _FixedKeyStore(self._config.key_store, new_key_id)
        new_tok = tok.__class__(key_store=fixed)  # type: ignore[call-arg]
        old_sentinel = TokenResult(
            token="[rotated]",
            field_type=field.field_type.value,
            algorithm=tok.algorithm,  # type: ignore[attr-defined]
            key_version=old_key_id,
            is_deterministic=True,
        )
        new = new_tok.tokenize(field.value, field.field_type.value)
        self._emit_rotation(old_sentinel, new, ctx)
        return new

    def _check_policy(
        self, field: PIIField, operation: str, context: dict[str, Any]
    ) -> PolicyDecision:
        guard = self._config.policy_guard
        if guard is None:
            return PolicyDecision(
                allowed=True,
                policy_id="default",
                reason="no policy guard configured",
            )
        return guard.evaluate(field.field_type.value, operation, context)

    def _emit(
        self,
        field: PIIField,
        result: TokenResult,
        operation: str,
        context: dict[str, Any],
        outcome: str = "success",
        extra: dict[str, Any] | None = None,
    ) -> None:
        self._sink.emit(AuditEvent(
            operation=operation,
            field_type=field.field_type.value,
            algorithm=result.algorithm,
            key_version=result.key_version,
            policy_id=str(context.get("policy_id", "default")),
            outcome=outcome,
            metadata=dict(extra or {}),  # type: ignore[arg-type]
        ))

    def _emit_rotation(
        self,
        old: TokenResult,
        new: TokenResult,
        context: dict[str, Any],
    ) -> None:
        self._sink.emit(AuditEvent(
            operation="key_rotation",
            field_type=old.field_type,
            algorithm=new.algorithm,
            key_version=new.key_version,
            policy_id=str(context.get("policy_id", "default")),
            outcome="success",
            metadata={"old_key_version": old.key_version},  # type: ignore[arg-type]
        ))
