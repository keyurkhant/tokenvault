from __future__ import annotations

from typing import Any

from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
from tokenvault.config import VaultConfig
from tokenvault.fields.base import FieldType, PIIField
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.protocols.matcher import MatchResult
from tokenvault.protocols.policy_guard import PolicyDecision
from tokenvault.protocols.tokenizer import TokenResult


class PolicyDeniedError(Exception):
    """Raised when PolicyGuard denies an operation."""


class UnsupportedOperationError(Exception):
    """Raised when the tokenizer does not support the requested operation."""


class TokenVault:
    def __init__(self, config: VaultConfig) -> None:
        self._config = config
        self._sink = config.audit_sink or PythonLoggingAuditSink()
        self._fallback_matcher = ExactTokenMatcher()

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
