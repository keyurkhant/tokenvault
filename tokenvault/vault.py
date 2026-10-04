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
        ctx = context if context is not None else {"purpose": "data_transfer"}
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
        ctx = context if context is not None else {"purpose": "data_transfer"}
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
            self._emit(
                operation, field_type, "n/a", "n/a", "denied", context,
                {"reason": decision.reason, "policy_id": decision.policy_id},
            )
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
