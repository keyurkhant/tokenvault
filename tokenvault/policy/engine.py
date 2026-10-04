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
        last_match: PolicyDecision | None = None
        for rule in self.rules:
            decision = rule.evaluate(field_type, operation, context)
            if decision is not None:
                if not decision.allowed:
                    return decision
                last_match = decision
        if last_match is not None:
            return last_match
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
