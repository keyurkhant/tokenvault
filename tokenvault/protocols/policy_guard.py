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
