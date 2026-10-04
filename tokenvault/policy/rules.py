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
        ctx_origin = context.get("origin_region")
        if ctx_origin is not None and ctx_origin != self.origin_region:
            return None
        destination = context.get("destination_region")
        if destination is None:
            return None
        if destination in self.allowed_destinations:
            return PolicyDecision(
                allowed=True,
                policy_id=self.policy_id,
                reason=f"destination {destination!r} is allowed",
            )
        return PolicyDecision(
            allowed=False,
            policy_id=self.policy_id,
            reason=f"destination {destination!r} not in allowed_destinations",
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
