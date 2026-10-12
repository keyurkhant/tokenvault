from __future__ import annotations

from typing import Any

from tokenvault.policy.engine import RuleSet
from tokenvault.policy.rules import FieldRule
from tokenvault.protocols.policy_guard import PolicyDecision

# Cal. Civ. Code § 1798.140(o) — categories of personal information under CCPA.
CCPA_PERSONAL_INFO_CATEGORIES: frozenset[str] = frozenset({
    "name",
    "email",
    "phone",
    "address",
    "ip_address",
    "date_of_birth",
    "national_id",         # SSN and government IDs
    "biometric",
    "geolocation",
    "browsing_history",
    "purchase_history",
    "financial_info",
    "health",
    "custom",
})

# CCPA consumer rights that must be declared as purpose for sensitive operations.
CCPA_PERMITTED_PURPOSES: frozenset[str] = frozenset({
    "ccpa_service",        # providing the service requested by the consumer
    "ccpa_security",       # security and integrity
    "ccpa_debugging",      # short-term, transient debugging
    "ccpa_first_party",    # internal research / analytics
    "ccpa_legal",          # legal obligation
    "opt_in_consent",      # consumer opted in explicitly
})

# Sensitive personal information (§ 1798.121) — requires opt-in or service purpose.
CCPA_SENSITIVE_CATEGORIES: frozenset[str] = frozenset({
    "national_id",
    "financial_info",
    "health",
    "biometric",
    "geolocation",
})

_STANDARD_OPS = frozenset({"tokenize", "match", "transfer"})


class _CCPATransferRule:
    """Deny sale/transfer of personal information without a permitted purpose."""

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision | None:
        if operation != "transfer":
            return None
        if field_type not in CCPA_PERSONAL_INFO_CATEGORIES:
            return None
        purpose = context.get("purpose")
        if purpose in CCPA_PERMITTED_PURPOSES:
            return PolicyDecision(
                allowed=True,
                policy_id="ccpa-transfer",
                reason=f"CCPA permitted purpose '{purpose}' authorises transfer.",
            )
        return PolicyDecision(
            allowed=False,
            policy_id="ccpa-transfer",
            reason=(
                f"Transfer of personal information requires a CCPA permitted purpose, "
                f"got {purpose!r}."
            ),
        )


class _CCPASensitiveCategoryRule:
    """Require opt_in_consent or ccpa_service purpose for sensitive categories."""

    _ALLOWED = frozenset({"opt_in_consent", "ccpa_service", "ccpa_legal"})

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision | None:
        if field_type not in CCPA_SENSITIVE_CATEGORIES:
            return None
        purpose = context.get("purpose")
        if purpose in self._ALLOWED:
            return PolicyDecision(
                allowed=True,
                policy_id="ccpa-sensitive",
                reason=f"Sensitive category '{field_type}' approved: purpose '{purpose}'.",
            )
        return PolicyDecision(
            allowed=False,
            policy_id="ccpa-sensitive",
            reason=(
                f"Sensitive category '{field_type}' requires opt_in_consent, "
                f"ccpa_service, or ccpa_legal purpose, got {purpose!r}."
            ),
        )


CCPA_DEFAULT_RULESET = RuleSet(
    rules=[
        *(
            FieldRule(
                field_type=cat,
                allowed_operations=_STANDARD_OPS,
                policy_id=f"ccpa-{cat}",
            )
            for cat in CCPA_PERSONAL_INFO_CATEGORIES
        ),
        _CCPASensitiveCategoryRule(),
        _CCPATransferRule(),
    ],
    default_allow=False,
)
