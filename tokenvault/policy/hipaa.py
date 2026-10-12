from __future__ import annotations

from typing import Any

from tokenvault.policy.engine import RuleSet
from tokenvault.policy.rules import FieldRule
from tokenvault.protocols.policy_guard import PolicyDecision

# 45 CFR § 164.514(b) — 18 PHI identifiers that must be removed or tokenized
# under the Safe Harbor de-identification standard.
HIPAA_PHI_IDENTIFIERS: frozenset[str] = frozenset({
    "name",
    "geographic_data",       # smaller than state (street, city, zip, county, precinct)
    "date_of_birth",         # except year; all ages > 89 must be suppressed
    "phone",
    "fax",
    "email",
    "ssn",                   # social security number
    "medical_record_number",
    "health_plan_number",
    "account_number",
    "certificate_license_number",
    "vehicle_identifier",    # VIN, license plate
    "device_identifier",     # serial numbers, unique device identifiers
    "url",
    "ip_address",
    "biometric",             # finger and voice prints
    "photo",                 # full-face photographs and comparable images
    "national_id",           # any other unique identifying number or code
})

# Tokenize and match are allowed on PHI; transfer requires an explicit
# purpose of "hipaa_treatment", "hipaa_payment", or "hipaa_operations"
# (the HIPAA TPO purposes).
_HIPAA_TRANSFER_PURPOSES = frozenset({
    "hipaa_treatment",
    "hipaa_payment",
    "hipaa_operations",
})

_ALL_OPS = frozenset({"tokenize", "match", "transfer"})


class _HIPAATransferRule:
    """Allows transfer only when purpose is one of the HIPAA TPO purposes."""

    def evaluate(
        self, field_type: str, operation: str, context: dict[str, Any]
    ) -> PolicyDecision | None:
        if operation != "transfer":
            return None
        if field_type not in HIPAA_PHI_IDENTIFIERS:
            return None
        purpose = context.get("purpose")
        if purpose in _HIPAA_TRANSFER_PURPOSES:
            return PolicyDecision(
                allowed=True,
                policy_id="hipaa-tpo-transfer",
                reason=f"HIPAA TPO purpose '{purpose}' authorises transfer.",
            )
        return PolicyDecision(
            allowed=False,
            policy_id="hipaa-tpo-transfer",
            reason=(
                f"PHI transfer requires a HIPAA TPO purpose "
                f"(treatment/payment/operations), got {purpose!r}."
            ),
        )


HIPAA_SAFE_HARBOR_RULESET = RuleSet(
    rules=[
        # All 18 PHI identifiers: tokenize + match always allowed;
        # transfer is declared here so the FieldRule doesn't deny it —
        # the _HIPAATransferRule below gates it on TPO purpose.
        *(
            FieldRule(
                field_type=phi,
                allowed_operations=_ALL_OPS,
                policy_id=f"hipaa-phi-{phi}",
            )
            for phi in HIPAA_PHI_IDENTIFIERS
        ),
        # Transfer of PHI requires a HIPAA TPO purpose
        _HIPAATransferRule(),
    ],
    default_allow=False,
)
