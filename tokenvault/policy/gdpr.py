from __future__ import annotations

from tokenvault.policy.engine import RuleSet
from tokenvault.policy.rules import FieldRule, RegionAdequacyRule, SpecialCategoryRule

# EC adequacy decisions current as of 2024 (Art. 45 GDPR).
# EU/EEA member states are implicitly adequate for intra-EU transfers.
GDPR_ADEQUATE_COUNTRIES: frozenset[str] = frozenset({
    # EU member states
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR",
    "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK",
    "SI", "ES", "SE",
    # EEA non-EU
    "IS", "LI", "NO",
    # EC adequacy decisions
    "AD", "AR", "CA", "FO", "GG", "IL", "IM", "JP", "JE", "NZ", "CH", "UY", "UK",
})

# Art. 9 special categories — require purpose="explicit_consent".
GDPR_SPECIAL_CATEGORIES: frozenset[str] = frozenset({
    "health", "biometric", "genetic",
})

_STANDARD_FIELD_TYPES = [
    "email", "name", "phone", "address", "date_of_birth", "national_id", "custom",
]
_STANDARD_OPS = frozenset({"tokenize", "match", "transfer"})

GDPR_DEFAULT_RULESET = RuleSet(
    rules=[
        # Standard fields — all operations permitted
        *(
            FieldRule(
                field_type=ft,
                allowed_operations=_STANDARD_OPS,
                policy_id=f"gdpr-{ft}",
            )
            for ft in _STANDARD_FIELD_TYPES
        ),
        # Art. 9 — special categories require explicit consent
        SpecialCategoryRule(
            special_field_types=GDPR_SPECIAL_CATEGORIES,
            required_purpose="explicit_consent",
            policy_id="gdpr-art9-special-category",
        ),
        # Art. 45 — transfers only to adequate destinations
        RegionAdequacyRule(
            adequate_regions=GDPR_ADEQUATE_COUNTRIES,
            policy_id="gdpr-art45-adequacy",
        ),
    ],
    default_allow=False,
)
