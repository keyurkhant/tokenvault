from __future__ import annotations

from tokenvault.policy.engine import RuleSet
from tokenvault.policy.rules import FieldRule, PurposeRule

# All 7 field types as string literals — must NOT import FieldType from fields/base.py
# to preserve the invariant that policy/ does not import from fields/
_ALL_FIELD_TYPES = ["email", "name", "phone", "address", "date_of_birth", "national_id", "custom"]

_STANDARD_OPS = frozenset({"tokenize", "match", "transfer"})

PIPEDA_DEFAULT_RULESET = RuleSet(
    rules=[
        *(
            FieldRule(
                field_type=ft,
                allowed_operations=_STANDARD_OPS,
                policy_id=f"pipeda-{ft}",
            )
            for ft in _ALL_FIELD_TYPES
        ),
        PurposeRule(required_purpose="data_transfer", policy_id="pipeda-purpose"),
    ],
    default_allow=False,
)
