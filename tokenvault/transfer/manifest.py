from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class FieldMapping:
    field_name: str
    field_type: str
    algorithm: str
    key_version: str


@dataclass(frozen=True)
class TransferManifest:
    source_region: str
    destination_region: str
    policy_id: str
    consent_reference: str
    field_mappings: list[FieldMapping]
    created_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_region": self.source_region,
            "destination_region": self.destination_region,
            "policy_id": self.policy_id,
            "consent_reference": self.consent_reference,
            "created_at": self.created_at.isoformat(),
            "field_mappings": [
                {
                    "field_name": fm.field_name,
                    "field_type": fm.field_type,
                    "algorithm": fm.algorithm,
                    "key_version": fm.key_version,
                }
                for fm in self.field_mappings
            ],
        }
