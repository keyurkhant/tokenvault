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

    @classmethod
    def from_tokenize_run(
        cls,
        field_map: dict[str, str],
        results: dict[str, Any],
        source_region: str = "unknown",
        destination_region: str = "unknown",
        policy_id: str = "none",
        consent_reference: str = "",
    ) -> TransferManifest:
        """Build a manifest from the outputs of a single tokenize pass.

        Args:
            field_map: Mapping of column name → field type string.
            results: Mapping of column name → :class:`~tokenvault.protocols.tokenizer.TokenResult`.
                     Columns not present in *results* are skipped.
            source_region: Origin region tag (e.g. ``"CA"``).
            destination_region: Destination region tag.
            policy_id: Policy identifier recorded in the manifest.
            consent_reference: Consent document reference.
        """
        from tokenvault.protocols.tokenizer import TokenResult

        mappings = [
            FieldMapping(
                field_name=col,
                field_type=field_map.get(col, "custom"),
                algorithm=result.algorithm,
                key_version=result.key_version,
            )
            for col, result in results.items()
            if isinstance(result, TokenResult)
        ]
        return cls(
            source_region=source_region,
            destination_region=destination_region,
            policy_id=policy_id,
            consent_reference=consent_reference,
            field_mappings=mappings,
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
