from __future__ import annotations

import types
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class AuditEvent:
    operation: str
    field_type: str
    algorithm: str
    key_version: str
    policy_id: str
    outcome: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    metadata: types.MappingProxyType[str, object] = field(
        default_factory=lambda: types.MappingProxyType({})
    )

    def __post_init__(self) -> None:
        if isinstance(self.metadata, dict):
            object.__setattr__(
                self, "metadata", types.MappingProxyType(self.metadata)
            )


@runtime_checkable
class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...
