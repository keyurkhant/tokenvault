from __future__ import annotations
import json
from pathlib import Path

from tokenvault.protocols.audit_sink import AuditEvent


class FileAuditSink:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def emit(self, event: AuditEvent) -> None:
        record = json.dumps({
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "operation": event.operation,
            "field_type": event.field_type,
            "algorithm": event.algorithm,
            "key_version": event.key_version,
            "policy_id": event.policy_id,
            "outcome": event.outcome,
            "metadata": dict(event.metadata),
        })
        with self._path.open("a") as fh:
            fh.write(record + "\n")
