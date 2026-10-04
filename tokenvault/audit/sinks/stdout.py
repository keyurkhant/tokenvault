from __future__ import annotations
import json

from tokenvault.protocols.audit_sink import AuditEvent


class StdoutAuditSink:
    def emit(self, event: AuditEvent) -> None:
        print(json.dumps({
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "operation": event.operation,
            "field_type": event.field_type,
            "algorithm": event.algorithm,
            "key_version": event.key_version,
            "policy_id": event.policy_id,
            "outcome": event.outcome,
            "metadata": dict(event.metadata),
        }))
