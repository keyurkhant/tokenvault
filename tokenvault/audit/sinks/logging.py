from __future__ import annotations
import logging

from tokenvault.protocols.audit_sink import AuditEvent

_logger = logging.getLogger("tokenvault.audit")


class PythonLoggingAuditSink:
    def emit(self, event: AuditEvent) -> None:
        _logger.info(
            "event_id=%s operation=%s field_type=%s algorithm=%s "
            "key_version=%s policy_id=%s outcome=%s timestamp=%s",
            event.event_id,
            event.operation,
            event.field_type,
            event.algorithm,
            event.key_version,
            event.policy_id,
            event.outcome,
            event.timestamp.isoformat(),
        )
