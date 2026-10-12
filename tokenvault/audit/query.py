from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    """Read-only query interface over a JSONL audit log file.

    Supports both plain :class:`~tokenvault.audit.sinks.file.FileAuditSink`
    output and :class:`~tokenvault.audit.sinks.chained.ChainedFileAuditSink`
    output (``chain_hmac`` fields are included in returned records as-is).

    The file is re-read on every :meth:`query` call so results always reflect
    the current state of the file.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def _load(self) -> list[dict[str, object]]:
        events: list[dict[str, object]] = []
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def query(
        self,
        *,
        operation: str | None = None,
        field_type: str | None = None,
        outcome: str | None = None,
        algorithm: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, object]]:
        """Return events matching all supplied filters (AND semantics).

        All parameters are optional; omitting one means "any value".

        *since* / *until* are inclusive and timezone-aware comparisons:
        naive datetimes are treated as UTC.
        """
        results = self._load()
        if operation is not None:
            results = [e for e in results if e.get("operation") == operation]
        if field_type is not None:
            results = [e for e in results if e.get("field_type") == field_type]
        if outcome is not None:
            results = [e for e in results if e.get("outcome") == outcome]
        if algorithm is not None:
            results = [e for e in results if e.get("algorithm") == algorithm]
        if since is not None:
            since_utc = _ensure_utc(since)
            results = [
                e for e in results
                if _ensure_utc(datetime.fromisoformat(str(e["timestamp"]))) >= since_utc
            ]
        if until is not None:
            until_utc = _ensure_utc(until)
            results = [
                e for e in results
                if _ensure_utc(datetime.fromisoformat(str(e["timestamp"]))) <= until_utc
            ]
        return results

    def group_by(self, field: str) -> dict[str, list[dict[str, object]]]:
        """Group all events by the value of *field*.

        Events missing the field are grouped under ``"<unknown>"``.
        """
        groups: dict[str, list[dict[str, object]]] = {}
        for event in self._load():
            key = str(event.get(field, "<unknown>"))
            groups.setdefault(key, []).append(event)
        return groups

    def count_by(self, field: str) -> dict[str, int]:
        """Return a count of events per unique value of *field*."""
        return {k: len(v) for k, v in self.group_by(field).items()}

    def __len__(self) -> int:
        return len(self._load())


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
