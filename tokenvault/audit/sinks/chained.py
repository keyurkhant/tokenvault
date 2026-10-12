from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from pathlib import Path

from tokenvault.protocols.audit_sink import AuditEvent

# All chains start from this genesis hash.
_GENESIS = b"\x00" * 32


def _record_bytes(record: dict[str, object]) -> bytes:
    """Canonical serialization used for both emit and verify."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


class ChainedFileAuditSink:
    """HMAC-SHA256 chained JSONL audit sink.

    Each entry carries a ``chain_hmac`` field computed as:

        HMAC-SHA256(key, prev_chain_hmac || canonical_record_bytes)

    where ``canonical_record_bytes`` is the JSON-serialised entry *without*
    the ``chain_hmac`` field (sort_keys=True, no extra whitespace).

    The chain starts from a 32-byte genesis value (all zeros). When
    appending to an existing file the last stored ``chain_hmac`` is used
    as the previous value, so the chain survives process restarts.

    Use :func:`verify_audit_log` to verify the full chain later.
    """

    def __init__(self, path: str | Path, key: bytes) -> None:
        self._path = Path(path)
        self._key = key
        self._prev_hmac = self._resume()

    def _resume(self) -> bytes:
        if not self._path.exists():
            return _GENESIS
        for line in reversed(self._path.read_text().splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                raw = record.get("chain_hmac")
                if raw:
                    return bytes.fromhex(raw)
            except (json.JSONDecodeError, ValueError):
                continue
        return _GENESIS

    def emit(self, event: AuditEvent) -> None:
        record: dict[str, object] = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "operation": event.operation,
            "field_type": event.field_type,
            "algorithm": event.algorithm,
            "key_version": event.key_version,
            "policy_id": event.policy_id,
            "outcome": event.outcome,
            "metadata": dict(event.metadata),
        }
        chain_hmac = _hmac.new(
            self._key,
            self._prev_hmac + _record_bytes(record),
            hashlib.sha256,
        ).digest()
        record["chain_hmac"] = chain_hmac.hex()
        with self._path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
        self._prev_hmac = chain_hmac


def verify_audit_log(path: str | Path, key: bytes) -> tuple[bool, int]:
    """Verify the HMAC chain of a log produced by :class:`ChainedFileAuditSink`.

    Returns ``(valid, entries_checked)``. ``valid`` is ``False`` if any entry
    fails its chain check, is missing ``chain_hmac``, or cannot be parsed.
    An empty file is considered valid (0 entries checked).
    """
    prev_hmac = _GENESIS
    count = 0
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, count
        stored = record.pop("chain_hmac", None)
        if stored is None:
            return False, count
        expected = _hmac.new(
            key, prev_hmac + _record_bytes(record), hashlib.sha256
        ).digest()
        if not _hmac.compare_digest(expected.hex(), stored):
            return False, count
        prev_hmac = expected
        count += 1
    return True, count
