from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tokenvault.audit.query import AuditLog
from tokenvault.audit.sinks.file import FileAuditSink
from tokenvault.protocols.audit_sink import AuditEvent


def _event(**kwargs) -> AuditEvent:
    defaults = dict(
        operation="tokenize",
        field_type="email",
        algorithm="hmac-sha256",
        key_version="v1",
        policy_id="test",
        outcome="success",
    )
    defaults.update(kwargs)
    return AuditEvent(**defaults)


@pytest.fixture()
def log_path(tmp_path) -> Path:
    path = tmp_path / "audit.jsonl"
    sink = FileAuditSink(path)
    sink.emit(_event(operation="tokenize", field_type="email", outcome="success"))
    sink.emit(_event(operation="tokenize", field_type="name", outcome="success"))
    sink.emit(_event(operation="match", field_type="email", outcome="success"))
    sink.emit(_event(operation="tokenize", field_type="email", outcome="denied"))
    sink.emit(_event(operation="detokenize", field_type="email", outcome="denied",
                     algorithm="aes-siv"))
    return path


# --- query filters ---

def test_query_all(log_path):
    log = AuditLog(log_path)
    assert len(log.query()) == 5


def test_query_by_operation(log_path):
    log = AuditLog(log_path)
    results = log.query(operation="tokenize")
    assert len(results) == 3
    assert all(e["operation"] == "tokenize" for e in results)


def test_query_by_field_type(log_path):
    log = AuditLog(log_path)
    results = log.query(field_type="name")
    assert len(results) == 1
    assert results[0]["field_type"] == "name"


def test_query_by_outcome(log_path):
    log = AuditLog(log_path)
    results = log.query(outcome="denied")
    assert len(results) == 2
    assert all(e["outcome"] == "denied" for e in results)


def test_query_by_algorithm(log_path):
    log = AuditLog(log_path)
    results = log.query(algorithm="aes-siv")
    assert len(results) == 1


def test_query_combined_filters(log_path):
    log = AuditLog(log_path)
    results = log.query(operation="tokenize", field_type="email", outcome="success")
    assert len(results) == 1


def test_query_no_match_returns_empty(log_path):
    log = AuditLog(log_path)
    assert log.query(operation="nonexistent") == []


# --- since / until ---

def test_query_since_future_returns_empty(log_path):
    log = AuditLog(log_path)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    assert log.query(since=future) == []


def test_query_until_past_returns_empty(log_path):
    log = AuditLog(log_path)
    past = datetime(2000, 1, 1, tzinfo=timezone.utc)
    assert log.query(until=past) == []


def test_query_since_epoch_returns_all(log_path):
    log = AuditLog(log_path)
    epoch = datetime(2000, 1, 1, tzinfo=timezone.utc)
    assert len(log.query(since=epoch)) == 5


# --- group_by / count_by ---

def test_group_by_operation(log_path):
    log = AuditLog(log_path)
    groups = log.group_by("operation")
    assert set(groups.keys()) == {"tokenize", "match", "detokenize"}
    assert len(groups["tokenize"]) == 3


def test_group_by_unknown_field(log_path):
    log = AuditLog(log_path)
    groups = log.group_by("no_such_field")
    assert "<unknown>" in groups
    assert len(groups["<unknown>"]) == 5


def test_count_by_outcome(log_path):
    log = AuditLog(log_path)
    counts = log.count_by("outcome")
    assert counts["success"] == 3
    assert counts["denied"] == 2


def test_count_by_field_type(log_path):
    log = AuditLog(log_path)
    counts = log.count_by("field_type")
    assert counts["email"] == 4
    assert counts["name"] == 1


# --- len ---

def test_len(log_path):
    assert len(AuditLog(log_path)) == 5


# --- empty file ---

def test_empty_file(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    log = AuditLog(path)
    assert log.query() == []
    assert len(log) == 0


# --- tolerates chain_hmac field ---

def test_works_with_chained_sink(tmp_path):
    import secrets

    from tokenvault.audit.sinks.chained import ChainedFileAuditSink
    path = tmp_path / "chained.jsonl"
    sink = ChainedFileAuditSink(path, secrets.token_bytes(32))
    sink.emit(_event(operation="tokenize", outcome="success"))
    sink.emit(_event(operation="match", outcome="denied"))
    log = AuditLog(path)
    assert len(log.query()) == 2
    assert len(log.query(outcome="denied")) == 1
