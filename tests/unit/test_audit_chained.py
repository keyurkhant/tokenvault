from __future__ import annotations

import json
import secrets

import pytest

from tokenvault.audit.sinks.chained import ChainedFileAuditSink, verify_audit_log
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
def key() -> bytes:
    return secrets.token_bytes(32)


# --- emit ---

def test_emit_writes_jsonl(tmp_path, key):
    sink = ChainedFileAuditSink(tmp_path / "audit.jsonl", key)
    sink.emit(_event())
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["operation"] == "tokenize"
    assert "chain_hmac" in record


def test_emit_multiple_entries(tmp_path, key):
    sink = ChainedFileAuditSink(tmp_path / "audit.jsonl", key)
    for _ in range(5):
        sink.emit(_event())
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 5


def test_each_entry_has_unique_chain_hmac(tmp_path, key):
    sink = ChainedFileAuditSink(tmp_path / "audit.jsonl", key)
    sink.emit(_event(field_type="email"))
    sink.emit(_event(field_type="name"))
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    hmacs = [json.loads(ln)["chain_hmac"] for ln in lines]
    assert hmacs[0] != hmacs[1]


def test_chain_hmac_changes_when_content_differs(tmp_path, key):
    sink_a = ChainedFileAuditSink(tmp_path / "a.jsonl", key)
    sink_b = ChainedFileAuditSink(tmp_path / "b.jsonl", key)
    sink_a.emit(_event(field_type="email"))
    sink_b.emit(_event(field_type="name"))
    h_a = json.loads((tmp_path / "a.jsonl").read_text())["chain_hmac"]
    h_b = json.loads((tmp_path / "b.jsonl").read_text())["chain_hmac"]
    assert h_a != h_b


# --- verify ---

def test_verify_valid_chain(tmp_path, key):
    sink = ChainedFileAuditSink(tmp_path / "audit.jsonl", key)
    for _ in range(10):
        sink.emit(_event())
    valid, count = verify_audit_log(tmp_path / "audit.jsonl", key)
    assert valid is True
    assert count == 10


def test_verify_empty_file(tmp_path, key):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    valid, count = verify_audit_log(path, key)
    assert valid is True
    assert count == 0


def test_verify_wrong_key_fails(tmp_path, key):
    sink = ChainedFileAuditSink(tmp_path / "audit.jsonl", key)
    sink.emit(_event())
    valid, _ = verify_audit_log(tmp_path / "audit.jsonl", secrets.token_bytes(32))
    assert valid is False


def test_verify_tampered_field_fails(tmp_path, key):
    sink = ChainedFileAuditSink(tmp_path / "audit.jsonl", key)
    sink.emit(_event(outcome="success"))
    path = tmp_path / "audit.jsonl"
    data = path.read_text()
    # Tamper with the outcome field
    tampered = data.replace('"success"', '"denied"')
    path.write_text(tampered)
    valid, _ = verify_audit_log(path, key)
    assert valid is False


def test_verify_injected_entry_fails(tmp_path, key):
    sink = ChainedFileAuditSink(tmp_path / "audit.jsonl", key)
    sink.emit(_event())
    path = tmp_path / "audit.jsonl"
    # Inject a fabricated second line without proper chain_hmac
    with path.open("a") as f:
        f.write(json.dumps({"operation": "tokenize", "chain_hmac": "deadbeef" * 8}) + "\n")
    valid, _ = verify_audit_log(path, key)
    assert valid is False


def test_verify_missing_chain_hmac_fails(tmp_path, key):
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps({"operation": "tokenize", "outcome": "success"}) + "\n")
    valid, _ = verify_audit_log(path, key)
    assert valid is False


# --- resume across restarts ---

def test_chain_survives_process_restart(tmp_path, key):
    path = tmp_path / "audit.jsonl"
    # First "process"
    sink1 = ChainedFileAuditSink(path, key)
    sink1.emit(_event(field_type="email"))
    sink1.emit(_event(field_type="name"))
    # Second "process" picks up where the first left off
    sink2 = ChainedFileAuditSink(path, key)
    sink2.emit(_event(field_type="phone"))
    valid, count = verify_audit_log(path, key)
    assert valid is True
    assert count == 3
