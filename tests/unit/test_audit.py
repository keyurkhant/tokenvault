import json
import logging
import tempfile
import os
import pytest

from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.audit.redactor import Redactor, redact
from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
from tokenvault.audit.sinks.stdout import StdoutAuditSink
from tokenvault.audit.sinks.file import FileAuditSink


def _make_event(**kwargs) -> AuditEvent:
    defaults = dict(
        operation="tokenize", field_type="email", algorithm="hmac-sha256",
        key_version="v1", policy_id="test", outcome="success",
    )
    return AuditEvent(**{**defaults, **kwargs})


# --- Redactor ---
def test_redactor_masks_email():
    r = Redactor()
    assert "jane@example.com" not in r.redact("user jane@example.com logged in")
    assert "[REDACTED]" in r.redact("user jane@example.com logged in")


def test_redactor_leaves_safe_text():
    r = Redactor()
    assert r.redact("hello world") == "hello world"


def test_module_level_redact():
    result = redact("contact jane@example.com for info")
    assert "[REDACTED]" in result


# --- PythonLoggingAuditSink ---
def test_logging_sink_emits(caplog):
    sink = PythonLoggingAuditSink()
    event = _make_event()
    with caplog.at_level(logging.INFO, logger="tokenvault.audit"):
        sink.emit(event)
    assert event.event_id in caplog.text
    assert "tokenize" in caplog.text


def test_logging_sink_no_raw_value(caplog):
    sink = PythonLoggingAuditSink()
    event = _make_event()
    with caplog.at_level(logging.INFO, logger="tokenvault.audit"):
        sink.emit(event)
    assert "jane@example.com" not in caplog.text


# --- FileAuditSink ---
def test_file_sink_writes_jsonl():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as f:
        path = f.name
    sink = FileAuditSink(path=path)
    sink.emit(_make_event())
    sink.emit(_make_event(operation="match"))
    lines = open(path).readlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["operation"] == "tokenize"
    os.unlink(path)


def test_file_sink_appends():
    with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as f:
        path = f.name
    sink = FileAuditSink(path=path)
    for _ in range(5):
        sink.emit(_make_event())
    assert len(open(path).readlines()) == 5
    os.unlink(path)


# --- StdoutAuditSink ---
def test_stdout_sink_emits(capsys):
    sink = StdoutAuditSink()
    sink.emit(_make_event())
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["operation"] == "tokenize"
    assert "value" not in data
