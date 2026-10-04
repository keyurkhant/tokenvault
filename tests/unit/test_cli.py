import csv
import json
import os
import secrets
import sys
import tempfile

import pytest

from tokenvault.cli.commands import main


@pytest.fixture()
def env_key(monkeypatch):
    key_hex = secrets.token_bytes(32).hex()
    monkeypatch.setenv("TOKENVAULT_KEY_TEST_V1", key_hex)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "test-v1")
    return key_hex


@pytest.fixture()
def config_file():
    data = '[fields]\nemail = "email"\nfull_name = "name"\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(data)
    yield f.name
    os.unlink(f.name)


@pytest.fixture()
def input_csv():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["email", "full_name"])
        writer.writeheader()
        writer.writerow({"email": "jane@example.com", "full_name": "Jane Smith"})
    yield f.name
    os.unlink(f.name)


def test_tokenize_command(env_key, config_file, input_csv):
    output = tempfile.mktemp(suffix=".csv")
    sys.argv = ["tokenvault", "tokenize",
                "--config", config_file,
                "--input", input_csv,
                "--output", output]
    main()
    rows = list(csv.DictReader(open(output)))
    assert len(rows) == 1
    assert rows[0]["email"] != "jane@example.com"
    assert len(rows[0]["email"]) > 10
    os.unlink(output)


def test_audit_command_reads_jsonl(capsys):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"event_id": "abc", "operation": "tokenize"}) + "\n")
        path = f.name
    sys.argv = ["tokenvault", "audit", "--log", path]
    main()
    out = capsys.readouterr().out
    assert "tokenize" in out
    os.unlink(path)
