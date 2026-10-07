from __future__ import annotations

import csv
import json
import os
import secrets
import sys
import tempfile

import pytest

from tokenvault.cli.commands import main


@pytest.fixture()
def env_key(monkeypatch: pytest.MonkeyPatch) -> str:
    key_hex = secrets.token_bytes(32).hex()
    monkeypatch.setenv("TOKENVAULT_KEY_TEST_V1", key_hex)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "test-v1")
    return key_hex


@pytest.fixture()
def config_file() -> Iterator[str]:  # noqa: F821
    data = '[fields]\nemail = "email"\nfull_name = "name"\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
        f.write(data)
    yield f.name
    os.unlink(f.name)


@pytest.fixture()
def input_csv() -> Iterator[str]:  # noqa: F821
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["email", "full_name"])
        writer.writeheader()
        writer.writerow({"email": "jane@example.com", "full_name": "Jane Smith"})
        writer.writerow({"email": "john@example.com", "full_name": "John Doe"})
    yield f.name
    os.unlink(f.name)


# ──────────────────────────────────────────────────────────────────────────────
# tokenize command
# ──────────────────────────────────────────────────────────────────────────────

def test_tokenize_command(env_key: str, config_file: str, input_csv: str) -> None:
    output = tempfile.mktemp(suffix=".csv")
    sys.argv = ["tokenvault", "tokenize",
                "--config", config_file,
                "--input", input_csv,
                "--output", output]
    main()
    rows = list(csv.DictReader(open(output)))
    assert len(rows) == 2
    assert rows[0]["email"] != "jane@example.com"
    assert len(rows[0]["email"]) > 10
    os.unlink(output)


def test_tokenize_manifest_flag(env_key: str, config_file: str, input_csv: str) -> None:
    output = tempfile.mktemp(suffix=".csv")
    manifest_path = output.replace(".csv", "_manifest.json")
    sys.argv = ["tokenvault", "tokenize",
                "--config", config_file,
                "--input", input_csv,
                "--output", output,
                "--manifest"]
    main()
    assert os.path.exists(manifest_path), "manifest sidecar not written"
    manifest = json.loads(open(manifest_path).read())
    assert "field_mappings" in manifest
    assert len(manifest["field_mappings"]) == 2
    fms = {fm["field_name"]: fm for fm in manifest["field_mappings"]}
    assert fms["email"]["field_type"] == "email"
    assert fms["email"]["algorithm"] == "hmac-sha256"
    os.unlink(output)
    os.unlink(manifest_path)


# ──────────────────────────────────────────────────────────────────────────────
# match command
# ──────────────────────────────────────────────────────────────────────────────

def _make_tokens_csv(rows: list[dict[str, str]]) -> str:
    path = tempfile.mktemp(suffix=".csv")
    with open(path, "w", newline="") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    return path


def test_match_exact_identical_tokens() -> None:
    tokens = [
        {"email": "tok_aaa", "name": "tok_bbb"},
        {"email": "tok_ccc", "name": "tok_ddd"},
    ]
    path_a = _make_tokens_csv(tokens)
    path_b = _make_tokens_csv(tokens)
    output = tempfile.mktemp(suffix=".csv")
    sys.argv = [
        "tokenvault", "match",
        "--tokens-a", path_a,
        "--tokens-b", path_b,
        "--algorithm", "exact",
        "--threshold", "1.0",
        "--output", output,
    ]
    main()
    rows = list(csv.DictReader(open(output)))
    matched = [r for r in rows if r["matched"] == "True"]
    # Row 0 in A matches row 0 in B; row 1 in A matches row 1 in B
    assert len(matched) == 2
    assert matched[0]["row_a"] == "0" and matched[0]["row_b"] == "0"
    os.unlink(path_a)
    os.unlink(path_b)
    os.unlink(output)


def test_match_exact_no_matches() -> None:
    path_a = _make_tokens_csv([{"email": "tok_aaa"}])
    path_b = _make_tokens_csv([{"email": "tok_bbb"}])
    output = tempfile.mktemp(suffix=".csv")
    sys.argv = [
        "tokenvault", "match",
        "--tokens-a", path_a,
        "--tokens-b", path_b,
        "--algorithm", "exact",
        "--output", output,
    ]
    main()
    rows = list(csv.DictReader(open(output)))
    assert all(r["matched"] == "False" for r in rows)
    os.unlink(path_a)
    os.unlink(path_b)
    os.unlink(output)


def test_match_specific_fields() -> None:
    path_a = _make_tokens_csv([{"email": "same", "name": "diff_a"}])
    path_b = _make_tokens_csv([{"email": "same", "name": "diff_b"}])
    output = tempfile.mktemp(suffix=".csv")
    # Match only on email → should match (score 1.0)
    sys.argv = [
        "tokenvault", "match",
        "--tokens-a", path_a,
        "--tokens-b", path_b,
        "--algorithm", "exact",
        "--threshold", "1.0",
        "--fields", "email",
        "--output", output,
    ]
    main()
    rows = list(csv.DictReader(open(output)))
    assert rows[0]["matched"] == "True"
    os.unlink(path_a)
    os.unlink(path_b)
    os.unlink(output)


def test_match_outputs_score_column() -> None:
    path_a = _make_tokens_csv([{"email": "tok_xyz"}])
    path_b = _make_tokens_csv([{"email": "tok_xyz"}])
    output = tempfile.mktemp(suffix=".csv")
    sys.argv = [
        "tokenvault", "match",
        "--tokens-a", path_a,
        "--tokens-b", path_b,
        "--algorithm", "exact",
        "--output", output,
    ]
    main()
    rows = list(csv.DictReader(open(output)))
    assert "score" in rows[0]
    assert float(rows[0]["score"]) == 1.0
    os.unlink(path_a)
    os.unlink(path_b)
    os.unlink(output)


# ──────────────────────────────────────────────────────────────────────────────
# audit command
# ──────────────────────────────────────────────────────────────────────────────

def test_audit_command_reads_jsonl(capsys: pytest.CaptureFixture[str]) -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"event_id": "abc", "operation": "tokenize"}) + "\n")
        path = f.name
    sys.argv = ["tokenvault", "audit", "--log", path]
    main()
    out = capsys.readouterr().out
    assert "tokenize" in out
    os.unlink(path)


def test_audit_filter_by_operation(capsys: pytest.CaptureFixture[str]) -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"operation": "tokenize", "outcome": "success"}) + "\n")
        f.write(json.dumps({"operation": "match", "outcome": "success"}) + "\n")
        path = f.name
    sys.argv = ["tokenvault", "audit", "--log", path, "--operation", "tokenize"]
    main()
    out = capsys.readouterr().out
    assert "tokenize" in out
    assert "match" not in out
    os.unlink(path)


def test_audit_filter_by_outcome(capsys: pytest.CaptureFixture[str]) -> None:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps({"operation": "tokenize", "outcome": "denied"}) + "\n")
        f.write(json.dumps({"operation": "tokenize", "outcome": "success"}) + "\n")
        path = f.name
    sys.argv = ["tokenvault", "audit", "--log", path, "--outcome", "denied"]
    main()
    out = capsys.readouterr().out
    assert "denied" in out
    assert "success" not in out
    os.unlink(path)
