import json
import os
import secrets
import tempfile

import pytest

from tokenvault.keys.direct import DirectKeyStore
from tokenvault.keys.env import EnvKeyStore
from tokenvault.keys.file import FileKeyStore
from tokenvault.protocols.key_store import KeyEntropyError

KEY = secrets.token_bytes(32)


# --- DirectKeyStore ---
def test_direct_returns_key():
    store = DirectKeyStore(keys={"v1": KEY}, current_key_id="v1")
    assert store.get_key("v1") == KEY
    assert store.get_current_key_id() == "v1"

def test_direct_rejects_short_key():
    with pytest.raises(KeyEntropyError):
        DirectKeyStore(keys={"v1": b"tooshort"}, current_key_id="v1")

def test_direct_missing_key():
    store = DirectKeyStore(keys={"v1": KEY}, current_key_id="v1")
    with pytest.raises(KeyError):
        store.get_key("missing")


# --- EnvKeyStore ---
def test_env_reads_key(monkeypatch):
    hex_key = KEY.hex()
    monkeypatch.setenv("TOKENVAULT_KEY_TEST_V1", hex_key)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "test-v1")
    store = EnvKeyStore()
    assert store.get_key("test-v1") == bytes.fromhex(hex_key)
    assert store.get_current_key_id() == "test-v1"

def test_env_missing_var(monkeypatch):
    monkeypatch.delenv("TOKENVAULT_KEY_MISSING", raising=False)
    store = EnvKeyStore()
    with pytest.raises(KeyError):
        store.get_key("missing")


# --- FileKeyStore ---
def test_file_reads_keys():
    data = {
        "current_key_id": "v1",
        "keys": {"v1": KEY.hex()}
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    store = FileKeyStore(path=path)
    assert store.get_key("v1") == KEY
    assert store.get_current_key_id() == "v1"
    os.unlink(path)

def test_file_rejects_short_key():
    data = {"current_key_id": "v1", "keys": {"v1": b"short".hex()}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    with pytest.raises(KeyEntropyError):
        FileKeyStore(path=path)
    os.unlink(path)
