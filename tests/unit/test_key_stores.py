from __future__ import annotations

import json
import os
import secrets
import tempfile

import pytest

from tokenvault.keys.direct import DirectKeyStore
from tokenvault.keys.env import EnvKeyStore
from tokenvault.keys.file import EncryptedFileKeyStore, FileKeyStore
from tokenvault.protocols.key_store import KeyEntropyError

KEY = secrets.token_bytes(32)


# ──────────────────────────────────────────────────────────────────────────────
# DirectKeyStore
# ──────────────────────────────────────────────────────────────────────────────

def test_direct_returns_key() -> None:
    store = DirectKeyStore(keys={"v1": KEY}, current_key_id="v1")
    assert store.get_key("v1") == KEY
    assert store.get_current_key_id() == "v1"


def test_direct_rejects_short_key() -> None:
    with pytest.raises(KeyEntropyError):
        DirectKeyStore(keys={"v1": b"tooshort"}, current_key_id="v1")


def test_direct_missing_key() -> None:
    store = DirectKeyStore(keys={"v1": KEY}, current_key_id="v1")
    with pytest.raises(KeyError):
        store.get_key("missing")


def test_direct_list_key_ids() -> None:
    k2 = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": KEY, "v2": k2}, current_key_id="v1")
    assert store.list_key_ids() == ["v1", "v2"]


# ──────────────────────────────────────────────────────────────────────────────
# EnvKeyStore
# ──────────────────────────────────────────────────────────────────────────────

def test_env_reads_key(monkeypatch: pytest.MonkeyPatch) -> None:
    hex_key = KEY.hex()
    monkeypatch.setenv("TOKENVAULT_KEY_TEST_V1", hex_key)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "test-v1")
    store = EnvKeyStore()
    assert store.get_key("test-v1") == bytes.fromhex(hex_key)
    assert store.get_current_key_id() == "test-v1"


def test_env_missing_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOKENVAULT_KEY_MISSING", raising=False)
    store = EnvKeyStore()
    with pytest.raises(KeyError):
        store.get_key("missing")


def test_env_base64_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    import base64
    b64_key = base64.b64encode(KEY).decode()
    monkeypatch.setenv("TOKENVAULT_KEY_V1", b64_key)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "v1")
    monkeypatch.setenv("TOKENVAULT_KEY_ENCODING", "base64")
    store = EnvKeyStore()
    assert store.get_key("v1") == KEY


def test_env_raw_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_val = "a" * 32  # 32-char ASCII string → 32 bytes
    monkeypatch.setenv("TOKENVAULT_KEY_V1", raw_val)
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "v1")
    monkeypatch.setenv("TOKENVAULT_KEY_ENCODING", "raw")
    store = EnvKeyStore()
    assert store.get_key("v1") == raw_val.encode()


def test_env_unknown_encoding_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKENVAULT_KEY_V1", KEY.hex())
    monkeypatch.setenv("TOKENVAULT_CURRENT_KEY_ID", "v1")
    monkeypatch.setenv("TOKENVAULT_KEY_ENCODING", "utf-16")
    store = EnvKeyStore()
    with pytest.raises(ValueError, match="Unknown key encoding"):
        store.get_key("v1")


def test_env_list_key_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKENVAULT_KEY_V1", KEY.hex())
    monkeypatch.setenv("TOKENVAULT_KEY_V2", KEY.hex())
    store = EnvKeyStore()
    ids = store.list_key_ids()
    assert "v1" in ids
    assert "v2" in ids


# ──────────────────────────────────────────────────────────────────────────────
# FileKeyStore (plaintext, deprecated)
# ──────────────────────────────────────────────────────────────────────────────

def test_file_reads_keys() -> None:
    data = {"current_key_id": "v1", "keys": {"v1": KEY.hex()}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    with pytest.warns(DeprecationWarning, match="cleartext"):
        store = FileKeyStore(path=path)
    assert store.get_key("v1") == KEY
    assert store.get_current_key_id() == "v1"
    os.unlink(path)


def test_file_rejects_short_key() -> None:
    data = {"current_key_id": "v1", "keys": {"v1": b"short".hex()}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    with pytest.warns(DeprecationWarning):
        with pytest.raises(KeyEntropyError):
            FileKeyStore(path=path)
    os.unlink(path)


def test_file_emits_deprecation_warning() -> None:
    data = {"current_key_id": "v1", "keys": {"v1": KEY.hex()}}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name
    with pytest.warns(DeprecationWarning, match="EncryptedFileKeyStore"):
        FileKeyStore(path=path)
    os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# EncryptedFileKeyStore
# ──────────────────────────────────────────────────────────────────────────────

cryptography = pytest.importorskip("cryptography", reason="cryptography not installed")


def _make_enc_store(
    tmp_path: os.PathLike[str],
    monkeypatch: pytest.MonkeyPatch,
    keys: dict[str, bytes] | None = None,
    current: str = "v1",
    passphrase: str = "hunter2",
    passphrase_env: str = "TV_MASTER_PASS",
) -> tuple[str, str]:
    """Create an encrypted key file; return (path, passphrase_env)."""
    if keys is None:
        keys = {"v1": KEY}
    hex_keys = {k: v.hex() for k, v in keys.items()}
    path = str(tmp_path) + "/keys.enc"
    monkeypatch.setenv(passphrase_env, passphrase)
    EncryptedFileKeyStore.create(
        path=path,
        keys=hex_keys,
        current_key_id=current,
        passphrase_env=passphrase_env,
    )
    return path, passphrase_env


def test_encrypted_roundtrip(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, env = _make_enc_store(tmp_path, monkeypatch)
    store = EncryptedFileKeyStore(path, passphrase_env=env)
    assert store.get_key("v1") == KEY
    assert store.get_current_key_id() == "v1"


def test_encrypted_multiple_keys(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    k2 = secrets.token_bytes(32)
    path, env = _make_enc_store(
        tmp_path, monkeypatch,
        keys={"v1": KEY, "v2": k2},
        current="v2",
    )
    store = EncryptedFileKeyStore(path, passphrase_env=env)
    assert store.get_current_key_id() == "v2"
    assert store.get_key("v1") == KEY
    assert store.get_key("v2") == k2


def test_encrypted_wrong_passphrase_raises(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, env = _make_enc_store(tmp_path, monkeypatch)
    monkeypatch.setenv(env, "wrong-passphrase")
    with pytest.raises(ValueError, match="decrypt"):
        EncryptedFileKeyStore(path, passphrase_env=env)


def test_encrypted_missing_passphrase_env_raises(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, env = _make_enc_store(tmp_path, monkeypatch)
    monkeypatch.delenv(env, raising=False)
    with pytest.raises(ValueError, match=env):
        EncryptedFileKeyStore(path, passphrase_env=env)


def test_encrypted_missing_key_id_raises(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    path, env = _make_enc_store(tmp_path, monkeypatch)
    store = EncryptedFileKeyStore(path, passphrase_env=env)
    with pytest.raises(KeyError):
        store.get_key("nonexistent")


def test_encrypted_rejects_short_key(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TV_MASTER_PASS", "hunter2")
    with pytest.raises(KeyEntropyError):
        EncryptedFileKeyStore.create(
            path=str(tmp_path) + "/keys.enc",
            keys={"v1": b"short".hex()},
            current_key_id="v1",
            passphrase_env="TV_MASTER_PASS",
        )


def test_encrypted_corrupted_file_raises(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import pathlib
    path, env = _make_enc_store(tmp_path, monkeypatch)
    # Flip a byte in the ciphertext region
    data = bytearray(pathlib.Path(path).read_bytes())
    data[-1] ^= 0xFF
    pathlib.Path(path).write_bytes(bytes(data))
    with pytest.raises(ValueError, match="decrypt"):
        EncryptedFileKeyStore(path, passphrase_env=env)


def test_encrypted_create_requires_passphrase_env(
    tmp_path: os.PathLike[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TV_MASTER_PASS", raising=False)
    with pytest.raises(ValueError, match="TV_MASTER_PASS"):
        EncryptedFileKeyStore.create(
            path=str(tmp_path) + "/keys.enc",
            keys={"v1": KEY.hex()},
            current_key_id="v1",
            passphrase_env="TV_MASTER_PASS",
        )
