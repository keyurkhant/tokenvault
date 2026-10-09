"""
Key store backends backed by files.

FileKeyStore          — plaintext JSON (deprecated; use EncryptedFileKeyStore).
EncryptedFileKeyStore — AES-256-GCM encrypted file; passphrase via env var.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import warnings
from pathlib import Path

from tokenvault.protocols.key_store import MIN_KEY_BYTES, KeyEntropyError

# ──────────────────────────────────────────────────────────────────────────────
# Plaintext store (deprecated)
# ──────────────────────────────────────────────────────────────────────────────

class FileKeyStore:
    """Loads keys from a plaintext JSON file.

    .. deprecated::
        Keys are stored in cleartext. Use :class:`EncryptedFileKeyStore` for
        any environment where the key file could be read by an adversary.

    File format::

        {
            "current_key_id": "v1",
            "keys": {
                "v1": "<hex-encoded 32+ byte key>"
            }
        }
    """

    def __init__(self, path: str | Path | None = None) -> None:
        warnings.warn(
            "FileKeyStore stores keys in cleartext JSON. "
            "Use EncryptedFileKeyStore for production deployments.",
            DeprecationWarning,
            stacklevel=2,
        )
        resolved = path or os.environ.get("TOKENVAULT_KEY_FILE")
        if not resolved:
            raise ValueError("FileKeyStore requires a path or TOKENVAULT_KEY_FILE env var.")
        data = json.loads(Path(resolved).read_text())
        self._current: str = data["current_key_id"]
        self._keys: dict[str, bytes] = {}
        for kid, hex_val in data["keys"].items():
            key = bytes.fromhex(hex_val)
            if len(key) < MIN_KEY_BYTES:
                raise KeyEntropyError(
                    f"Key '{kid}' in file is {len(key)} bytes; minimum is {MIN_KEY_BYTES}."
                )
            self._keys[kid] = key
        if self._current not in self._keys:
            raise ValueError(
                f"current_key_id {self._current!r} not found in loaded keys."
            )

    def get_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(f"Key ID '{key_id}' not found in FileKeyStore.") from None

    def get_current_key_id(self) -> str:
        return self._current

    def list_key_ids(self) -> list[str]:
        return sorted(self._keys.keys())


# ──────────────────────────────────────────────────────────────────────────────
# Encrypted store
# ──────────────────────────────────────────────────────────────────────────────

class EncryptedFileKeyStore:
    """Key store backed by an AES-256-GCM encrypted file.

    The master passphrase is read from an environment variable at load time and
    never stored in memory after key derivation. The derived AES-256 key is held
    only for the duration of the constructor; the decrypted plaintext is
    discarded once keys are parsed.

    Binary file format::

        [4-byte version][16-byte scrypt salt][12-byte GCM nonce][ciphertext+tag]

    The plaintext is the same JSON schema used by :class:`FileKeyStore`.

    Scrypt parameters: N=16384, r=8, p=1, dklen=32.

    Example — create and load::

        EncryptedFileKeyStore.create(
            path="keys.enc",
            keys={"v1": os.urandom(32).hex()},
            current_key_id="v1",
            passphrase_env="TOKENVAULT_MASTER_PASS",
        )
        store = EncryptedFileKeyStore("keys.enc", passphrase_env="TOKENVAULT_MASTER_PASS")
    """

    _VERSION = b"\x00\x00\x00\x01"
    _SALT_LEN = 16
    _NONCE_LEN = 12
    _SCRYPT_N = 16384
    _SCRYPT_R = 8
    _SCRYPT_P = 1
    _KEY_LEN = 32

    def __init__(
        self,
        path: str | Path,
        passphrase_env: str = "TOKENVAULT_MASTER_PASS",
    ) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "EncryptedFileKeyStore requires the 'cryptography' package. "
                "Install with: pip install 'tokenvault[aes-siv]'"
            ) from None

        passphrase = os.environ.get(passphrase_env)
        if not passphrase:
            raise ValueError(
                f"EncryptedFileKeyStore requires env var {passphrase_env!r} to be set."
            )

        raw = Path(path).read_bytes()
        if len(raw) < 4 + self._SALT_LEN + self._NONCE_LEN + 16:
            raise ValueError("File is too short to be a valid EncryptedFileKeyStore file.")
        version = raw[:4]
        if version != self._VERSION:
            raise ValueError(
                f"Unsupported EncryptedFileKeyStore version: {version!r}. "
                f"Expected {self._VERSION!r}."
            )

        offset = 4
        salt = raw[offset : offset + self._SALT_LEN]
        offset += self._SALT_LEN
        nonce = raw[offset : offset + self._NONCE_LEN]
        offset += self._NONCE_LEN
        ciphertext = raw[offset:]

        aes_key = hashlib.scrypt(
            passphrase.encode(),
            salt=salt,
            n=self._SCRYPT_N,
            r=self._SCRYPT_R,
            p=self._SCRYPT_P,
            dklen=self._KEY_LEN,
        )
        try:
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise ValueError(
                "Failed to decrypt key file — wrong passphrase or corrupted file."
            ) from exc

        data: dict[str, object] = json.loads(plaintext)
        self._current: str = str(data["current_key_id"])
        self._keys: dict[str, bytes] = {}
        raw_keys: dict[str, str] = data.get("keys", {})  # type: ignore[assignment]
        for kid, hex_val in raw_keys.items():
            key_bytes = bytes.fromhex(str(hex_val))
            if len(key_bytes) < MIN_KEY_BYTES:
                raise KeyEntropyError(
                    f"Key '{kid}' in encrypted file is {len(key_bytes)} bytes; "
                    f"minimum is {MIN_KEY_BYTES}."
                )
            self._keys[kid] = key_bytes

        if self._current not in self._keys:
            raise ValueError(
                f"current_key_id {self._current!r} not found in decrypted keys."
            )

    def get_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(
                f"Key ID '{key_id}' not found in EncryptedFileKeyStore."
            ) from None

    def get_current_key_id(self) -> str:
        return self._current

    def list_key_ids(self) -> list[str]:
        return sorted(self._keys.keys())

    @classmethod
    def create(
        cls,
        path: str | Path,
        keys: dict[str, str],
        current_key_id: str,
        passphrase_env: str = "TOKENVAULT_MASTER_PASS",
    ) -> None:
        """Encrypt *keys* and write them to *path*.

        Args:
            path: Destination file (will be overwritten).
            keys: Mapping of key-id → hex-encoded key bytes.
            current_key_id: Key ID to mark as current.
            passphrase_env: Name of the env var that holds the master passphrase.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "EncryptedFileKeyStore requires the 'cryptography' package. "
                "Install with: pip install 'tokenvault[aes-siv]'"
            ) from None

        passphrase = os.environ.get(passphrase_env)
        if not passphrase:
            raise ValueError(
                f"EncryptedFileKeyStore.create() requires env var {passphrase_env!r} to be set."
            )

        for kid, hex_val in keys.items():
            key_bytes = bytes.fromhex(hex_val)
            if len(key_bytes) < MIN_KEY_BYTES:
                raise KeyEntropyError(
                    f"Key '{kid}' is {len(key_bytes)} bytes; minimum is {MIN_KEY_BYTES}."
                )

        salt = secrets.token_bytes(cls._SALT_LEN)
        nonce = secrets.token_bytes(cls._NONCE_LEN)
        aes_key = hashlib.scrypt(
            passphrase.encode(),
            salt=salt,
            n=cls._SCRYPT_N,
            r=cls._SCRYPT_R,
            p=cls._SCRYPT_P,
            dklen=cls._KEY_LEN,
        )
        plaintext = json.dumps({"current_key_id": current_key_id, "keys": keys}).encode()
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
        Path(path).write_bytes(cls._VERSION + salt + nonce + ciphertext)
