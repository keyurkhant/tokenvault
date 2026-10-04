"""
FileKeyStore — plaintext JSON key file store.

WARNING: Keys are stored in cleartext JSON. This backend requires external
at-rest protection (filesystem permissions, secret manager, volume encryption).
Encrypted-at-rest key storage is not yet implemented; it is planned for v0.2.
Use EnvKeyStore for production deployments where keys come from a secret manager.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from tokenvault.protocols.key_store import MIN_KEY_BYTES, KeyEntropyError


class FileKeyStore:
    """Loads keys from a JSON file.

    File format:
        {
            "current_key_id": "v1",
            "keys": {
                "v1": "<hex-encoded 32+ byte key>"
            }
        }
    """

    def __init__(self, path: str | Path | None = None) -> None:
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
