from __future__ import annotations

import os

from tokenvault.protocols.key_store import MIN_KEY_BYTES, KeyEntropyError


class EnvKeyStore:
    def __init__(
        self,
        prefix: str = "TOKENVAULT_KEY_",
        current_key_env: str = "TOKENVAULT_CURRENT_KEY_ID",
    ) -> None:
        self._prefix = prefix.upper()
        self._current_key_env = current_key_env

    def get_key(self, key_id: str) -> bytes:
        env_name = self._prefix + key_id.upper().replace("-", "_")
        raw = os.environ.get(env_name)
        if raw is None:
            raise KeyError(f"Environment variable '{env_name}' not set.")
        is_hex = all(c in "0123456789abcdefABCDEF" for c in raw)
        key = bytes.fromhex(raw) if is_hex else raw.encode()
        if len(key) < MIN_KEY_BYTES:
            raise KeyEntropyError(
                f"Key from '{env_name}' is {len(key)} bytes; minimum is {MIN_KEY_BYTES}."
            )
        return key

    def get_current_key_id(self) -> str:
        val = os.environ.get(self._current_key_env)
        if val is None:
            raise KeyError(f"Environment variable '{self._current_key_env}' not set.")
        return val
