from __future__ import annotations
from tokenvault.protocols.key_store import KeyEntropyError, MIN_KEY_BYTES


class DirectKeyStore:
    def __init__(self, keys: dict[str, bytes], current_key_id: str) -> None:
        for kid, key in keys.items():
            if len(key) < MIN_KEY_BYTES:
                raise KeyEntropyError(
                    f"Key '{kid}' is {len(key)} bytes; minimum is {MIN_KEY_BYTES} (256-bit)."
                )
        self._keys = dict(keys)
        self._current = current_key_id

    def get_key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyError(f"Key ID '{key_id}' not found in DirectKeyStore.") from None

    def get_current_key_id(self) -> str:
        return self._current
