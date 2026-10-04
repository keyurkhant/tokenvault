from typing import Protocol, runtime_checkable

MIN_KEY_BYTES = 32


class KeyEntropyError(ValueError):
    """Raised when a key does not meet the minimum 256-bit entropy requirement."""


@runtime_checkable
class KeyStore(Protocol):
    def get_key(self, key_id: str) -> bytes: ...
    def get_current_key_id(self) -> str: ...
