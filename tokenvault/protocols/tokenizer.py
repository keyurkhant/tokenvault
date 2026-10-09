from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class TokenResult:
    token: str
    field_type: str
    algorithm: str
    key_version: str
    is_deterministic: bool


class TokenizationError(Exception):
    """Raised when a tokenizer or detokenizer encounters an unrecoverable error.

    The original exception cause is suppressed so that internal details
    (ciphertext fragments, key material, cryptographic library messages)
    never reach the caller.  Inspect :attr:`field_type` and
    :attr:`operation` for context.
    """

    def __init__(self, message: str, *, field_type: str, operation: str) -> None:
        super().__init__(message)
        self.field_type = field_type
        self.operation = operation


@runtime_checkable
class Tokenizer(Protocol):
    def tokenize(self, value: str, field_type: str) -> TokenResult: ...
    def supports_field(self, field_type: str) -> bool: ...
