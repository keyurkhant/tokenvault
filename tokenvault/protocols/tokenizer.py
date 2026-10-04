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


@runtime_checkable
class Tokenizer(Protocol):
    def tokenize(self, value: str, field_type: str) -> TokenResult: ...
    def supports_field(self, field_type: str) -> bool: ...
