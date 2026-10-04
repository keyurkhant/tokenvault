from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class MatchResult:
    score: float
    algorithm: str
    threshold: float
    matched: bool


@runtime_checkable
class Matcher(Protocol):
    def match(self, token_a: str, token_b: str) -> MatchResult: ...
