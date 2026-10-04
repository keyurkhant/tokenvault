from __future__ import annotations

import hmac as _hmac

from tokenvault.protocols.matcher import MatchResult


class ExactTokenMatcher:
    algorithm = "exact"

    def __init__(self, threshold: float = 1.0) -> None:
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        matched = _hmac.compare_digest(token_a.encode(), token_b.encode())
        score = 1.0 if matched else 0.0
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=matched,
        )
