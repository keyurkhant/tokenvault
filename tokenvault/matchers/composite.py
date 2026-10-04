from __future__ import annotations

from dataclasses import dataclass

from tokenvault.protocols.matcher import Matcher, MatchResult


@dataclass
class WeightedMatcher:
    matcher: Matcher
    weight: float


class CompositeMatcher:
    algorithm = "composite"

    def __init__(
        self,
        matchers: list[WeightedMatcher],
        threshold: float = 0.80,
    ) -> None:
        total = sum(wm.weight for wm in matchers)
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Weights must sum to 1.0, got {total:.6f}.")
        self._matchers = matchers
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        score = sum(
            wm.matcher.match(token_a, token_b).score * wm.weight
            for wm in self._matchers
        )
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
