from __future__ import annotations

from tokenvault.protocols.matcher import MatchResult


class NgramSimilarityMatcher:
    algorithm = "ngram"

    def __init__(self, n: int = 2, threshold: float = 0.7) -> None:
        self._n = n
        self._threshold = threshold

    def _ngrams(self, s: str) -> set[str]:
        pad = "$" * (self._n - 1)
        padded = f"{pad}{s}{pad}"
        return {padded[i : i + self._n] for i in range(len(padded) - self._n + 1)}

    def match(self, token_a: str, token_b: str) -> MatchResult:
        set_a = self._ngrams(token_a)
        set_b = self._ngrams(token_b)
        union = set_a | set_b
        score = len(set_a & set_b) / len(union) if union else 1.0
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
