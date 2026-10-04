from __future__ import annotations

from tokenvault.protocols.matcher import MatchResult

try:
    import jellyfish as _jf
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class LevenshteinMatcher:
    algorithm = "levenshtein"

    def __init__(self, threshold: float = 0.80, max_distance: int | None = None) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use LevenshteinMatcher.")
        self._threshold = threshold
        self._max_distance = max_distance

    def match(self, token_a: str, token_b: str) -> MatchResult:
        dist = _jf.levenshtein_distance(token_a, token_b)
        max_len = max(len(token_a), len(token_b), 1)
        score = 1.0 - (dist / max_len)
        if self._max_distance is not None and dist > self._max_distance:
            score = 0.0
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
