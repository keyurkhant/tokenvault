from __future__ import annotations

from tokenvault.protocols.matcher import MatchResult

try:
    import jellyfish as _jf
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class JaroWinklerMatcher:
    algorithm = "jaro-winkler"

    def __init__(self, threshold: float = 0.85) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use JaroWinklerMatcher.")
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        score = float(_jf.jaro_winkler_similarity(token_a, token_b))
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )
