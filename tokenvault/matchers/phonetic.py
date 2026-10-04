from __future__ import annotations

import hmac as _hmac

from tokenvault.protocols.matcher import MatchResult

try:
    import jellyfish as _jf
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class SoundexMatcher:
    algorithm = "soundex"

    def __init__(self, threshold: float = 1.0) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use SoundexMatcher.")
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        code_a = _jf.soundex(token_a)
        code_b = _jf.soundex(token_b)
        matched = _hmac.compare_digest(code_a.encode(), code_b.encode())
        return MatchResult(
            score=1.0 if matched else 0.0,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=matched,
        )


class MetaphoneMatcher:
    algorithm = "metaphone"

    def __init__(self, threshold: float = 1.0) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[fuzzy] to use MetaphoneMatcher.")
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        code_a = _jf.metaphone(token_a)
        code_b = _jf.metaphone(token_b)
        matched = _hmac.compare_digest(code_a.encode(), code_b.encode())
        return MatchResult(
            score=1.0 if matched else 0.0,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=matched,
        )
