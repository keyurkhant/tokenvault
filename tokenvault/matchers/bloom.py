from __future__ import annotations

import hashlib
import hmac as _hmac

from tokenvault.protocols.matcher import MatchResult


def _popcount(data: bytes) -> int:
    return sum(bin(b).count("1") for b in data)


def _ngrams(value: str, sizes: tuple[int, ...]) -> set[str]:
    result: set[str] = set()
    for n in sizes:
        for i in range(len(value) - n + 1):
            result.add(value[i : i + n])
    return result


class BloomFilterEncoder:
    """Encodes a string value into a keyed Bloom filter bit vector for PPRL.

    Uses double-hashing: for each n-gram g, bit positions are derived as
    (h1(g) + i*h2(g)) mod filter_length for i in range(num_hash_functions),
    where h1 and h2 are HMAC-SHA256 under the caller-supplied key.
    """

    def __init__(
        self,
        key: bytes,
        filter_length: int = 1024,
        num_hash_functions: int = 30,
        ngram_sizes: tuple[int, ...] = (2, 3),
    ) -> None:
        if filter_length % 8 != 0:
            raise ValueError("filter_length must be a multiple of 8.")
        if filter_length < 8:
            raise ValueError("filter_length must be at least 8.")
        if num_hash_functions < 1:
            raise ValueError("num_hash_functions must be at least 1.")
        self._key = key
        self._filter_length = filter_length
        self._num_hashes = num_hash_functions
        self._ngram_sizes = ngram_sizes

    @property
    def filter_bytes(self) -> int:
        return self._filter_length // 8

    def encode(self, value: str) -> bytes:
        bits = bytearray(self._filter_length // 8)
        for gram in _ngrams(value, self._ngram_sizes):
            gram_bytes = gram.encode()
            h1 = int.from_bytes(
                _hmac.new(self._key, b"\x00" + gram_bytes, hashlib.sha256).digest()[:4],
                "big",
            )
            h2 = int.from_bytes(
                _hmac.new(self._key, b"\x01" + gram_bytes, hashlib.sha256).digest()[:4],
                "big",
            )
            for i in range(self._num_hashes):
                pos = (h1 + i * h2) % self._filter_length
                bits[pos >> 3] |= 1 << (pos & 7)
        return bytes(bits)


class BloomFilterMatcher:
    """Compares two Bloom filter bit vectors using the Dice coefficient.

    Dice(A, B) = 2 * popcount(A AND B) / (popcount(A) + popcount(B))

    Operates on raw bytes produced by BloomFilterEncoder; use match_encoded
    as the primary interface. The match() adapter accepts base64url-encoded
    vectors for compatibility with string-based pipeline callers.
    """

    algorithm = "bloom-dice"

    def __init__(self, threshold: float = 0.75) -> None:
        self._threshold = threshold

    def match_encoded(self, bf_a: bytes, bf_b: bytes) -> MatchResult:
        if len(bf_a) != len(bf_b):
            raise ValueError(
                f"Bloom filter vectors must be the same length "
                f"({len(bf_a)} vs {len(bf_b)})."
            )
        a_count = _popcount(bf_a)
        b_count = _popcount(bf_b)
        if a_count + b_count == 0:
            return MatchResult(
                score=0.0,
                algorithm=self.algorithm,
                threshold=self._threshold,
                matched=False,
            )
        intersection = _popcount(bytes(a & b for a, b in zip(bf_a, bf_b)))
        score = 2.0 * intersection / (a_count + b_count)
        return MatchResult(
            score=score,
            algorithm=self.algorithm,
            threshold=self._threshold,
            matched=score >= self._threshold,
        )

    def match(self, token_a: str, token_b: str) -> MatchResult:
        """Match base64url-encoded BF vectors (no padding required)."""
        import base64

        bf_a = base64.urlsafe_b64decode(token_a + "==")
        bf_b = base64.urlsafe_b64decode(token_b + "==")
        return self.match_encoded(bf_a, bf_b)
