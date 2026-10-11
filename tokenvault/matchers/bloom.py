from __future__ import annotations

import hashlib
import hmac as _hmac


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
