from __future__ import annotations

from tokenvault.matchers.bloom import BloomFilterEncoder


class CLKEncoder:
    """Cryptographic Linkage Key (CLK) encoder for multi-party PPRL.

    Each party uses a private key to encode their records independently.
    The resulting bit vectors can be compared via Dice coefficient without
    either party revealing their key or raw field values to a comparison
    service.

    For cross-party comparison to produce meaningful scores, both parties
    must use the same key (a shared secret). The CLK pattern is that this
    shared key is kept from the neutral comparison service, not from each
    other.

    encode_record() encodes multiple fields and OR-combines the resulting
    bit vectors into a single record-level vector.
    """

    def __init__(
        self,
        key: bytes,
        filter_length: int = 1024,
        num_hash_functions: int = 30,
        ngram_sizes: tuple[int, ...] = (2, 3),
    ) -> None:
        self._encoder = BloomFilterEncoder(
            key=key,
            filter_length=filter_length,
            num_hash_functions=num_hash_functions,
            ngram_sizes=ngram_sizes,
        )

    @property
    def filter_bytes(self) -> int:
        return self._encoder.filter_bytes

    def encode(self, value: str) -> bytes:
        return self._encoder.encode(value)

    def encode_record(self, fields: dict[str, str]) -> bytes:
        """OR-combine per-field Bloom filters into a single record vector."""
        combined = bytearray(self._encoder.filter_bytes)
        for value in fields.values():
            for i, b in enumerate(self._encoder.encode(value)):
                combined[i] |= b
        return bytes(combined)
