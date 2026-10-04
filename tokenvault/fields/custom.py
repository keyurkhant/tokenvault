from __future__ import annotations

from tokenvault.protocols.normalizer import Normalizer


class PassthroughNormalizer:
    def normalize(self, value: str) -> str:
        return value.strip()


class UserDefinedNormalizer:
    def __init__(self, fn: Normalizer) -> None:
        self._fn = fn

    def normalize(self, value: str) -> str:
        return self._fn.normalize(value)
