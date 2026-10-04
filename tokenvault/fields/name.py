from __future__ import annotations

import re
import unicodedata


class NameNormalizer:
    _PUNCT = re.compile(r"[^\w\s]", re.UNICODE)
    _MULTI_SPACE = re.compile(r"\s+")

    def normalize(self, value: str) -> str:
        if not value:
            return ""
        value = unicodedata.normalize("NFC", value)
        value = self._PUNCT.sub("", value)
        return self._MULTI_SPACE.sub(" ", value).strip().lower()
