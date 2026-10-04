from __future__ import annotations

import re
import unicodedata


class AddressNormalizer:
    _MULTI_SPACE = re.compile(r"\s+")

    def normalize(self, value: str) -> str:
        if not value:
            return ""
        value = unicodedata.normalize("NFC", value)
        return self._MULTI_SPACE.sub(" ", value).strip().lower()
