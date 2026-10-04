from __future__ import annotations

import re


class NationalIDNormalizer:
    _NON_ALNUM = re.compile(r"[^a-zA-Z0-9]")

    def normalize(self, value: str) -> str:
        return self._NON_ALNUM.sub("", value).upper()
