from __future__ import annotations

import re


class PhoneNormalizer:
    _NON_DIGIT = re.compile(r"[^\d]")

    def normalize(self, value: str) -> str:
        if not value:
            return ""
        digits = self._NON_DIGIT.sub("", value)
        return f"+{digits}" if digits else ""
