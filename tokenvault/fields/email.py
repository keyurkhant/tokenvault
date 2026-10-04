from __future__ import annotations

import re


class EmailNormalizer:
    _WHITESPACE = re.compile(r"\s+")

    def normalize(self, value: str) -> str:
        if not value:
            return ""
        value = self._WHITESPACE.sub("", value).lower()
        local, sep, domain = value.partition("@")
        if not sep:
            return value
        local = local.split("+")[0]
        return f"{local}@{domain}"
