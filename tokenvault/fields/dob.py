from __future__ import annotations

import re


class DateOfBirthNormalizer:
    _SEP = re.compile(r"[-/.]")

    def normalize(self, value: str) -> str:
        parts = self._SEP.split(value.strip())
        if len(parts) != 3:
            return value.strip()
        if len(parts[0]) == 4:
            y, m, d = parts[0], parts[1], parts[2]
        else:
            d, m, y = parts[0], parts[1], parts[2]
        return f"{y}-{m.zfill(2)}-{d.zfill(2)}"
