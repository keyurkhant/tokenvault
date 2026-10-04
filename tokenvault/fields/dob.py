from __future__ import annotations

import re


class DateOfBirthNormalizer:
    def normalize(self, value: str) -> str:
        if not value:
            return ""
        stripped = value.strip()
        # Try YYYY-MM-DD
        m = re.match(r'^(\d{4})-(\d{1,2})-(\d{1,2})$', stripped)
        if m:
            y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1800 <= y <= 2200 and 1 <= mo <= 12 and 1 <= d <= 31:
                return f"{y:04d}-{mo:02d}-{d:02d}"
        # Try DD/MM/YYYY
        m = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{4})$', stripped)
        if m:
            d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if 1800 <= y <= 2200 and 1 <= mo <= 12 and 1 <= d <= 31:
                return f"{y:04d}-{mo:02d}-{d:02d}"
        # Invalid input: return as-is (do not produce garbage)
        return stripped
