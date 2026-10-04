from __future__ import annotations
import re

_PATTERNS = [
    re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    re.compile(r"\b\+?[\d\s\-(). ]{7,15}\d\b"),
    re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
]
_REDACTED = "[REDACTED]"


class Redactor:
    def redact(self, text: str) -> str:
        for pattern in _PATTERNS:
            text = pattern.sub(_REDACTED, text)
        return text


_default = Redactor()


def redact(text: str) -> str:
    return _default.redact(text)
