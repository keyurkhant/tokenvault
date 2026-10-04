from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tokenvault.protocols.tokenizer import TokenResult


@dataclass
class TransferPayload:
    records: list[dict[str, str]] = field(default_factory=list)

    def add_record(self, tokenized: dict[str, TokenResult]) -> None:
        self.records.append({k: v.token for k, v in tokenized.items()})

    def to_dict(self) -> dict[str, Any]:
        return {"records": self.records}
