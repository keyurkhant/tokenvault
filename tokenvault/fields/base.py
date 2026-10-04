from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FieldType(str, Enum):
    EMAIL = "email"
    NAME = "name"
    PHONE = "phone"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    NATIONAL_ID = "national_id"
    CUSTOM = "custom"


@dataclass(frozen=True)
class PIIField:
    name: str
    field_type: FieldType
    value: str

    def __repr__(self) -> str:
        return (
            f"PIIField(name={self.name!r}, "
            f"field_type={self.field_type!r}, value='[REDACTED]')"
        )
