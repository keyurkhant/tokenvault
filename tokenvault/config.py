from __future__ import annotations

from dataclasses import dataclass, field

from tokenvault.fields.address import AddressNormalizer
from tokenvault.fields.base import FieldType
from tokenvault.fields.custom import PassthroughNormalizer
from tokenvault.fields.dob import DateOfBirthNormalizer
from tokenvault.fields.email import EmailNormalizer
from tokenvault.fields.name import NameNormalizer
from tokenvault.fields.national_id import NationalIDNormalizer
from tokenvault.fields.phone import PhoneNormalizer
from tokenvault.protocols.audit_sink import AuditSink
from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.matcher import Matcher
from tokenvault.protocols.normalizer import Normalizer
from tokenvault.protocols.policy_guard import PolicyGuard
from tokenvault.protocols.tokenizer import Tokenizer


def _default_normalizers() -> dict[FieldType, Normalizer]:
    return {
        FieldType.EMAIL: EmailNormalizer(),
        FieldType.NAME: NameNormalizer(),
        FieldType.PHONE: PhoneNormalizer(),
        FieldType.DATE_OF_BIRTH: DateOfBirthNormalizer(),
        FieldType.ADDRESS: AddressNormalizer(),
        FieldType.NATIONAL_ID: NationalIDNormalizer(),
        FieldType.CUSTOM: PassthroughNormalizer(),
    }


@dataclass
class VaultConfig:
    key_store: KeyStore
    tokenizer: Tokenizer
    matchers: dict[str, Matcher] = field(default_factory=dict)
    policy_guard: PolicyGuard | None = None
    audit_sink: AuditSink | None = None
    consent_reference: str = ""
    region: str = "CA"
    normalizers: dict[FieldType, Normalizer] = field(default_factory=_default_normalizers)
