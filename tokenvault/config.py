from __future__ import annotations
from dataclasses import dataclass, field

from tokenvault.protocols.audit_sink import AuditSink
from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.matcher import Matcher
from tokenvault.protocols.policy_guard import PolicyGuard
from tokenvault.protocols.tokenizer import Tokenizer


@dataclass
class VaultConfig:
    key_store: KeyStore
    tokenizer: Tokenizer
    matchers: dict[str, Matcher] = field(default_factory=dict)
    policy_guard: PolicyGuard | None = None
    audit_sink: AuditSink | None = None
    consent_reference: str = ""
    region: str = "CA"
