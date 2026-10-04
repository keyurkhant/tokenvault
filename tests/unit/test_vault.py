import secrets
import pytest

from tokenvault.fields.base import FieldType, PIIField
from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.config import VaultConfig
from tokenvault.vault import TokenVault, PolicyDeniedError
from tokenvault.protocols.audit_sink import AuditEvent


class _CaptureSink:
    def __init__(self):
        self.events: list[AuditEvent] = []
    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


@pytest.fixture()
def capture():
    return _CaptureSink()


@pytest.fixture()
def vault(capture):
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    tokenizer = HMACTokenizer(key_store=store)
    return TokenVault(VaultConfig(
        key_store=store,
        tokenizer=tokenizer,
        matchers={"exact": ExactTokenMatcher()},
        audit_sink=capture,
    )), capture


def test_tokenize_returns_token_result(vault):
    tv, _ = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    result = tv.tokenize(field)
    assert result.token
    assert result.field_type == "email"


def test_tokenize_emits_audit_event(vault):
    tv, capture = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    tv.tokenize(field)
    assert len(capture.events) == 1
    assert capture.events[0].operation == "tokenize"
    assert capture.events[0].outcome == "success"


def test_audit_event_never_contains_raw_value(vault):
    tv, capture = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="sensitive@secret.com")
    tv.tokenize(field)
    for event in capture.events:
        assert "sensitive@secret.com" not in str(event)


def test_match_same_token(vault):
    tv, _ = vault
    field = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    r1 = tv.tokenize(field)
    r2 = tv.tokenize(field)
    match = tv.match(r1, r2, algorithm="exact")
    assert match.matched is True


def test_match_different_tokens(vault):
    tv, _ = vault
    f1 = PIIField(name="email", field_type=FieldType.EMAIL, value="jane@example.com")
    f2 = PIIField(name="email", field_type=FieldType.EMAIL, value="john@example.com")
    r1 = tv.tokenize(f1)
    r2 = tv.tokenize(f2)
    match = tv.match(r1, r2, algorithm="exact")
    assert match.matched is False


def test_tokenize_record(vault):
    tv, _ = vault
    record = {
        "email": PIIField("email", FieldType.EMAIL, "jane@example.com"),
        "name": PIIField("name", FieldType.NAME, "Jane Smith"),
    }
    results = tv.tokenize_record(record)
    assert set(results.keys()) == {"email", "name"}


def test_policy_denied_emits_audit_event():
    from tokenvault.policy.engine import PolicyEngine, RuleSet
    from tokenvault.policy.rules import FieldRule

    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    tokenizer = HMACTokenizer(key_store=store)
    capture = _CaptureSink()
    deny_engine = PolicyEngine([
        RuleSet(rules=[FieldRule("email", frozenset(), "deny-all")], default_allow=False)
    ])
    tv = TokenVault(VaultConfig(
        key_store=store, tokenizer=tokenizer,
        policy_guard=deny_engine, audit_sink=capture,
    ))
    field = PIIField("email", FieldType.EMAIL, "jane@example.com")
    with pytest.raises(PolicyDeniedError):
        tv.tokenize(field)
    denied = [e for e in capture.events if e.outcome == "denied"]
    assert len(denied) == 1
