import secrets

import pytest

from tokenvault.config import VaultConfig
from tokenvault.fields.base import FieldType, PIIField
from tokenvault.fields.email import EmailNormalizer
from tokenvault.fields.name import NameNormalizer
from tokenvault.keys.direct import DirectKeyStore
from tokenvault.matchers.composite import CompositeMatcher, WeightedMatcher
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.matchers.ngram import NgramSimilarityMatcher
from tokenvault.policy.engine import PolicyEngine, RuleSet
from tokenvault.policy.pipeda import PIPEDA_DEFAULT_RULESET
from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.transfer.manifest import FieldMapping, TransferManifest
from tokenvault.transfer.payload import TransferPayload
from tokenvault.vault import PolicyDeniedError, TokenVault


class _CaptureSink:
    def __init__(self): self.events: list[AuditEvent] = []
    def emit(self, e: AuditEvent): self.events.append(e)


@pytest.fixture()
def setup():
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    tokenizer = HMACTokenizer(key_store=store)
    capture = _CaptureSink()
    vault = TokenVault(VaultConfig(
        key_store=store,
        tokenizer=tokenizer,
        matchers={
            "exact": ExactTokenMatcher(),
            "composite": CompositeMatcher([
                WeightedMatcher(ExactTokenMatcher(), 0.4),
                WeightedMatcher(NgramSimilarityMatcher(n=2), 0.6),
            ], threshold=0.5),
        },
        audit_sink=capture,
    ))
    return vault, capture


def test_exact_match_same_value_after_normalization(setup):
    vault, capture = setup
    norm = EmailNormalizer()
    f1 = PIIField("email", FieldType.EMAIL, norm.normalize("Jane@Example.COM"))
    f2 = PIIField("email", FieldType.EMAIL, norm.normalize("jane@example.com"))
    r1 = vault.tokenize(f1)
    r2 = vault.tokenize(f2)
    result = vault.match(r1, r2, algorithm="exact")
    assert result.matched is True


def test_different_values_do_not_match(setup):
    vault, _ = setup
    norm = EmailNormalizer()
    f1 = PIIField("email", FieldType.EMAIL, norm.normalize("jane@example.com"))
    f2 = PIIField("email", FieldType.EMAIL, norm.normalize("john@example.com"))
    r1 = vault.tokenize(f1)
    r2 = vault.tokenize(f2)
    assert vault.match(r1, r2, algorithm="exact").matched is False


def test_audit_trail_no_pii(setup):
    vault, capture = setup
    vault.tokenize(PIIField("email", FieldType.EMAIL, "secret@example.com"))
    for event in capture.events:
        assert "secret@example.com" not in str(event)


def test_cross_field_tokens_never_collide(setup):
    vault, _ = setup
    f_email = PIIField("email", FieldType.EMAIL, "same")
    f_name = PIIField("name", FieldType.NAME, "same")
    r_email = vault.tokenize(f_email)
    r_name = vault.tokenize(f_name)
    assert r_email.token != r_name.token


def test_policy_deny_emits_audit_event():
    from tokenvault.policy.rules import FieldRule
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    capture = _CaptureSink()
    engine = PolicyEngine([RuleSet([FieldRule("email", frozenset(), "deny")], default_allow=False)])
    vault = TokenVault(VaultConfig(
        key_store=store,
        tokenizer=HMACTokenizer(key_store=store),
        policy_guard=engine,
        audit_sink=capture,
    ))
    with pytest.raises(PolicyDeniedError):
        vault.tokenize(PIIField("email", FieldType.EMAIL, "x"))
    assert any(e.outcome == "denied" for e in capture.events)


def test_pipeda_requires_purpose():
    key = secrets.token_bytes(32)
    store = DirectKeyStore(keys={"v1": key}, current_key_id="v1")
    engine = PolicyEngine([PIPEDA_DEFAULT_RULESET])
    vault = TokenVault(VaultConfig(
        key_store=store,
        tokenizer=HMACTokenizer(key_store=store),
        policy_guard=engine,
    ))
    with pytest.raises(PolicyDeniedError):
        vault.tokenize(
            PIIField("email", FieldType.EMAIL, "jane@example.com"),
            context={}  # no purpose
        )
    result = vault.tokenize(
        PIIField("email", FieldType.EMAIL, "jane@example.com"),
        context={"purpose": "data_transfer"},
    )
    assert result.token


def test_transfer_payload_contains_no_raw_pii(setup):
    vault, _ = setup
    norm = EmailNormalizer()
    field = PIIField("email", FieldType.EMAIL, norm.normalize("jane@example.com"))
    token = vault.tokenize(field)
    payload = TransferPayload()
    payload.add_record({"email": token})
    assert "jane@example.com" not in str(payload.to_dict())


def test_full_cross_border_workflow(setup):
    vault, capture = setup
    email_norm = EmailNormalizer()
    name_norm = NameNormalizer()

    record = {
        "email": PIIField("email", FieldType.EMAIL, email_norm.normalize("Jane@Example.COM")),
        "name": PIIField("name", FieldType.NAME, name_norm.normalize("JANE SMITH")),
    }
    tokens = vault.tokenize_record(record, context={"purpose": "data_transfer"})

    payload = TransferPayload()
    payload.add_record(tokens)

    manifest = TransferManifest(
        source_region="CA",
        destination_region="US",
        policy_id="pipeda-default",
        consent_reference="consent-ref-001",
        field_mappings=[
            FieldMapping(
                field_name=k,
                field_type=v.field_type,
                algorithm=v.algorithm,
                key_version=v.key_version,
            )
            for k, v in tokens.items()
        ],
    )
    d = payload.to_dict()
    m = manifest.to_dict()

    assert "jane@example.com" not in str(d)
    assert "jane@example.com" not in str(m)
    assert m["source_region"] == "CA"
    assert len(d["records"]) == 1
    assert len(capture.events) == 2
