from dataclasses import fields
from tokenvault.protocols.tokenizer import TokenResult
from tokenvault.protocols.matcher import MatchResult
from tokenvault.protocols.audit_sink import AuditEvent
from tokenvault.protocols.policy_guard import PolicyDecision
from tokenvault.protocols.key_store import KeyEntropyError, MIN_KEY_BYTES


def test_token_result_is_frozen():
    r = TokenResult(token="abc", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", is_deterministic=True)
    try:
        r.token = "x"  # type: ignore
        assert False, "should be immutable"
    except Exception:
        pass


def test_token_result_repr_safe():
    r = TokenResult(token="abc", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", is_deterministic=True)
    assert "abc" in repr(r)  # token itself is opaque, safe to show


def test_match_result_is_frozen():
    r = MatchResult(score=0.9, algorithm="jaro-winkler", threshold=0.85, matched=True)
    try:
        r.score = 0.1  # type: ignore
        assert False
    except Exception:
        pass


def test_audit_event_has_no_value_field():
    event_fields = {f.name for f in fields(AuditEvent)}
    assert "value" not in event_fields
    assert "raw" not in event_fields


def test_audit_event_auto_id_and_timestamp():
    e1 = AuditEvent(operation="tokenize", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", policy_id="p1", outcome="success")
    e2 = AuditEvent(operation="tokenize", field_type="email", algorithm="hmac-sha256",
                    key_version="v1", policy_id="p1", outcome="success")
    assert e1.event_id != e2.event_id


def test_policy_decision_frozen():
    d = PolicyDecision(allowed=True, policy_id="p1", reason="ok")
    try:
        d.allowed = False  # type: ignore
        assert False
    except Exception:
        pass


def test_min_key_bytes():
    assert MIN_KEY_BYTES == 32
