import secrets
import pytest
from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer


@pytest.fixture()
def store() -> DirectKeyStore:
    return DirectKeyStore(keys={"v1": secrets.token_bytes(32)}, current_key_id="v1")


def test_hmac_deterministic(store):
    t = HMACTokenizer(key_store=store)
    r1 = t.tokenize("jane@example.com", "email")
    r2 = t.tokenize("jane@example.com", "email")
    assert r1.token == r2.token
    assert r1.is_deterministic is True


def test_hmac_different_values_differ(store):
    t = HMACTokenizer(key_store=store)
    r1 = t.tokenize("jane@example.com", "email")
    r2 = t.tokenize("john@example.com", "email")
    assert r1.token != r2.token


def test_hmac_domain_separation(store):
    t = HMACTokenizer(key_store=store)
    r_email = t.tokenize("jane", "email")
    r_name = t.tokenize("jane", "name")
    assert r_email.token != r_name.token


def test_hmac_token_is_url_safe(store):
    t = HMACTokenizer(key_store=store)
    token = t.tokenize("test@example.com", "email").token
    assert "+" not in token
    assert "/" not in token
    assert "=" not in token


def test_hmac_carries_key_version(store):
    t = HMACTokenizer(key_store=store)
    r = t.tokenize("x", "email")
    assert r.key_version == "v1"


def test_hmac_supports_field_default(store):
    t = HMACTokenizer(key_store=store)
    assert t.supports_field("email") is True
    assert t.supports_field("anything") is True


def test_hmac_supports_field_restricted(store):
    t = HMACTokenizer(key_store=store, allowed_fields=frozenset({"email"}))
    assert t.supports_field("email") is True
    assert t.supports_field("name") is False


def test_hmac_different_keys_differ():
    k1 = secrets.token_bytes(32)
    k2 = secrets.token_bytes(32)
    s1 = DirectKeyStore(keys={"v1": k1}, current_key_id="v1")
    s2 = DirectKeyStore(keys={"v1": k2}, current_key_id="v1")
    r1 = HMACTokenizer(key_store=s1).tokenize("same", "email")
    r2 = HMACTokenizer(key_store=s2).tokenize("same", "email")
    assert r1.token != r2.token
