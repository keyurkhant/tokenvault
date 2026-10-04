import secrets

import pytest

cryptography = pytest.importorskip("cryptography")

from tokenvault.keys.direct import DirectKeyStore  # noqa: E402
from tokenvault.tokenizers.aes_siv import AESSIVTokenizer  # noqa: E402


@pytest.fixture()
def store():
    # AES-SIV-256 needs a 64-byte key (two 256-bit keys internally)
    return DirectKeyStore(keys={"v1": secrets.token_bytes(64)}, current_key_id="v1")


def test_aes_siv_deterministic(store):
    t = AESSIVTokenizer(key_store=store)
    r1 = t.tokenize("jane@example.com", "email")
    r2 = t.tokenize("jane@example.com", "email")
    assert r1.token == r2.token


def test_aes_siv_roundtrip(store):
    t = AESSIVTokenizer(key_store=store)
    original = "jane@example.com"
    result = t.tokenize(original, "email")
    recovered = t._detokenize(result)
    assert recovered == original


def test_aes_siv_domain_separation(store):
    t = AESSIVTokenizer(key_store=store)
    r_email = t.tokenize("jane", "email")
    r_name = t.tokenize("jane", "name")
    assert r_email.token != r_name.token


def test_aes_siv_is_deterministic_flag(store):
    t = AESSIVTokenizer(key_store=store)
    r = t.tokenize("x", "email")
    assert r.is_deterministic is True
    assert r.algorithm == "aes-siv"
