import pytest

from tokenvault.tokenizers.uuid_random import UUIDRandomTokenizer


def test_uuid_nondeterministic():
    t = UUIDRandomTokenizer()
    r1 = t.tokenize("same@example.com", "email")
    r2 = t.tokenize("same@example.com", "email")
    assert r1.token != r2.token


def test_uuid_is_not_deterministic():
    t = UUIDRandomTokenizer()
    r = t.tokenize("x", "email")
    assert r.is_deterministic is False


def test_uuid_no_key_version():
    t = UUIDRandomTokenizer()
    r = t.tokenize("x", "email")
    assert r.key_version == "none"


def test_uuid_supports_all_fields():
    t = UUIDRandomTokenizer()
    assert t.supports_field("email") is True
    assert t.supports_field("custom") is True


# Argon2 tests only run if argon2-cffi is installed
argon2 = pytest.importorskip("argon2")


def test_argon2_nondeterministic():
    from tokenvault.tokenizers.argon2_opaque import Argon2OpaqueTokenizer
    t = Argon2OpaqueTokenizer(time_cost=1, memory_cost=8192, parallelism=1)
    r1 = t.tokenize("same@example.com", "email")
    r2 = t.tokenize("same@example.com", "email")
    assert r1.token != r2.token


def test_argon2_verify_correct_value():
    from tokenvault.tokenizers.argon2_opaque import Argon2OpaqueTokenizer
    t = Argon2OpaqueTokenizer(time_cost=1, memory_cost=8192, parallelism=1)
    r = t.tokenize("jane@example.com", "email")
    assert t.verify("jane@example.com", r) is True


def test_argon2_verify_wrong_value():
    from tokenvault.tokenizers.argon2_opaque import Argon2OpaqueTokenizer
    t = Argon2OpaqueTokenizer(time_cost=1, memory_cost=8192, parallelism=1)
    r = t.tokenize("jane@example.com", "email")
    assert t.verify("other@example.com", r) is False
