from __future__ import annotations

import secrets

import pytest

from tokenvault.matchers.bloom import BloomFilterEncoder, BloomFilterMatcher, _popcount
from tokenvault.matchers.clk import CLKEncoder


@pytest.fixture()
def key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture()
def clk(key: bytes) -> CLKEncoder:
    return CLKEncoder(key=key, filter_length=512, num_hash_functions=20)


# --- Single-field encode ---

def test_clk_encode_deterministic(clk):
    assert clk.encode("jane@example.com") == clk.encode("jane@example.com")


def test_clk_encode_matches_underlying_bloom(key):
    clk = CLKEncoder(key=key, filter_length=256, num_hash_functions=10)
    bf_enc = BloomFilterEncoder(key=key, filter_length=256, num_hash_functions=10)
    assert clk.encode("hello") == bf_enc.encode("hello")


def test_clk_encode_output_length(clk):
    result = clk.encode("test value")
    assert len(result) == clk.filter_bytes


def test_clk_different_keys_produce_different_vectors():
    key_a = secrets.token_bytes(32)
    key_b = secrets.token_bytes(32)
    clk_a = CLKEncoder(key=key_a, filter_length=256)
    clk_b = CLKEncoder(key=key_b, filter_length=256)
    assert clk_a.encode("john smith") != clk_b.encode("john smith")


# --- encode_record ---

def test_encode_record_empty_returns_zero_vector(clk):
    result = clk.encode_record({})
    assert result == bytes(clk.filter_bytes)


def test_encode_record_single_field_matches_encode(clk):
    assert clk.encode_record({"name": "alice"}) == clk.encode("alice")


def test_encode_record_ors_fields(clk):
    bf_name = clk.encode("alice")
    bf_email = clk.encode("alice@example.com")
    expected = bytes(a | b for a, b in zip(bf_name, bf_email))
    result = clk.encode_record({"name": "alice", "email": "alice@example.com"})
    assert result == expected


def test_encode_record_more_bits_than_single_field(clk):
    single = clk.encode("alice")
    combined = clk.encode_record({"name": "alice", "email": "alice@example.com"})
    assert _popcount(combined) >= _popcount(single)


def test_encode_record_output_length(clk):
    result = clk.encode_record({"name": "alice", "dob": "1990-01-01", "email": "a@b.com"})
    assert len(result) == clk.filter_bytes


# --- Cross-party comparison semantics ---

def test_same_key_cross_party_scores_high():
    # Two parties using the same key → same record → Dice ≈ 1.0
    shared_key = secrets.token_bytes(32)
    party_a = CLKEncoder(key=shared_key, filter_length=512, num_hash_functions=20)
    party_b = CLKEncoder(key=shared_key, filter_length=512, num_hash_functions=20)
    matcher = BloomFilterMatcher(threshold=0.75)

    record = {"name": "john smith", "dob": "1985-03-15"}
    result = matcher.match_encoded(
        party_a.encode_record(record),
        party_b.encode_record(record),
    )
    assert result.score == pytest.approx(1.0)
    assert result.matched is True


def test_different_key_cross_party_scores_low():
    # Different keys → same record → Dice is not meaningful (low overlap)
    party_a = CLKEncoder(key=secrets.token_bytes(32), filter_length=2048, num_hash_functions=20)
    party_b = CLKEncoder(key=secrets.token_bytes(32), filter_length=2048, num_hash_functions=20)
    matcher = BloomFilterMatcher(threshold=0.75)

    record = {"name": "john smith", "dob": "1985-03-15"}
    result = matcher.match_encoded(
        party_a.encode_record(record),
        party_b.encode_record(record),
    )
    # Without shared key the bit positions are incomparable
    assert result.matched is False
