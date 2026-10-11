from __future__ import annotations

import secrets

import pytest

from tokenvault.matchers.bloom import BloomFilterEncoder, _ngrams, _popcount


@pytest.fixture()
def key() -> bytes:
    return secrets.token_bytes(32)


# --- _ngrams helper ---

def test_ngrams_bigrams():
    result = _ngrams("abc", (2,))
    assert result == {"ab", "bc"}


def test_ngrams_trigrams():
    result = _ngrams("abcd", (3,))
    assert result == {"abc", "bcd"}


def test_ngrams_empty_string():
    assert _ngrams("", (2, 3)) == set()


def test_ngrams_too_short():
    assert _ngrams("a", (2,)) == set()


# --- _popcount helper ---

def test_popcount_zero():
    assert _popcount(b"\x00\x00") == 0


def test_popcount_all_ones():
    assert _popcount(b"\xff") == 8


def test_popcount_mixed():
    assert _popcount(b"\x0f") == 4


# --- BloomFilterEncoder ---

def test_encoder_output_length_default(key):
    enc = BloomFilterEncoder(key=key)
    result = enc.encode("hello")
    assert len(result) == 1024 // 8  # 128 bytes


def test_encoder_output_length_custom(key):
    enc = BloomFilterEncoder(key=key, filter_length=256)
    result = enc.encode("hello")
    assert len(result) == 256 // 8  # 32 bytes


def test_encoder_deterministic(key):
    enc = BloomFilterEncoder(key=key)
    assert enc.encode("jane@example.com") == enc.encode("jane@example.com")


def test_encoder_different_values_differ(key):
    enc = BloomFilterEncoder(key=key)
    assert enc.encode("alice") != enc.encode("bob")


def test_encoder_different_keys_differ():
    enc_a = BloomFilterEncoder(key=secrets.token_bytes(32))
    enc_b = BloomFilterEncoder(key=secrets.token_bytes(32))
    assert enc_a.encode("john smith") != enc_b.encode("john smith")


def test_encoder_empty_string_returns_zero_vector(key):
    enc = BloomFilterEncoder(key=key)
    result = enc.encode("")
    assert result == bytes(enc.filter_bytes)


def test_encoder_filter_length_not_multiple_of_8():
    with pytest.raises(ValueError, match="multiple of 8"):
        BloomFilterEncoder(key=b"k" * 32, filter_length=100)


def test_encoder_filter_length_too_small():
    with pytest.raises(ValueError):
        BloomFilterEncoder(key=b"k" * 32, filter_length=4)


def test_encoder_num_hash_functions_zero():
    with pytest.raises(ValueError, match="num_hash_functions"):
        BloomFilterEncoder(key=b"k" * 32, num_hash_functions=0)


def test_encoder_sets_bits(key):
    enc = BloomFilterEncoder(key=key)
    bf = enc.encode("hello world")
    assert _popcount(bf) > 0


def test_encoder_similar_values_have_overlapping_bits(key):
    enc = BloomFilterEncoder(key=key)
    bf_a = enc.encode("john smith")
    bf_b = enc.encode("john smyth")
    intersection = _popcount(bytes(a & b for a, b in zip(bf_a, bf_b)))
    # Typo differs by one char — substantial overlap expected
    assert intersection > 0
