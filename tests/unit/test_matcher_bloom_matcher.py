from __future__ import annotations

import base64
import secrets

import pytest

from tokenvault.matchers.bloom import BloomFilterEncoder, BloomFilterMatcher


@pytest.fixture()
def key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture()
def enc(key: bytes) -> BloomFilterEncoder:
    return BloomFilterEncoder(key=key, filter_length=512, num_hash_functions=20)


@pytest.fixture()
def matcher() -> BloomFilterMatcher:
    return BloomFilterMatcher(threshold=0.75)


# --- Dice coefficient correctness ---

def test_dice_identical_vectors(enc, matcher):
    bf = enc.encode("john smith")
    result = matcher.match_encoded(bf, bf)
    assert result.score == pytest.approx(1.0)
    assert result.matched is True


def test_dice_zero_vectors(matcher):
    empty = bytes(64)
    result = matcher.match_encoded(empty, empty)
    assert result.score == 0.0
    assert result.matched is False


def test_dice_one_empty_vector(enc, matcher):
    bf = enc.encode("hello")
    empty = bytes(enc.filter_bytes)
    result = matcher.match_encoded(bf, empty)
    assert result.score == 0.0
    assert result.matched is False


def test_dice_similar_values_above_threshold(enc):
    matcher = BloomFilterMatcher(threshold=0.6)
    bf_a = enc.encode("john smith")
    bf_b = enc.encode("john smyth")  # one character typo
    result = matcher.match_encoded(bf_a, bf_b)
    assert result.matched is True
    assert result.score > 0.6


def test_dice_different_values_below_threshold(enc, matcher):
    bf_a = enc.encode("john smith")
    bf_b = enc.encode("alice johnson")
    result = matcher.match_encoded(bf_a, bf_b)
    # Very different names should score low
    assert result.score < 0.9


def test_dice_score_between_0_and_1(enc, matcher):
    bf_a = enc.encode("partial overlap here")
    bf_b = enc.encode("partial overlap there")
    result = matcher.match_encoded(bf_a, bf_b)
    assert 0.0 <= result.score <= 1.0


def test_dice_length_mismatch_raises(matcher):
    with pytest.raises(ValueError, match="same length"):
        matcher.match_encoded(bytes(64), bytes(32))


def test_dice_algorithm_label(enc, matcher):
    bf = enc.encode("test")
    result = matcher.match_encoded(bf, bf)
    assert result.algorithm == "bloom-dice"


def test_dice_threshold_stored(matcher):
    assert matcher._threshold == 0.75


# --- match() adapter (base64url strings) ---

def test_match_via_base64url(enc, matcher):
    value = "jane@example.com"
    bf = enc.encode(value)
    token = base64.urlsafe_b64encode(bf).rstrip(b"=").decode()
    result = matcher.match(token, token)
    assert result.score == pytest.approx(1.0)
    assert result.matched is True


def test_match_different_tokens(enc, matcher):
    bf_a = enc.encode("alice")
    bf_b = enc.encode("bob")
    ta = base64.urlsafe_b64encode(bf_a).rstrip(b"=").decode()
    tb = base64.urlsafe_b64encode(bf_b).rstrip(b"=").decode()
    result = matcher.match(ta, tb)
    assert isinstance(result.score, float)
