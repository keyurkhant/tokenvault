from __future__ import annotations

import pytest

from tokenvault.matchers.dp import DifferentialPrivacyWrapper, _laplace_sample
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.protocols.matcher import MatchResult

# --- _laplace_sample ---

def test_laplace_sample_is_float():
    assert isinstance(_laplace_sample(1.0), float)


def test_laplace_sample_scale_zero_limit():
    # Very small scale → noise near zero
    samples = [_laplace_sample(1e-9) for _ in range(50)]
    assert all(abs(s) < 1e-5 for s in samples)


def test_laplace_sample_large_scale_varies():
    # Large scale → samples spread wide
    samples = [_laplace_sample(10.0) for _ in range(100)]
    assert max(samples) - min(samples) > 1.0


# --- DifferentialPrivacyWrapper construction ---

def test_dp_requires_positive_epsilon():
    with pytest.raises(ValueError, match="epsilon"):
        DifferentialPrivacyWrapper(ExactTokenMatcher(), epsilon=0.0)


def test_dp_requires_positive_sensitivity():
    with pytest.raises(ValueError, match="sensitivity"):
        DifferentialPrivacyWrapper(ExactTokenMatcher(), sensitivity=-1.0)


def test_dp_algorithm_label():
    wrapper = DifferentialPrivacyWrapper(ExactTokenMatcher(), epsilon=1.0)
    assert wrapper.algorithm == "dp-exact"


def test_dp_unknown_base_algorithm():
    class NoAlgo:
        def match(self, a: str, b: str) -> MatchResult:
            return MatchResult(score=0.5, algorithm="x", threshold=0.5, matched=True)

    wrapper = DifferentialPrivacyWrapper(NoAlgo())
    assert wrapper.algorithm == "dp-unknown"


# --- match() output ---

def test_dp_score_clamped_to_0_1():
    # Use large epsilon (small noise) to keep score near original
    wrapper = DifferentialPrivacyWrapper(ExactTokenMatcher(), epsilon=100.0, sensitivity=1.0)
    for _ in range(30):
        result = wrapper.match("abc", "abc")
        assert 0.0 <= result.score <= 1.0


def test_dp_matched_reflects_noisy_score():
    wrapper = DifferentialPrivacyWrapper(ExactTokenMatcher(), epsilon=1000.0)
    result = wrapper.match("abc", "abc")
    assert result.matched == (result.score >= result.threshold)


def test_dp_preserves_threshold():
    base = ExactTokenMatcher(threshold=0.9)
    wrapper = DifferentialPrivacyWrapper(base, epsilon=1.0)
    result = wrapper.match("a", "a")
    assert result.threshold == pytest.approx(0.9)


def test_dp_score_differs_from_base_for_exact_match():
    # With meaningful epsilon, noise should perturb the score sometimes
    wrapper = DifferentialPrivacyWrapper(ExactTokenMatcher(), epsilon=0.5, sensitivity=1.0)
    results = [wrapper.match("abc", "abc").score for _ in range(50)]
    # Not every run is exactly 1.0 because noise is added
    assert any(s != pytest.approx(1.0) for s in results)


def test_dp_mismatch_score_is_noisy():
    wrapper = DifferentialPrivacyWrapper(ExactTokenMatcher(), epsilon=0.5)
    results = [wrapper.match("abc", "xyz").score for _ in range(50)]
    # Base score is 0.0; noise can push it positive
    assert any(s > 0.0 for s in results)


def test_dp_algorithm_label_in_result():
    wrapper = DifferentialPrivacyWrapper(ExactTokenMatcher(), epsilon=1.0)
    result = wrapper.match("a", "a")
    assert result.algorithm == "dp-exact"
