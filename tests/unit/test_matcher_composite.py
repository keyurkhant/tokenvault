import pytest

from tokenvault.matchers.composite import CompositeMatcher, WeightedMatcher
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.matchers.ngram import NgramSimilarityMatcher


def test_composite_weights_must_sum_to_one():
    with pytest.raises(ValueError, match="1.0"):
        CompositeMatcher(
            matchers=[
                WeightedMatcher(ExactTokenMatcher(), 0.3),
                WeightedMatcher(NgramSimilarityMatcher(), 0.3),
            ]
        )


def test_composite_weighted_score():
    m = CompositeMatcher(
        matchers=[
            WeightedMatcher(ExactTokenMatcher(), 0.5),
            WeightedMatcher(NgramSimilarityMatcher(n=2), 0.5),
        ],
        threshold=0.5,
    )
    r = m.match("smith", "smith")
    assert r.score == pytest.approx(1.0)
    assert r.matched is True
    assert r.algorithm == "composite"


def test_composite_partial_match():
    m = CompositeMatcher(
        matchers=[
            WeightedMatcher(ExactTokenMatcher(), 0.5),
            WeightedMatcher(NgramSimilarityMatcher(n=2, threshold=0.5), 0.5),
        ],
        threshold=0.4,
    )
    r = m.match("smith", "smyth")
    assert 0.0 < r.score < 1.0
