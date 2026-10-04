import pytest
from tokenvault.matchers.exact import ExactTokenMatcher
from tokenvault.matchers.ngram import NgramSimilarityMatcher


# --- Exact ---
def test_exact_same_token():
    m = ExactTokenMatcher()
    r = m.match("abc123", "abc123")
    assert r.matched is True
    assert r.score == 1.0


def test_exact_different_token():
    m = ExactTokenMatcher()
    r = m.match("abc123", "xyz789")
    assert r.matched is False
    assert r.score == 0.0


def test_exact_constant_time_safe():
    # both comparisons must complete without raising
    m = ExactTokenMatcher()
    m.match("a" * 1000, "b" * 1000)
    m.match("a" * 1000, "a" * 1000)


# --- Ngram (stdlib, no optional dep) ---
def test_ngram_identical():
    m = NgramSimilarityMatcher(n=2, threshold=0.7)
    r = m.match("smith", "smith")
    assert r.score == pytest.approx(1.0)
    assert r.matched is True


def test_ngram_similar():
    m = NgramSimilarityMatcher(n=2, threshold=0.5)
    r = m.match("smith", "smyth")
    assert r.score > 0.4


def test_ngram_dissimilar():
    m = NgramSimilarityMatcher(n=2, threshold=0.7)
    r = m.match("smith", "jones")
    assert r.matched is False


def test_ngram_empty_strings():
    m = NgramSimilarityMatcher(n=2)
    r = m.match("", "")
    assert r.score == pytest.approx(1.0)


# --- Optional fuzzy matchers (skip if jellyfish not installed) ---
jellyfish = pytest.importorskip("jellyfish")


def test_jaro_winkler_high_similarity():
    from tokenvault.matchers.jaro_winkler import JaroWinklerMatcher
    m = JaroWinklerMatcher(threshold=0.85)
    r = m.match("jane smith", "jane smyth")
    assert r.score > 0.85
    assert r.matched is True


def test_jaro_winkler_dissimilar():
    from tokenvault.matchers.jaro_winkler import JaroWinklerMatcher
    m = JaroWinklerMatcher(threshold=0.85)
    r = m.match("jane smith", "robert jones")
    assert r.matched is False


def test_levenshtein_typo():
    from tokenvault.matchers.levenshtein import LevenshteinMatcher
    m = LevenshteinMatcher(threshold=0.80)
    r = m.match("johnsen", "johnson")
    assert r.matched is True


def test_soundex_same_sound():
    from tokenvault.matchers.phonetic import SoundexMatcher
    m = SoundexMatcher()
    r = m.match("smith", "smyth")
    assert r.matched is True


def test_metaphone_same_sound():
    from tokenvault.matchers.phonetic import MetaphoneMatcher
    m = MetaphoneMatcher()
    r = m.match("john", "jon")
    assert r.matched is True
