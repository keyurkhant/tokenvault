from __future__ import annotations
from tokenvault.protocols.matcher import MatchResult


class PrivateSetIntersectionMatcher:
    """Stub for OPRF-based Private Set Intersection cross-system matching.

    Satisfies the Matcher protocol but raises NotImplementedError.

    Expected OPRF-PSI protocol (RFC draft, EPRINT 2016/799):
      1. Party A blinds elements: blinded_i = H(elem_i)^r  mod p
      2. Party B evaluates:       eval_i    = blinded_i^sk  mod p
      3. Party A unblinds:        final_i   = eval_i^(1/r) mod p
                                             = H(elem_i)^sk mod p
      4. Both parties sort and intersect on final_i values.
    Neither party learns the other's raw set.
    """

    algorithm = "psi-oprf-stub"

    def __init__(self, threshold: float = 1.0) -> None:
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        raise NotImplementedError(
            "PSI cross-system matching is not yet implemented. "
            "See tokenvault/transfer/psi.py for the expected OPRF contract."
        )
