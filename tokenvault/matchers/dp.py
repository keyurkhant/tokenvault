from __future__ import annotations

import math
import secrets

from tokenvault.protocols.matcher import MatchResult


def _laplace_sample(scale: float) -> float:
    """Sample from Laplace(0, scale) via the inverse CDF method using secrets."""
    while True:
        u = secrets.randbelow(2**53) / 2**53
        if 0.0 < u < 1.0:
            break
    u -= 0.5  # shift to (-0.5, 0.5)
    return -scale * math.copysign(1.0, u) * math.log(1.0 - 2.0 * abs(u))


class DifferentialPrivacyWrapper:
    """Adds calibrated Laplace noise to match scores for differential privacy.

    Noise is drawn from Laplace(0, sensitivity/epsilon). The noisy score is
    clamped to [0.0, 1.0]. A record is considered matched when the noisy
    score meets or exceeds the base matcher's threshold.

    The algorithm label is prefixed with "dp-" to distinguish DP-protected
    results from raw scores in audit logs.
    """

    def __init__(
        self,
        base_matcher: object,
        epsilon: float = 1.0,
        sensitivity: float = 1.0,
    ) -> None:
        if epsilon <= 0:
            raise ValueError("epsilon must be positive.")
        if sensitivity <= 0:
            raise ValueError("sensitivity must be positive.")
        self._base = base_matcher
        self._scale = sensitivity / epsilon
        base_algo = getattr(base_matcher, "algorithm", "unknown")
        self.algorithm = f"dp-{base_algo}"

    def match(self, token_a: str, token_b: str) -> MatchResult:
        result: MatchResult = self._base.match(token_a, token_b)  # type: ignore[attr-defined]
        noisy = max(0.0, min(1.0, result.score + _laplace_sample(self._scale)))
        return MatchResult(
            score=noisy,
            algorithm=self.algorithm,
            threshold=result.threshold,
            matched=noisy >= result.threshold,
        )
