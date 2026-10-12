from __future__ import annotations

import hashlib
import secrets

from tokenvault.protocols.matcher import MatchResult

# RFC 3526 Group 14 — 2048-bit MODP group (safe prime).
# Q = (P - 1) // 2 is the prime subgroup order used for scalar arithmetic.
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_Q = (_P - 1) // 2
_G = 2  # generator of the prime-order subgroup


def _hash_to_group(token: str) -> int:
    """Map a token to a group element: g^SHA-256(token) mod P."""
    h = int.from_bytes(hashlib.sha256(token.encode()).digest(), "big")
    return pow(_G, h, _P)


def _random_scalar() -> int:
    """Uniform random scalar in [1, Q-1]."""
    return secrets.randbelow(_Q - 1) + 1


class OPRFServer:
    """Server side of the OPRF-based PSI protocol.

    Holds a secret scalar k derived from *key*. Two operations:
    - evaluate(blinded): raise a single blinded group element to k
    - precompute_set(tokens): evaluate H(t)^k for every server token
      to build the reference set the client compares against
    """

    def __init__(self, key: bytes) -> None:
        k_raw = int.from_bytes(
            hashlib.pbkdf2_hmac("sha256", key, b"oprf-server-scalar", 100_000),
            "big",
        )
        self._k = (k_raw % (_Q - 1)) + 1  # k in [1, Q-1]

    def evaluate(self, blinded: int) -> int:
        """B = A^k mod P."""
        return pow(blinded, self._k, _P)

    def precompute_set(self, tokens: list[str]) -> frozenset[int]:
        """Return {H(t)^k : t in tokens} for client-side intersection."""
        return frozenset(pow(_hash_to_group(t), self._k, _P) for t in tokens)


class OPRFClient:
    """Client side of the OPRF-based PSI protocol.

    Stateless — all per-query state is returned to the caller.

    Protocol:
      1. blind(tokens)          → blinded group elements + blindings (keep secret)
      2. server.evaluate(each)  → evaluated elements  (send/receive over wire)
      3. unblind(evaluated, blindings) → H(t)^k for each client token
      4. finalize(unblinded, server_set) → intersection membership booleans
    """

    def blind(self, tokens: list[str]) -> tuple[list[int], list[int]]:
        """A_i = H(t_i)^r_i mod P. Returns (blinded, blindings)."""
        blinded: list[int] = []
        blindings: list[int] = []
        for t in tokens:
            r = _random_scalar()
            blinded.append(pow(_hash_to_group(t), r, _P))
            blindings.append(r)
        return blinded, blindings

    def unblind(self, evaluated: list[int], blindings: list[int]) -> list[int]:
        """C_i = B_i^(r_i^{-1} mod Q) mod P  →  H(t_i)^k."""
        return [
            pow(e, pow(r, _Q - 2, _Q), _P)
            for e, r in zip(evaluated, blindings)
        ]

    def finalize(
        self, unblinded: list[int], server_set: frozenset[int]
    ) -> list[bool]:
        """True for each unblinded value found in the server's pre-computed set."""
        return [u in server_set for u in unblinded]


class PSIQuery:
    """Convenience wrapper that runs the full OPRF-PSI protocol in one call.

    Suitable for same-process use (testing, local pipelines). In a real
    two-party deployment the server and client would run in separate processes
    and exchange blinded/evaluated values over a network.
    """

    def __init__(self, server: OPRFServer, server_tokens: list[str]) -> None:
        self._server = server
        self._server_set = server.precompute_set(server_tokens)

    def query(self, client_tokens: list[str]) -> list[str]:
        """Return the subset of *client_tokens* present in the server's set."""
        client = OPRFClient()
        blinded, blindings = client.blind(client_tokens)
        evaluated = [self._server.evaluate(b) for b in blinded]
        unblinded = client.unblind(evaluated, blindings)
        matched = client.finalize(unblinded, self._server_set)
        return [t for t, m in zip(client_tokens, matched) if m]


class PrivateSetIntersectionMatcher:
    """Matcher-protocol stub kept for backward compatibility.

    Use PSIQuery for the real OPRF-PSI set-level protocol.
    """

    algorithm = "psi-oprf"

    def __init__(self, threshold: float = 1.0) -> None:
        self._threshold = threshold

    def match(self, token_a: str, token_b: str) -> MatchResult:
        raise NotImplementedError(
            "Pair-wise PSI is not meaningful; use PSIQuery for set-level intersection."
        )
