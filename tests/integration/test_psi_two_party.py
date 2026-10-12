"""Two-party OPRF-PSI integration test.

Simulates a real deployment: Party A (server) and Party B (client) are in
separate logical contexts. The protocol exchange is:

  1. Server pre-computes H(t)^k for its token set — shared with client as
     an opaque set of integers (no raw tokens exposed).
  2. Client blinds its tokens with per-element random scalars — only blinded
     values cross the wire, hiding raw tokens from the server.
  3. Server evaluates each blinded value — returns A_i^k = H(t_i)^(r_i * k).
  4. Client unblinds — recovers H(t_i)^k and checks membership in server set.

Neither party sees the other's raw token set beyond the intersection.
"""
from __future__ import annotations

import secrets

from tokenvault.transfer.psi import OPRFClient, OPRFServer, PSIQuery


def make_server_tokens(vault_a_records: list[str]) -> list[str]:
    return vault_a_records


def simulate_protocol(
    server: OPRFServer,
    server_tokens: list[str],
    client_tokens: list[str],
) -> list[str]:
    """Run the full wire-exchange protocol without PSIQuery shorthand."""
    # Phase 1: server pre-computes its reference set
    server_set = server.precompute_set(server_tokens)

    # Phase 2: client blinds (r is kept local — never leaves client)
    client = OPRFClient()
    blinded, blindings = client.blind(client_tokens)

    # Phase 3: server evaluates the blinded values (wire transfer simulation)
    evaluated = [server.evaluate(b) for b in blinded]

    # Phase 4: client unblinds and checks membership
    unblinded = client.unblind(evaluated, blindings)
    matched = client.finalize(unblinded, server_set)
    return [t for t, m in zip(client_tokens, matched) if m]


# ---------------------------------------------------------------------------
# Correctness
# ---------------------------------------------------------------------------

def test_exact_intersection_correctness():
    shared_key = secrets.token_bytes(32)
    server = OPRFServer(key=shared_key)

    party_a_tokens = ["hmac-token-001", "hmac-token-002", "hmac-token-003", "hmac-token-004"]
    party_b_tokens = ["hmac-token-002", "hmac-token-004", "hmac-token-005"]

    intersection = simulate_protocol(server, party_a_tokens, party_b_tokens)
    assert sorted(intersection) == ["hmac-token-002", "hmac-token-004"]


def test_disjoint_sets_produce_empty_intersection():
    server = OPRFServer(key=secrets.token_bytes(32))
    result = simulate_protocol(server, ["a", "b", "c"], ["x", "y", "z"])
    assert result == []


def test_subset_intersection():
    server = OPRFServer(key=secrets.token_bytes(32))
    server_tokens = [f"tok-{i}" for i in range(20)]
    client_tokens = [f"tok-{i}" for i in range(5, 10)]
    result = simulate_protocol(server, server_tokens, client_tokens)
    assert sorted(result) == sorted(client_tokens)


def test_large_sets():
    server = OPRFServer(key=secrets.token_bytes(32))
    n = 100
    server_tokens = [f"server-{i}" for i in range(n)]
    client_tokens = [f"server-{i}" for i in range(0, n, 2)]  # even-numbered tokens
    result = simulate_protocol(server, server_tokens, client_tokens)
    assert sorted(result) == sorted(client_tokens)


# ---------------------------------------------------------------------------
# Privacy / security properties
# ---------------------------------------------------------------------------

def test_blinding_hides_raw_tokens():
    """Blinded values for the same token differ across protocol runs."""
    client = OPRFClient()
    token = "sensitive-id-12345"

    blinded_run1, _ = client.blind([token])
    blinded_run2, _ = client.blind([token])

    # The server sees different values each time — cannot identify the token
    assert blinded_run1[0] != blinded_run2[0]


def test_different_keys_produce_different_server_sets():
    """A client cannot use one server's pre-computed set against another server."""
    server_a = OPRFServer(key=secrets.token_bytes(32))
    server_b = OPRFServer(key=secrets.token_bytes(32))
    tokens = ["tok-1", "tok-2"]

    set_a = server_a.precompute_set(tokens)
    set_b = server_b.precompute_set(tokens)
    assert set_a != set_b


def test_psiq_wrapper_matches_manual_protocol():
    key = secrets.token_bytes(32)
    server = OPRFServer(key=key)
    server_tokens = ["alpha", "beta", "gamma"]
    client_tokens = ["beta", "delta"]

    psiq_result = PSIQuery(server, server_tokens).query(client_tokens)
    manual_result = simulate_protocol(server, server_tokens, client_tokens)
    assert sorted(psiq_result) == sorted(manual_result)
