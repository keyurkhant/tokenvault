from __future__ import annotations

import secrets

import pytest

from tokenvault.transfer.psi import (
    OPRFClient,
    OPRFServer,
    PSIQuery,
    _hash_to_group,
    _random_scalar,
)


@pytest.fixture()
def key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture()
def server(key: bytes) -> OPRFServer:
    return OPRFServer(key=key)


# --- primitives ---

def test_hash_to_group_is_positive():
    assert _hash_to_group("hello") > 0


def test_hash_to_group_deterministic():
    assert _hash_to_group("jane@example.com") == _hash_to_group("jane@example.com")


def test_hash_to_group_different_inputs_differ():
    assert _hash_to_group("alice") != _hash_to_group("bob")


def test_random_scalar_in_range():
    from tokenvault.transfer.psi import _Q
    for _ in range(20):
        r = _random_scalar()
        assert 1 <= r <= _Q - 1


# --- OPRFServer ---

def test_server_evaluate_deterministic(server):
    from tokenvault.transfer.psi import _hash_to_group
    h = _hash_to_group("token")
    assert server.evaluate(h) == server.evaluate(h)


def test_server_different_keys_produce_different_outputs():
    s1 = OPRFServer(key=secrets.token_bytes(32))
    s2 = OPRFServer(key=secrets.token_bytes(32))
    from tokenvault.transfer.psi import _hash_to_group
    h = _hash_to_group("token")
    assert s1.evaluate(h) != s2.evaluate(h)


def test_precompute_set_returns_frozenset(server):
    result = server.precompute_set(["a", "b", "c"])
    assert isinstance(result, frozenset)
    assert len(result) == 3


def test_precompute_set_empty(server):
    assert server.precompute_set([]) == frozenset()


# --- OPRFClient ---

def test_blind_returns_two_lists_of_equal_length():
    client = OPRFClient()
    blinded, blindings = client.blind(["a", "b", "c"])
    assert len(blinded) == 3
    assert len(blindings) == 3


def test_blind_produces_different_values_each_call():
    client = OPRFClient()
    b1, _ = client.blind(["token"])
    b2, _ = client.blind(["token"])
    # Different random scalars → different blinded values (almost certainly)
    assert b1 != b2


def test_unblind_recovers_server_output(server):
    client = OPRFClient()
    tokens = ["alice@example.com"]
    blinded, blindings = client.blind(tokens)
    evaluated = [server.evaluate(b) for b in blinded]
    unblinded = client.unblind(evaluated, blindings)
    expected = server.precompute_set(tokens)
    assert unblinded[0] in expected


def test_finalize_returns_booleans():
    server = OPRFServer(key=secrets.token_bytes(32))
    client = OPRFClient()
    blinded, blindings = client.blind(["x"])
    evaluated = [server.evaluate(b) for b in blinded]
    unblinded = client.unblind(evaluated, blindings)
    result = client.finalize(unblinded, server.precompute_set(["x"]))
    assert result == [True]


# --- PSIQuery ---

def test_psiq_exact_intersection(server):
    q = PSIQuery(server, server_tokens=["alice", "bob", "carol"])
    result = q.query(["bob", "dave"])
    assert result == ["bob"]


def test_psiq_no_intersection(server):
    q = PSIQuery(server, server_tokens=["alice", "bob"])
    assert q.query(["carol", "dave"]) == []


def test_psiq_full_intersection(server):
    tokens = ["t1", "t2", "t3"]
    q = PSIQuery(server, server_tokens=tokens)
    assert sorted(q.query(tokens)) == sorted(tokens)


def test_psiq_empty_client(server):
    q = PSIQuery(server, server_tokens=["alice"])
    assert q.query([]) == []


def test_psiq_empty_server():
    server = OPRFServer(key=secrets.token_bytes(32))
    q = PSIQuery(server, server_tokens=[])
    assert q.query(["alice"]) == []
