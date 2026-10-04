from __future__ import annotations

import pytest
from tokenvault.protocols.policy_guard import PolicyDecision
from tokenvault.policy.rules import FieldRule, RegionRule, PurposeRule
from tokenvault.policy.engine import PolicyEngine, RuleSet


# --- FieldRule ---
def test_field_rule_allows_matching_operation():
    rule = FieldRule(
        field_type="email",
        allowed_operations=frozenset({"tokenize", "match"}),
        policy_id="test",
    )
    decision = rule.evaluate("email", "tokenize", {})
    assert decision is not None
    assert decision.allowed is True


def test_field_rule_denies_unlisted_operation():
    rule = FieldRule(
        field_type="email",
        allowed_operations=frozenset({"tokenize"}),
        policy_id="test",
    )
    decision = rule.evaluate("email", "detokenize", {})
    assert decision is not None
    assert decision.allowed is False


def test_field_rule_skips_other_field():
    rule = FieldRule(
        field_type="email",
        allowed_operations=frozenset({"tokenize"}),
        policy_id="test",
    )
    assert rule.evaluate("name", "tokenize", {}) is None


# --- RegionRule ---
def test_region_rule_allows_valid_destination():
    rule = RegionRule(
        origin_region="CA",
        allowed_destinations=frozenset({"US", "EU"}),
        policy_id="test",
    )
    d = rule.evaluate("email", "transfer", {"destination_region": "US"})
    assert d is not None and d.allowed is True


def test_region_rule_denies_invalid_destination():
    rule = RegionRule(
        origin_region="CA",
        allowed_destinations=frozenset({"US"}),
        policy_id="test",
    )
    d = rule.evaluate("email", "transfer", {"destination_region": "CN"})
    assert d is not None and d.allowed is False


def test_region_rule_skips_non_transfer():
    rule = RegionRule("CA", frozenset({"US"}), "test")
    assert rule.evaluate("email", "tokenize", {}) is None


# --- PurposeRule ---
def test_purpose_rule_allows_matching_purpose():
    rule = PurposeRule(required_purpose="data_transfer", policy_id="test")
    d = rule.evaluate("email", "tokenize", {"purpose": "data_transfer"})
    assert d is not None and d.allowed is True


def test_purpose_rule_denies_no_purpose():
    rule = PurposeRule(required_purpose="data_transfer", policy_id="test")
    d = rule.evaluate("email", "tokenize", {})
    assert d is not None and d.allowed is False


# --- PolicyEngine ---
def test_engine_default_deny_no_rules():
    engine = PolicyEngine(rule_sets=[RuleSet(rules=[], default_allow=False)])
    d = engine.evaluate("email", "tokenize", {})
    assert d.allowed is False


def test_engine_first_deny_wins():
    deny_rule = FieldRule("email", frozenset(), "deny")
    allow_rule = FieldRule("email", frozenset({"tokenize"}), "allow")
    engine = PolicyEngine(rule_sets=[
        RuleSet(rules=[deny_rule], default_allow=True),
        RuleSet(rules=[allow_rule], default_allow=True),
    ])
    d = engine.evaluate("email", "tokenize", {})
    assert d.allowed is False


# --- PIPEDA ---
def test_pipeda_ruleset_denies_without_purpose():
    from tokenvault.policy.pipeda import PIPEDA_DEFAULT_RULESET
    engine = PolicyEngine(rule_sets=[PIPEDA_DEFAULT_RULESET])
    d = engine.evaluate("email", "tokenize", {})
    assert d.allowed is False


def test_pipeda_ruleset_allows_with_purpose():
    from tokenvault.policy.pipeda import PIPEDA_DEFAULT_RULESET
    engine = PolicyEngine(rule_sets=[PIPEDA_DEFAULT_RULESET])
    d = engine.evaluate("email", "tokenize", {"purpose": "data_transfer"})
    assert d.allowed is True
