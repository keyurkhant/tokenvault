from __future__ import annotations

from tokenvault.policy.gdpr import GDPR_DEFAULT_RULESET


def allow(field_type: str, operation: str, **ctx):
    return GDPR_DEFAULT_RULESET.evaluate(field_type, operation, ctx).allowed


# --- standard fields ---

def test_tokenize_email_allowed():
    assert allow("email", "tokenize", purpose="data_transfer")

def test_match_name_allowed():
    assert allow("name", "match", purpose="data_transfer")

def test_unknown_field_denied():
    assert not allow("unknown_field", "tokenize", purpose="data_transfer")


# --- Art. 45 adequacy ---

def test_transfer_to_adequate_country_allowed():
    assert allow("email", "transfer", destination_region="CA", purpose="data_transfer")

def test_transfer_to_non_adequate_country_denied():
    assert not allow("email", "transfer", destination_region="US", purpose="data_transfer")

def test_transfer_to_eu_country_allowed():
    assert allow("email", "transfer", destination_region="DE", purpose="data_transfer")

def test_transfer_to_uk_allowed():
    assert allow("name", "transfer", destination_region="UK", purpose="data_transfer")

def test_transfer_no_destination_passes_adequacy():
    # No destination → adequacy rule abstains; field rule decides
    assert allow("email", "transfer", purpose="data_transfer")


# --- Art. 9 special categories ---

def test_health_field_requires_explicit_consent():
    assert not allow("health", "tokenize", purpose="data_transfer")

def test_health_with_explicit_consent_allowed():
    assert allow("health", "tokenize", purpose="explicit_consent")

def test_biometric_denied_without_consent():
    assert not allow("biometric", "tokenize", purpose="analytics")

def test_genetic_denied_without_consent():
    assert not allow("genetic", "transfer", destination_region="CA", purpose="data_transfer")

def test_special_category_no_purpose_denied():
    assert not allow("health", "tokenize")


# --- policy_id labels ---

def test_email_policy_id():
    decision = GDPR_DEFAULT_RULESET.evaluate("email", "tokenize", {"purpose": "data_transfer"})
    assert decision.policy_id == "gdpr-email"

def test_adequacy_policy_id():
    decision = GDPR_DEFAULT_RULESET.evaluate(
        "email", "transfer", {"destination_region": "US", "purpose": "data_transfer"}
    )
    assert decision.policy_id == "gdpr-art45-adequacy"

def test_special_category_policy_id():
    decision = GDPR_DEFAULT_RULESET.evaluate(
        "health", "tokenize", {"purpose": "analytics"}
    )
    assert decision.policy_id == "gdpr-art9-special-category"
