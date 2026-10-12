from __future__ import annotations

from tokenvault.policy.ccpa import CCPA_DEFAULT_RULESET


def allow(field_type: str, operation: str, **ctx):
    return CCPA_DEFAULT_RULESET.evaluate(field_type, operation, ctx).allowed


# --- tokenize / match on personal info ---

def test_tokenize_email_allowed():
    assert allow("email", "tokenize", purpose="ccpa_service")

def test_tokenize_name_allowed():
    assert allow("name", "tokenize", purpose="ccpa_service")

def test_match_phone_allowed():
    assert allow("phone", "match", purpose="ccpa_service")

def test_unknown_category_denied():
    assert not allow("favourite_colour", "tokenize", purpose="ccpa_service")


# --- sensitive categories ---

def test_sensitive_health_requires_opt_in():
    assert not allow("health", "tokenize", purpose="marketing")

def test_sensitive_health_with_opt_in_allowed():
    assert allow("health", "tokenize", purpose="opt_in_consent")

def test_sensitive_biometric_with_ccpa_service_allowed():
    assert allow("biometric", "tokenize", purpose="ccpa_service")

def test_sensitive_financial_denied_without_allowed_purpose():
    assert not allow("financial_info", "tokenize", purpose="ccpa_first_party")

def test_sensitive_national_id_with_ccpa_legal_allowed():
    assert allow("national_id", "tokenize", purpose="ccpa_legal")

def test_sensitive_category_no_purpose_denied():
    assert not allow("health", "tokenize")


# --- transfer rules ---

def test_transfer_with_ccpa_service_allowed():
    assert allow("email", "transfer", purpose="ccpa_service")

def test_transfer_with_opt_in_allowed():
    assert allow("name", "transfer", purpose="opt_in_consent")

def test_transfer_without_permitted_purpose_denied():
    assert not allow("email", "transfer", purpose="marketing")

def test_transfer_no_purpose_denied():
    assert not allow("email", "transfer")

def test_transfer_non_personal_info_denied():
    assert not allow("favourite_colour", "transfer", purpose="ccpa_service")


# --- policy IDs ---

def test_standard_field_policy_id():
    decision = CCPA_DEFAULT_RULESET.evaluate("email", "tokenize", {"purpose": "ccpa_service"})
    assert decision.policy_id == "ccpa-email"

def test_sensitive_denial_policy_id():
    decision = CCPA_DEFAULT_RULESET.evaluate("health", "tokenize", {"purpose": "analytics"})
    assert decision.policy_id == "ccpa-sensitive"

def test_transfer_denial_policy_id():
    decision = CCPA_DEFAULT_RULESET.evaluate("email", "transfer", {"purpose": "marketing"})
    assert decision.policy_id == "ccpa-transfer"
