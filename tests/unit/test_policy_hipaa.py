from __future__ import annotations

from tokenvault.policy.hipaa import HIPAA_SAFE_HARBOR_RULESET


def allow(field_type: str, operation: str, **ctx):
    return HIPAA_SAFE_HARBOR_RULESET.evaluate(field_type, operation, ctx).allowed


# --- tokenize / match on PHI ---

def test_tokenize_phi_name_allowed():
    assert allow("name", "tokenize")

def test_tokenize_email_allowed():
    assert allow("email", "tokenize")

def test_tokenize_ssn_allowed():
    assert allow("ssn", "tokenize")

def test_tokenize_biometric_allowed():
    assert allow("biometric", "tokenize")

def test_match_phi_allowed():
    assert allow("national_id", "match")

def test_non_phi_field_denied():
    assert not allow("custom_field", "tokenize")


# --- transfer with HIPAA TPO purposes ---

def test_transfer_phi_with_treatment_purpose_allowed():
    assert allow("email", "transfer", purpose="hipaa_treatment")

def test_transfer_phi_with_payment_purpose_allowed():
    assert allow("name", "transfer", purpose="hipaa_payment")

def test_transfer_phi_with_operations_purpose_allowed():
    assert allow("phone", "transfer", purpose="hipaa_operations")

def test_transfer_phi_without_tpo_purpose_denied():
    assert not allow("email", "transfer", purpose="marketing")

def test_transfer_phi_no_purpose_denied():
    assert not allow("email", "transfer")

def test_transfer_non_phi_denied():
    # Non-PHI field not in ruleset → default_allow=False
    assert not allow("custom_field", "transfer", purpose="hipaa_treatment")


# --- policy IDs ---

def test_phi_field_policy_id():
    decision = HIPAA_SAFE_HARBOR_RULESET.evaluate("email", "tokenize", {})
    assert decision.policy_id == "hipaa-phi-email"

def test_tpo_transfer_policy_id():
    decision = HIPAA_SAFE_HARBOR_RULESET.evaluate(
        "email", "transfer", {"purpose": "marketing"}
    )
    assert decision.policy_id == "hipaa-tpo-transfer"

def test_all_18_identifiers_can_be_tokenized():
    from tokenvault.policy.hipaa import HIPAA_PHI_IDENTIFIERS
    for phi in HIPAA_PHI_IDENTIFIERS:
        assert allow(phi, "tokenize"), f"tokenize should be allowed for PHI field '{phi}'"
