import secrets

import pytest

from tokenvault.keys.direct import DirectKeyStore
from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
from tokenvault.transfer.manifest import FieldMapping, TransferManifest
from tokenvault.transfer.payload import TransferPayload
from tokenvault.transfer.psi import PrivateSetIntersectionMatcher


@pytest.fixture()
def token_result():
    store = DirectKeyStore(keys={"v1": secrets.token_bytes(32)}, current_key_id="v1")
    t = HMACTokenizer(key_store=store)
    return t.tokenize("jane@example.com", "email")


def test_payload_contains_no_raw_pii(token_result):
    payload = TransferPayload()
    payload.add_record({"email": token_result})
    data = payload.to_dict()
    assert "jane@example.com" not in str(data)
    assert token_result.token in str(data)


def test_payload_multiple_records(token_result):
    payload = TransferPayload()
    payload.add_record({"email": token_result})
    payload.add_record({"email": token_result})
    assert len(payload.to_dict()["records"]) == 2


def test_manifest_to_dict(token_result):
    manifest = TransferManifest(
        source_region="CA",
        destination_region="US",
        policy_id="pipeda-default",
        consent_reference="consent-abc-123",
        field_mappings=[
            FieldMapping(
                field_name="email",
                field_type="email",
                algorithm=token_result.algorithm,
                key_version=token_result.key_version,
            )
        ],
    )
    d = manifest.to_dict()
    assert d["source_region"] == "CA"
    assert d["destination_region"] == "US"
    assert len(d["field_mappings"]) == 1
    assert "jane@example.com" not in str(d)


def test_psi_stub_raises():
    m = PrivateSetIntersectionMatcher()
    with pytest.raises(NotImplementedError):
        m.match("token_a", "token_b")
