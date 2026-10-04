import secrets
import pytest


@pytest.fixture()
def test_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture()
def test_key_store(test_key: bytes):
    from tokenvault.keys.direct import DirectKeyStore
    return DirectKeyStore(keys={"test-v1": test_key}, current_key_id="test-v1")


@pytest.fixture()
def hmac_tokenizer(test_key_store):
    from tokenvault.tokenizers.hmac_sha256 import HMACTokenizer
    return HMACTokenizer(key_store=test_key_store)


@pytest.fixture()
def vault(test_key_store, hmac_tokenizer):
    from tokenvault.config import VaultConfig
    from tokenvault.vault import TokenVault
    from tokenvault.matchers.exact import ExactTokenMatcher
    from tokenvault.audit.sinks.logging import PythonLoggingAuditSink
    return TokenVault(
        VaultConfig(
            key_store=test_key_store,
            tokenizer=hmac_tokenizer,
            matchers={"exact": ExactTokenMatcher()},
            audit_sink=PythonLoggingAuditSink(),
        )
    )
