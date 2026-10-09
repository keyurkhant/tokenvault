from __future__ import annotations

import base64
import hashlib
import hmac as _hmac

from tokenvault.protocols.key_store import KeyEntropyError, KeyStore
from tokenvault.protocols.tokenizer import TokenizationError, TokenResult


class HMACTokenizer:
    algorithm = "hmac-sha256"

    def __init__(
        self,
        key_store: KeyStore,
        allowed_fields: frozenset[str] | None = None,
    ) -> None:
        self._key_store = key_store
        self._allowed = allowed_fields

    def supports_field(self, field_type: str) -> bool:
        return self._allowed is None or field_type in self._allowed

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        try:
            key_id = self._key_store.get_current_key_id()
            key = self._key_store.get_key(key_id)
            domain_input = f"{field_type}:{value}".encode()
            digest = _hmac.new(key, domain_input, hashlib.sha256).digest()
            token = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
            return TokenResult(
                token=token,
                field_type=field_type,
                algorithm=self.algorithm,
                key_version=key_id,
                is_deterministic=True,
            )
        except (KeyError, KeyEntropyError):
            raise
        except Exception:
            raise TokenizationError(
                "HMAC tokenization failed",
                field_type=field_type,
                operation="tokenize",
            ) from None
