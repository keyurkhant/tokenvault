from __future__ import annotations
import base64

from tokenvault.protocols.key_store import KeyStore
from tokenvault.protocols.tokenizer import TokenResult

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESSIV
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class AESSIVTokenizer:
    algorithm = "aes-siv"

    def __init__(
        self,
        key_store: KeyStore,
        allowed_fields: frozenset[str] | None = None,
    ) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[aes-siv] to use AESSIVTokenizer.")
        self._key_store = key_store
        self._allowed = allowed_fields

    def supports_field(self, field_type: str) -> bool:
        return self._allowed is None or field_type in self._allowed

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        key_id = self._key_store.get_current_key_id()
        key = self._key_store.get_key(key_id)
        aes = AESSIV(key)
        ciphertext = aes.encrypt(value.encode(), [field_type.encode()])
        token = base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode()
        return TokenResult(
            token=token,
            field_type=field_type,
            algorithm=self.algorithm,
            key_version=key_id,
            is_deterministic=True,
        )

    def detokenize(self, token_result: TokenResult) -> str:
        key = self._key_store.get_key(token_result.key_version)
        ciphertext = base64.urlsafe_b64decode(token_result.token + "==")
        aes = AESSIV(key)
        return aes.decrypt(ciphertext, [token_result.field_type.encode()]).decode()
