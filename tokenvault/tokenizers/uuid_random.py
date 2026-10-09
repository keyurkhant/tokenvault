from __future__ import annotations

import secrets
import uuid as _uuid

from tokenvault.protocols.tokenizer import TokenizationError, TokenResult


class UUIDRandomTokenizer:
    algorithm = "uuid-v4"

    def supports_field(self, field_type: str) -> bool:
        return True

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        try:
            token = str(_uuid.UUID(bytes=secrets.token_bytes(16), version=4))
            return TokenResult(
                token=token,
                field_type=field_type,
                algorithm=self.algorithm,
                key_version="none",
                is_deterministic=False,
            )
        except Exception:
            raise TokenizationError(
                "UUID tokenization failed",
                field_type=field_type,
                operation="tokenize",
            ) from None
