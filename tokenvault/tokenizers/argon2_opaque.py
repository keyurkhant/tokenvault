from __future__ import annotations
import base64
import hmac as _hmac
import secrets

from tokenvault.protocols.tokenizer import TokenResult

try:
    from argon2.low_level import Type, hash_secret_raw
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False

_SALT_BYTES = 32


class Argon2OpaqueTokenizer:
    algorithm = "argon2id"

    def __init__(
        self,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32,
    ) -> None:
        if not _AVAILABLE:
            raise ImportError("Install tokenvault[argon2] to use Argon2OpaqueTokenizer.")
        self._time_cost = time_cost
        self._memory_cost = memory_cost
        self._parallelism = parallelism
        self._hash_len = hash_len

    def supports_field(self, field_type: str) -> bool:
        return True

    def tokenize(self, value: str, field_type: str) -> TokenResult:
        salt = secrets.token_bytes(_SALT_BYTES)
        domain_input = f"{field_type}:{value}".encode()
        raw = hash_secret_raw(
            secret=domain_input,
            salt=salt,
            time_cost=self._time_cost,
            memory_cost=self._memory_cost,
            parallelism=self._parallelism,
            hash_len=self._hash_len,
            type=Type.ID,
        )
        token = base64.urlsafe_b64encode(salt + raw).rstrip(b"=").decode()
        return TokenResult(
            token=token,
            field_type=field_type,
            algorithm=self.algorithm,
            key_version="none",
            is_deterministic=False,
        )

    def verify(self, value: str, token_result: TokenResult) -> bool:
        combined = base64.urlsafe_b64decode(token_result.token + "==")
        salt = combined[:_SALT_BYTES]
        stored = combined[_SALT_BYTES:]
        domain_input = f"{token_result.field_type}:{value}".encode()
        candidate = hash_secret_raw(
            secret=domain_input,
            salt=salt,
            time_cost=self._time_cost,
            memory_cost=self._memory_cost,
            parallelism=self._parallelism,
            hash_len=len(stored),
            type=Type.ID,
        )
        return _hmac.compare_digest(stored, candidate)
