from __future__ import annotations

import base64
import os

from tokenvault.protocols.key_store import MIN_KEY_BYTES, KeyEntropyError

_SUPPORTED_ENCODINGS = frozenset({"hex", "base64", "raw"})


class EnvKeyStore:
    """Key store that reads key material from environment variables.

    Key encoding is controlled by the ``TOKENVAULT_KEY_ENCODING`` env var
    (or a custom *encoding_env* name).  Supported values:

    * ``hex`` *(default)* — keys are hex-encoded strings, e.g. ``deadbeef…``
    * ``base64``          — keys are standard base64-encoded strings
    * ``raw``             — keys are UTF-8 byte strings (use only for testing)

    Each key lives in an env var named ``<prefix><KEY_ID_UPPER>``, where
    hyphens in the key ID are replaced with underscores, e.g.
    key ID ``"v1"`` with the default prefix resolves to
    ``TOKENVAULT_KEY_V1``.
    """

    def __init__(
        self,
        prefix: str = "TOKENVAULT_KEY_",
        current_key_env: str = "TOKENVAULT_CURRENT_KEY_ID",
        encoding_env: str = "TOKENVAULT_KEY_ENCODING",
    ) -> None:
        self._prefix = prefix.upper()
        self._current_key_env = current_key_env
        self._encoding_env = encoding_env

    def _decode_key(self, raw: str, env_name: str) -> bytes:
        encoding = os.environ.get(self._encoding_env, "hex").lower().strip()
        if encoding not in _SUPPORTED_ENCODINGS:
            raise ValueError(
                f"Unknown key encoding {encoding!r} from env var {self._encoding_env!r}. "
                f"Supported: {', '.join(sorted(_SUPPORTED_ENCODINGS))}"
            )
        try:
            if encoding == "hex":
                return bytes.fromhex(raw)
            if encoding == "base64":
                return base64.b64decode(raw)
            return raw.encode()  # raw
        except Exception as exc:
            raise ValueError(
                f"Failed to decode key from '{env_name}' as {encoding!r}: {exc}"
            ) from exc

    def get_key(self, key_id: str) -> bytes:
        env_name = self._prefix + key_id.upper().replace("-", "_")
        raw = os.environ.get(env_name)
        if raw is None:
            raise KeyError(f"Environment variable '{env_name}' not set.")
        key = self._decode_key(raw, env_name)
        if len(key) < MIN_KEY_BYTES:
            raise KeyEntropyError(
                f"Key from '{env_name}' is {len(key)} bytes; minimum is {MIN_KEY_BYTES}."
            )
        return key

    def get_current_key_id(self) -> str:
        val = os.environ.get(self._current_key_env)
        if val is None:
            raise KeyError(f"Environment variable '{self._current_key_env}' not set.")
        return val

    def list_key_ids(self) -> list[str]:
        """Return key IDs discovered from env vars matching the prefix.

        Each env var named ``<PREFIX><SUFFIX>`` yields a key ID formed by
        lowercasing *SUFFIX* and replacing underscores with hyphens.
        """
        prefix = self._prefix
        ids = []
        for var in os.environ:
            if var.upper().startswith(prefix):
                suffix = var[len(prefix):]
                ids.append(suffix.lower().replace("_", "-"))
        return sorted(ids)
