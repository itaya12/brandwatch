"""Secrets handling (spec §13).

* ``SecretStore`` — where secrets come from at runtime (env in dev; keyring / KMS later).
* ``Envelope``    — envelope encryption for stored API keys: AES-256-GCM with a per-record DEK,
                    the DEK wrapped by a KEK. ``api_keys(ciphertext, dek_wrapped, last4)``.
* ``mask``        — the only form a secret ever takes in logs or the UI (``sk-…a4f2``).
* ``RedactingFilter`` — logging filter that blanks known secret values.

Local dev: KEK from ``LOCAL_KEK_B64``. Production: the KEK is held by a KMS / secrets manager and
``Envelope`` is constructed from it; the hook is the same.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12
_KEY_LEN = 32


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...


class EnvSecretStore:
    """Reads secrets from environment variables (dev / CI)."""

    def get(self, name: str) -> str | None:
        value = os.environ.get(name)
        return value.strip() if value and value.strip() else None


def mask(secret: str, visible: int = 4) -> str:
    """``sk-abcdef...a4f2`` → ``sk-…a4f2``. Short secrets collapse to ``…``."""
    if not secret or len(secret) <= visible:
        return "…"
    prefix = ""
    head = secret[:5]
    if "-" in head:
        prefix = secret[: head.index("-") + 1]
    return f"{prefix}…{secret[-visible:]}"


def last4(secret: str) -> str:
    return secret[-4:] if len(secret) >= 4 else "…"


class Envelope:
    """AES-256-GCM envelope encryption. ``kek`` must be 32 bytes."""

    def __init__(self, kek: bytes) -> None:
        if len(kek) != _KEY_LEN:
            raise ValueError("KEK must be exactly 32 bytes (AES-256)")
        self._kek = AESGCM(kek)

    @classmethod
    def from_b64(cls, kek_b64: str) -> Envelope:
        return cls(base64.b64decode(kek_b64))

    @classmethod
    def generate_kek_b64(cls) -> str:
        return base64.b64encode(os.urandom(_KEY_LEN)).decode("ascii")

    def encrypt(self, plaintext: str, *, aad: bytes = b"") -> tuple[bytes, bytes]:
        """Return ``(ciphertext, dek_wrapped)``; each blob is ``nonce || gcm_output``."""
        dek = os.urandom(_KEY_LEN)
        nonce = os.urandom(_NONCE_LEN)
        ciphertext = nonce + AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad)
        wrap_nonce = os.urandom(_NONCE_LEN)
        dek_wrapped = wrap_nonce + self._kek.encrypt(wrap_nonce, dek, aad)
        return ciphertext, dek_wrapped

    def decrypt(self, ciphertext: bytes, dek_wrapped: bytes, *, aad: bytes = b"") -> str:
        dek = self._kek.decrypt(dek_wrapped[:_NONCE_LEN], dek_wrapped[_NONCE_LEN:], aad)
        plain = AESGCM(dek).decrypt(ciphertext[:_NONCE_LEN], ciphertext[_NONCE_LEN:], aad)
        return plain.decode("utf-8")


class RedactingFilter(logging.Filter):
    """Replaces every known secret value in log records with ``***``."""

    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        self._secrets = sorted({s for s in secrets if s}, key=len, reverse=True)

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secrets:
            msg = record.getMessage()
            redacted = msg
            for s in self._secrets:
                redacted = redacted.replace(s, "***")
            if redacted != msg:
                record.msg = redacted
                record.args = ()
        return True
