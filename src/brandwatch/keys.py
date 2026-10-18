"""Provider API keys stored per workspace with envelope encryption (spec §13 "Secrets").

AES-256-GCM per record (``brandwatch.config.secrets.Envelope``); the DEK is wrapped by a KEK.
The KEK comes from ``LOCAL_KEK_B64`` (dev) or a KMS in production; when neither is configured the
KEK is derived from ``SECRET_KEY`` with HKDF so a fresh checkout still works — the README tells
operators to set a real KEK. The associated data binds each ciphertext to its workspace and
provider, so a row copied to another workspace or provider does not decrypt.
Keys are decrypted in memory only, never logged, and shown as ``last4`` only.
"""

from __future__ import annotations

import base64
import uuid

import sqlalchemy as sa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.orm import Session

from brandwatch.config.secrets import Envelope, last4
from brandwatch.config.settings import PROVIDER_KEY_FIELDS, Settings
from brandwatch.db.models import ApiKey
from brandwatch.db.types import utcnow

# secrets that are not provider API keys but are stored the same encrypted way
RESERVED_SECRETS: tuple[str, ...] = ("residential_proxy_password", "webshare_token", "mobile_proxy_password")
KNOWN_PROVIDERS: tuple[str, ...] = tuple(sorted(PROVIDER_KEY_FIELDS))
STORABLE: tuple[str, ...] = KNOWN_PROVIDERS + RESERVED_SECRETS


def kek_bytes(settings: Settings) -> bytes:
    if settings.local_kek_b64:
        raw = base64.b64decode(settings.local_kek_b64.get_secret_value())
        if len(raw) != 32:
            raise ValueError("LOCAL_KEK_B64 must decode to 32 bytes")
        return raw
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"brandwatch-kek-v1", info=b"api-keys"
    ).derive(settings.secret_key.get_secret_value().encode())


def envelope(settings: Settings) -> Envelope:
    return Envelope(kek_bytes(settings))


def _aad(workspace_id: uuid.UUID, provider: str) -> bytes:
    return f"{workspace_id}:{provider}".encode()


def store_key(
    session: Session, workspace_id: uuid.UUID, provider: str, plaintext: str, settings: Settings
) -> ApiKey:
    if provider not in STORABLE:
        raise ValueError(f"unknown provider '{provider}'")
    secret = plaintext.strip()
    if len(secret) < 6:
        raise ValueError("secret looks too short")
    ct, wrapped = envelope(settings).encrypt(secret, aad=_aad(workspace_id, provider))
    row = session.scalars(
        sa.select(ApiKey).where(ApiKey.workspace_id == workspace_id, ApiKey.provider == provider)
    ).first()
    if row is None:
        row = ApiKey(
            workspace_id=workspace_id,
            provider=provider,
            ciphertext=ct,
            dek_wrapped=wrapped,
            last4=last4(secret),
        )
        session.add(row)
    else:
        row.ciphertext, row.dek_wrapped, row.last4 = ct, wrapped, last4(secret)
        row.rotated_at = utcnow()
    session.flush()
    return row


def delete_key(session: Session, workspace_id: uuid.UUID, provider: str) -> bool:
    row = session.scalars(
        sa.select(ApiKey).where(ApiKey.workspace_id == workspace_id, ApiKey.provider == provider)
    ).first()
    if row is None:
        return False
    session.delete(row)
    session.flush()
    return True


def decrypt_key(row: ApiKey, settings: Settings) -> str:
    return envelope(settings).decrypt(
        row.ciphertext, row.dek_wrapped, aad=_aad(row.workspace_id, row.provider)
    )


def provider_ready(session: Session, workspace_id: uuid.UUID, settings: Settings, provider: str) -> bool:
    """Can a scan of this workspace call ``provider``? Demo mode (recorded answers), a key in the environment, or a key
    saved in Settings → API keys (stored per workspace, encrypted). The app-wide registry knows only the environment, so
    pages must ask here — a key saved in the UI used to read as "no key" on the brand page while the scan used it."""
    if settings.demo_mode or settings.provider_key(provider):
        return True
    return session.scalar(sa.select(ApiKey.id).where(ApiKey.workspace_id == workspace_id, ApiKey.provider == provider).limit(1)) is not None


def load_keys(session: Session, workspace_id: uuid.UUID, settings: Settings) -> dict[str, str]:
    """{provider: plaintext} for this workspace — in memory only, for one scan."""
    out: dict[str, str] = {}
    for row in session.scalars(sa.select(ApiKey).where(ApiKey.workspace_id == workspace_id)).all():
        try:
            out[row.provider] = decrypt_key(row, settings)
        except Exception:  # noqa: BLE001 - a key encrypted under a rotated KEK is simply unusable
            continue
    return out
