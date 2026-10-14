"""Grab a site's live TLS certificate without trusting DNS twice.

Used by the intel page only when no provider (VirusTotal) already has the certificate. The host is
resolved and validated through the SSRF guard first, the socket connects to that validated IP with
SNI = host, and the leaf certificate is parsed with ``cryptography``. Verification is disabled on
purpose: phishing sites often present broken/self-signed certificates, and we want to *see* them.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from datetime import UTC
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from brandwatch.security.fetcher_guard import resolve_and_validate

TIMEOUT = 6.0


def _name(n: x509.Name) -> str:
    parts = []
    for attr in n:
        short = {NameOID.COMMON_NAME: "CN", NameOID.ORGANIZATION_NAME: "O", NameOID.COUNTRY_NAME: "C",
                 NameOID.ORGANIZATIONAL_UNIT_NAME: "OU", NameOID.LOCALITY_NAME: "L",
                 NameOID.STATE_OR_PROVINCE_NAME: "ST"}.get(attr.oid, attr.oid._name)  # fmt: skip
        parts.append(f"{short}={attr.value}")
    return " ".join(parts)


def parse_certificate(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_list = sans.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_list = []
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = san_list[0] if san_list else ""
    nb = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=UTC)  # fmt: skip
    na = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=UTC)  # fmt: skip
    return {
        "subject": _name(cert.subject),
        "subject_cn": str(cn),
        "issuer": _name(cert.issuer),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "sans": list(san_list),
        "serial": format(cert.serial_number, "x"),
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),  # noqa: S324 - thumbprint, not a security hash
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "public_key_algorithm": type(cert.public_key()).__name__.replace("PublicKey", "").replace("_", ""),
        "fingerprint_sha256_colon": ":".join(f"{b:02x}" for b in cert.fingerprint(hashes.SHA256())),
        "version": str(cert.version).split(".")[-1],
    }  # fmt: skip


def _fetch_sync(host: str, ip: str, port: int) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            info = parse_certificate(der)
            info["tls_version"] = tls.version()
            info["cipher"] = (tls.cipher() or [None])[0]
            return info


async def fetch_certificate(host: str, port: int = 443) -> dict[str, Any]:
    """The live leaf certificate of ``host``: resolved through the SSRF guard (fails closed on
    private/metadata addresses), then one TLS handshake on the validated IP."""
    ips = [str(i) for i in await asyncio.to_thread(resolve_and_validate, host)]
    ip = next((i for i in ips if ":" not in i), ips[0])  # this network's IPv6 is broken
    info = await asyncio.to_thread(_fetch_sync, host, ip, port)
    info["ip"] = ip
    return info
