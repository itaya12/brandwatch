"""Recorded WHOIS histories for the demo, in the exact record shape of WhoisXML's WHOIS History
API (``records[]`` with ``createdDateISO8601``, ``audit``, ``registrarName``, ``registrantContact``,
``nameServers``, ``rawText`` …), so the demo and live mode run the same parser.

Dates are relative to today, so the stories stay consistent with the recorded scenarios' domain
ages. All people, companies, e-mail domains and phone numbers are fictional (``.example``
domains, UK drama-range phone numbers).

The stories an interviewer sees:
- shopnova-giftcard.com / shopnova-refund.net: registered with the owner's real details, privacy
  switched on a day later; the same e-mail sits in both histories → one operator behind two kits.
- shopn0va.com: an aged domain that expired, was dropped and re-registered three days ago.
- shopnova-support-center.com: registered at a cheap registrar, then transferred.
- shopnova-blog.net: the brand's own blog, owned by ShopNova Inc. for years (legitimacy evidence).
Any other domain gets a single snapshot built from its recorded WHOIS.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

PRIVACY = {"name": "REDACTED FOR PRIVACY", "organization": "Privacy service provided by WhoisProxy (demo)",
           "email": "redacted-contact@whoisproxy.example", "country": "IS", "city": "Reykjavik"}  # fmt: skip
JM = {"name": "Jordan Marlow", "organization": "JM Digital Media", "email": "jm.digital.media@mailbox.example",
      "telephone": "+44.7700900123", "country": "GB", "city": "Leeds", "street": "14 Albion Street (demo)"}  # fmt: skip
NOVA_SUPPLIES = {"name": "Dana Whitfield", "organization": "Nova Shop Supplies", "email": "dana@novashopsupplies.example",
                 "country": "US", "city": "Portland", "state": "OR"}  # fmt: skip
KITOPS = {"email": "kitops@proton.example", "country": "PA"}
SHOPNOVA_INC = {
    "organization": "ShopNova Inc.",
    "email": "domains@shopnova.com",
    "country": "US",
    "city": "Austin",
    "state": "TX",
}
NS_MOCK = ["ns1.mock-dns.example", "ns2.mock-dns.example"]
NS_OLD = ["ns1.parking-host.example", "ns2.parking-host.example"]

# snapshot specs: days ago seen · days ago created · days until expiry (from today) · registrar · registrant · NS
STORIES: dict[str, list[dict[str, Any]]] = {
    "shopnova-giftcard.com": [
        {"seen": 4, "created": 4, "expires": 361, "registrar": "Mock Registrar LLC", "registrant": JM, "ns": NS_MOCK},
        {"seen": 3, "created": 4, "expires": 361, "registrar": "Mock Registrar LLC", "registrant": PRIVACY, "ns": NS_MOCK},
        {"seen": 1, "created": 4, "expires": 361, "registrar": "Mock Registrar LLC", "registrant": PRIVACY, "ns": NS_MOCK},
    ],
    "shopnova-refund.net": [
        {"seen": 9, "created": 9, "expires": 356, "registrar": "Mock Registrar LLC", "registrant": {**JM, "name": "J. Marlow"}, "ns": NS_MOCK},
        {"seen": 8, "created": 9, "expires": 356, "registrar": "Mock Registrar LLC", "registrant": PRIVACY, "ns": NS_MOCK},
    ],
    "shopn0va.com": [
        {"seen": 2200, "created": 2400, "expires": -2035, "registrar": "Legacy Names Inc. (demo)", "registrant": NOVA_SUPPLIES, "ns": NS_OLD},
        {"seen": 900, "created": 2400, "expires": -35, "registrar": "Legacy Names Inc. (demo)", "registrant": NOVA_SUPPLIES, "ns": NS_OLD},
        {"seen": 3, "created": 3, "expires": 362, "registrar": "Mock Registrar LLC", "registrant": KITOPS, "ns": NS_OLD},
        {"seen": 2, "created": 3, "expires": 362, "registrar": "Mock Registrar LLC", "registrant": KITOPS, "ns": NS_MOCK},
    ],
    "shopnova-support-center.com": [
        {"seen": 25, "created": 25, "expires": 340, "registrar": "Cheap Names Ltd (demo)", "registrant": PRIVACY, "ns": NS_OLD},
        {"seen": 12, "created": 25, "expires": 340, "registrar": "Mock Registrar LLC", "registrant": PRIVACY, "ns": NS_MOCK},
    ],
    "shopnova-blog.net": [
        {"seen": 1190, "created": 1200, "expires": -835, "registrar": "Legacy Names Inc. (demo)", "registrant": SHOPNOVA_INC, "ns": NS_OLD},
        {"seen": 830, "created": 1200, "expires": -470, "registrar": "Legacy Names Inc. (demo)", "registrant": SHOPNOVA_INC, "ns": NS_OLD},
        {"seen": 400, "created": 1200, "expires": 260, "registrar": "Mock Registrar LLC", "registrant": SHOPNOVA_INC, "ns": NS_MOCK},
    ],
}  # fmt: skip


def _contact(c: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "name",
        "organization",
        "street",
        "city",
        "state",
        "postalCode",
        "country",
        "email",
        "telephone",
        "fax",
    )
    out = {k: c.get(k, "") for k in keys}
    out["rawText"] = "\n".join(f"{k}: {v}" for k, v in out.items() if v)
    return out


def _record(domain: str, today: date, spec: dict[str, Any]) -> dict[str, Any]:
    seen = today - timedelta(days=spec["seen"])
    created = today - timedelta(days=spec["created"])
    expires = today + timedelta(days=spec["expires"])
    reg = _contact(spec["registrant"])
    raw = "\n".join([
        f"Domain Name: {domain.upper()}", f"Registrar: {spec['registrar']}",
        f"Creation Date: {created.isoformat()}T00:00:00Z", f"Updated Date: {seen.isoformat()}T00:00:00Z",
        f"Registry Expiry Date: {expires.isoformat()}T00:00:00Z",
        *(f"Registrant {k.capitalize()}: {v}" for k, v in spec["registrant"].items()),
        *(f"Name Server: {n.upper()}" for n in spec["ns"]),
    ])  # fmt: skip
    return {
        "domainName": domain, "domainType": "added",
        "createdDateISO8601": f"{created.isoformat()}T00:00:00Z", "updatedDateISO8601": f"{seen.isoformat()}T00:00:00Z",
        "expiresDateISO8601": f"{expires.isoformat()}T00:00:00Z",
        "createdDateRaw": created.isoformat(), "updatedDateRaw": seen.isoformat(), "expiresDateRaw": expires.isoformat(),
        "audit": {"createdDate": f"{seen.isoformat()} 00:00:00 UTC", "updatedDate": f"{seen.isoformat()} 00:00:00 UTC"},
        "registrarName": spec["registrar"], "whoisServer": "whois.mock-registrar.example",
        "nameServers": list(spec["ns"]), "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
        "registrantContact": reg, "administrativeContact": reg, "technicalContact": _contact(PRIVACY),
        "rawText": raw, "cleanText": raw,
    }  # fmt: skip


def records_for(domain: str, whois: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """The WhoisXML-shaped history of ``domain``: a recorded story, or one snapshot from its WHOIS."""
    today = datetime.now(UTC).date()
    domain = domain.lower()
    if domain in STORIES:
        return [_record(domain, today, spec) for spec in STORIES[domain]]
    if not whois:
        return []
    age = int(whois.get("age_days") or 0)
    reg = whois.get("registrant") or {}
    contact = {
        "organization": reg.get("org") or "",
        "name": reg.get("name") or "",
        "email": reg.get("email") or "",
    }
    if not any(contact.values()):
        contact = PRIVACY
    spec = {"seen": max(age - 1, 0), "created": age, "expires": 365 - age % 365, "registrar": whois.get("registrar") or "Mock Registrar LLC",
            "registrant": contact, "ns": NS_MOCK}  # fmt: skip
    return [_record(domain, today, spec)]
