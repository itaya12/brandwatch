"""What kind of network an address belongs to: a CDN, a big cloud, or a hoster.

Two sites on the same CloudFront or Cloudflare address say nothing about each other: thousands of unrelated sites sit behind the
same few addresses. Two sites on the same server of a big cloud (AWS, Azure, DigitalOcean …) say a little, because anyone can rent a
machine there. Two sites on the same small hoster's server (Gransy, Alexhost …) say a lot. The name of the network comes from what the
investigation already stored (VirusTotal's ``as_owner``, or the geolocation ``org``); nothing is fetched here.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Any

from sqlalchemy.orm import Session

CDN = re.compile(r"cloudflare|cloudfront|akamai(?!.*(linode|connected cloud))|fastly|incapsula|imperva|sucuri|bunny|vercel|netlify|github|stackpath|edgecast|"
                 r"azure front ?door|google(?!.*cloud)|gcore|cdn77|keycdn|limelight|edgio|cachefly|quic\.cloud|ddos-guard|stormwall", re.I)
CLOUD = re.compile(r"amazon|aws|ec2|google.*cloud|gcp|microsoft|azure|digitalocean|ovh|hetzner|linode|vultr|oracle|alibaba|tencent|"
                   r"scaleway|connected cloud|contabo|leaseweb|choopa|m247|namecheap|hostinger|godaddy|squarespace|wix|shopify|wpengine|bluehost|siteground", re.I)
KIND = {"cdn": "a CDN (thousands of unrelated sites share its addresses)", "cloud": "a big cloud (anyone can rent a machine there)", "hoster": "a hoster",
        "unknown": "a network nobody has looked up yet"}  # fmt: skip


def classify(org: str | None) -> str:
    """``"cdn"``, ``"cloud"``, ``"hoster"`` (a small, specific network) or ``"unknown"`` (nothing is stored about the address yet)."""
    org = (org or "").strip()
    if not org:
        return "unknown"
    if CDN.search(org):
        return "cdn"
    if CLOUD.search(org):
        return "cloud"
    return "hoster"


def org_of(session: Session, workspace_id: uuid.UUID, ip: str, cache: dict[str, str | None] | None = None) -> str | None:
    """The network's name for an address, from the cached investigation (VirusTotal, then geolocation)."""
    from brandwatch.detection import intel as intel_mod

    if cache is not None and ip in cache:
        return cache[ip]
    rows = intel_mod.rows_for(session, workspace_id, "ip", ip)
    vt, geo = rows.get("virustotal/report"), rows.get("geo/report")
    org = ((((vt.payload or {}).get("attributes") or {}).get("as_owner")) if vt is not None and vt.status == "ok" else None) or (
        (geo.payload or {}).get("org") if geo is not None and geo.status == "ok" else None)  # fmt: skip
    if cache is not None:
        cache[ip] = org
    return org


def ip_class(session: Session, workspace_id: uuid.UUID, ip: str, cache: dict[str, str | None] | None = None) -> tuple[str, str | None]:
    """(class, network name) of an address. Cloudflare's own published ranges are a CDN even before anything was investigated."""
    from brandwatch.detection.enrichment import _on_cloudflare

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "unknown", None
    org = org_of(session, workspace_id, ip, cache)
    if _on_cloudflare([ip]):
        return "cdn", org or "Cloudflare"
    return classify(org), org


def is_cdn(org: str | None, ip: str | None = None) -> bool:
    """A CDN / anycast edge: the address is answered by the node nearest to whoever asks, so its geolocation is the asker's neighbourhood
    (a visit from Tel Aviv gets Tel Aviv), never the place the site is hosted."""
    if classify(org) == "cdn":
        return True
    if ip:
        from brandwatch.detection.enrichment import _on_cloudflare

        return _on_cloudflare([ip])
    return False


def describe(cls: str) -> str:
    return KIND.get(cls, cls)


def summary(counts: dict[str, Any]) -> str:  # a one-line "hosted on …" for a card
    return ", ".join(f"{k} ({v})" for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
