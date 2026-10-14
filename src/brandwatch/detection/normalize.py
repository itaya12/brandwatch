"""Normalize → Deduplicate → Pre-filter (spec §3 stages 2–4).

* normalize   — pure: DiscoveryHit → NormalizedCandidate (canonical URL, hostname, registrable
                domain, surface). Malformed input is dropped (returns None).
* deduplicate — one DB upsert on the identity ``(brand_id, canonical_url)``; a known candidate
                only gets the new source attached (no re-pipeline).
* pre_filter  — cheap, no network, **fail-open**: whitelist (official / subsidiary / www) → drop,
                everything else → keep.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from brandwatch.db.enums import CandidateState, Surface
from brandwatch.db.models import Candidate, CandidateSource
from brandwatch.db.types import utcnow
from brandwatch.detection.discovery import split_host
from brandwatch.pipeline.stages import (
    DedupResult,
    DiscoveryHit,
    NormalizedCandidate,
    PreFilterResult,
)


def normalize(hit: DiscoveryHit) -> NormalizedCandidate | None:
    raw = hit.raw_value.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or "." not in host:
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    scheme = parts.scheme.lower() if parts.scheme in ("http", "https") else "https"
    path = parts.path or "/"
    if not path.endswith("/") and "." not in path.rsplit("/", 1)[-1]:
        path += "/"
    canonical_url = urlunsplit((scheme, host, path, parts.query, ""))
    reg = split_host(host).registrable
    surface = hit.surface
    if surface is Surface.NAME and reg != host:
        surface = Surface.SUBDOMAIN
    if path not in ("", "/") or parts.query:
        surface = Surface.PATH
    return NormalizedCandidate(
        canonical_domain=reg,
        canonical_url=canonical_url,
        hostname=host,
        surface=surface,
        source=hit.source,
        matched_pattern=hit.matched_pattern,
    )


def deduplicate(session: Session, brand_id: uuid.UUID, cand: NormalizedCandidate) -> DedupResult:
    existing = session.scalars(
        sa.select(Candidate).where(
            Candidate.brand_id == brand_id, Candidate.canonical_url == cand.canonical_url
        )
    ).first()
    is_new = existing is None
    if existing is None:
        existing = Candidate(
            brand_id=brand_id,
            canonical_domain=cand.canonical_domain,
            canonical_url=cand.canonical_url,
            hostname=cand.hostname,
            surface=cand.surface,
            state=CandidateState.NEW,
        )
        session.add(existing)
        session.flush()
    else:
        existing.last_seen = utcnow()

    source_added = False
    has_source = session.scalar(
        sa.select(sa.func.count())
        .select_from(CandidateSource)
        .where(CandidateSource.candidate_id == existing.id, CandidateSource.source == cand.source)
    )
    if not has_source:
        try:
            # add inside the SAVEPOINT: begin_nested() flushes pending rows before it exists, so a
            # raced duplicate added outside it would poison the outer transaction
            with session.begin_nested():
                session.add(
                    CandidateSource(
                        candidate_id=existing.id,
                        source=cand.source,
                        matched_pattern=cand.matched_pattern,
                    )
                )
                session.flush()
            source_added = True
        except IntegrityError:  # raced by a concurrent worker: the DB uniqueness wins
            source_added = False
    return DedupResult(candidate_id=existing.id, is_new=is_new, source_added=source_added)


def whitelist_for(official_domains: Iterable[str], extra: Iterable[str] = ()) -> set[str]:
    out: set[str] = set()
    for d in list(official_domains) + list(extra):
        d = d.lower().strip().rstrip(".")
        if d:
            out.add(d)
            out.add(protected_root(d))
    return out


def protected_root(host: str) -> str:
    """What whitelisting ``host`` protects: its registrable domain (and every subdomain) — except on
    shared hosting, where the registrable domain is the platform: whitelisting
    ``shopnova.github.io`` must not protect ``shopnova-login.github.io``."""
    host = host.lower().strip().rstrip(".")
    if is_shared_hosting(host):
        return host
    return split_host(host).registrable or host


# Big, moderated platforms that show up in brand searches (videos, app-store pages, courses,
# social profiles). They are never the phishing host themselves, so they are not candidates.
KNOWN_PLATFORMS: frozenset[str] = frozenset({
    "youtube.com", "youtu.be", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "wikipedia.org", "udemy.com", "coursera.org", "medium.com",
    "github.com", "tiktok.com", "trustpilot.com", "g2.com", "capterra.com", "producthunt.com",
    "crunchbase.com", "coinmarketcap.com", "coingecko.com", "quora.com", "pinterest.com",
    "twitch.tv", "discord.com", "bing.com", "yahoo.com", "stackoverflow.com", "vimeo.com",
    "spotify.com", "soundcloud.com", "glassdoor.com", "indeed.com", "bbb.org",
})  # fmt: skip
# Hosting platforms where the path / subdomain *is* the site: every distinct URL stays a candidate.
SHARED_HOSTING: frozenset[str] = frozenset({
    "pages.dev", "workers.dev", "github.io", "netlify.app", "vercel.app", "web.app",
    "firebaseapp.com", "weebly.com", "wixsite.com", "blogspot.com", "sites.google.com",
    "notion.site", "webflow.io", "glitch.me", "repl.co", "replit.app", "s3.amazonaws.com",
    "azurewebsites.net", "herokuapp.com", "cloudfront.net", "surge.sh", "onrender.com",
    "000webhostapp.com", "godaddysites.com", "square.site", "carrd.co", "mystrikingly.com",
    "typeform.com", "jotform.com", "wordpress.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
})  # fmt: skip


# App stores and APK mirrors: a listing that carries the brand's name is a classic impersonation
# vector (fake wallet / trading apps). Every listing URL is examined on its own; the official
# app listings linked from the brand's own site are learned at baseline time and skipped.
APP_STORES: frozenset[str] = frozenset({
    "apps.apple.com", "play.google.com", "apps.microsoft.com", "chromewebstore.google.com",
    "chrome.google.com", "addons.mozilla.org", "galaxystore.samsung.com", "appgallery.huawei.com",
    "f-droid.org", "apkpure.com", "apkpure.net", "apkmirror.com", "aptoide.com", "uptodown.com",
    "apkcombo.com", "apk.support", "apkmonk.com", "softonic.com", "apkdone.com", "apksum.com",
    "apk-dl.com", "androidapksfree.com", "apps.samsung.com", "getjar.com", "9apps.com",
    "appbrain.com", "apkfab.com", "happymod.com", "modapk.com",
})  # fmt: skip


def is_app_store(hostname: str) -> bool:
    return _under(hostname, APP_STORES)


def canonical_listing_url(url: str) -> str:
    """Comparable form of an app-store listing URL: no scheme, no fragment, no tracking query;
    only an ``id=`` parameter (Google Play's listing identity) is kept."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/")
    ident = next((v for k, v in parse_qsl(parts.query) if k == "id"), None)
    return f"{host}{path}" + (f"?id={ident}" if ident else "")


def _under(host: str, domains: frozenset[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def is_known_platform(hostname: str) -> bool:
    return _under(hostname, KNOWN_PLATFORMS)


def is_shared_hosting(hostname: str) -> bool:
    return _under(hostname, SHARED_HOSTING)


def pre_filter(hostname: str, whitelist: set[str]) -> PreFilterResult:
    host = hostname.lower().rstrip(".")
    for allowed in whitelist:
        if host == allowed or host.endswith("." + allowed):
            return PreFilterResult(keep=False, reason="whitelisted")
    return PreFilterResult(keep=True, reason="keep")  # fail-open
