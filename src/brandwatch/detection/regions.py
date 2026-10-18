"""Regional campaigns of a global brand: a main brand and one child brand per country site.

    The North Face            thenorthface.com            (the main brand)
      ├─ The North Face · Israel      thenorthface.co.il      country IL, Hebrew queries, ILS prices
      └─ The North Face · Germany     thenorthface.de         …

A region is an ordinary brand — its own domains, fingerprint, Google queries, prices, ads countries and
schedule — so a kit that copies the Hebrew site is compared with the Hebrew site. What the **family**
(the main brand and all its regions) shares is protection: no member can flag another member's site
(``family_domains``), and one suspect becomes one finding, not one per region (``tracked_elsewhere``).

A small company with a single multilingual site needs none of this: one brand with several countries.

Country sites are *suggested* from the official homepage (``country_sites``: hreflang tags and links to
sites that carry the brand's name) and added only when the analyst confirms.
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlsplit

import sqlalchemy as sa
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from brandwatch.db.enums import FindingState
from brandwatch.db.models import Brand, BrandDomain, Candidate, Finding
from brandwatch.detection.discovery import split_host

# country-code TLD → ISO country (the ones a brand's country sites actually use)
CCTLD_COUNTRY = {"il": "IL", "uk": "GB", "gb": "GB", "de": "DE", "fr": "FR", "es": "ES", "it": "IT", "nl": "NL",
                 "au": "AU", "ca": "CA", "br": "BR", "pl": "PL", "ru": "RU", "jp": "JP", "se": "SE", "no": "NO",
                 "dk": "DK", "fi": "FI", "ch": "CH", "at": "AT", "be": "BE", "pt": "PT", "ie": "IE", "nz": "NZ",
                 "mx": "MX", "ar": "AR", "tr": "TR", "gr": "GR", "cz": "CZ", "hu": "HU", "ro": "RO", "kr": "KR",
                 "cn": "CN", "in": "IN", "za": "ZA", "ae": "AE", "sa": "SA", "sg": "SG", "hk": "HK", "tw": "TW"}  # fmt: skip
COUNTRY_NAMES = {"IL": "Israel", "US": "USA", "GB": "United Kingdom", "DE": "Germany", "FR": "France", "ES": "Spain",
                 "IT": "Italy", "NL": "Netherlands", "AU": "Australia", "CA": "Canada", "BR": "Brazil", "PL": "Poland",
                 "RU": "Russia", "JP": "Japan", "SE": "Sweden", "NO": "Norway", "DK": "Denmark", "FI": "Finland",
                 "CH": "Switzerland", "AT": "Austria", "BE": "Belgium", "PT": "Portugal", "IE": "Ireland",
                 "NZ": "New Zealand", "MX": "Mexico", "AR": "Argentina", "TR": "Turkey", "GR": "Greece",
                 "CZ": "Czechia", "HU": "Hungary", "RO": "Romania", "KR": "South Korea", "CN": "China", "IN": "India",
                 "ZA": "South Africa", "AE": "UAE", "SA": "Saudi Arabia", "SG": "Singapore", "HK": "Hong Kong",
                 "TW": "Taiwan"}  # fmt: skip
COUNTRY_LANG = {"IL": "he", "DE": "de", "FR": "fr", "ES": "es", "IT": "it", "NL": "nl", "BR": "pt", "PT": "pt",
                "PL": "pl", "RU": "ru", "JP": "ja", "SE": "sv", "NO": "no", "DK": "da", "FI": "fi", "AT": "de",
                "CH": "de", "TR": "tr", "GR": "el", "CZ": "cs", "HU": "hu", "RO": "ro", "KR": "ko", "CN": "zh",
                "AE": "ar", "SA": "ar", "MX": "es", "AR": "es"}  # fmt: skip

# settings a region starts from (copied once from the main brand; the analyst can re-copy them)
INHERITED_PROFILE_KEYS = ("ad_keywords", "ads_per_search", "ad_searches_max", "shops_checked_max", "official_social")


# ------------------------------------------------------------------------------------ the family
def root_of(session: Session, brand: Brand) -> Brand:
    seen: set[uuid.UUID] = set()
    while brand.parent_id and brand.id not in seen:
        seen.add(brand.id)
        parent = session.get(Brand, brand.parent_id)
        if parent is None:
            break
        brand = parent
    return brand


def family_ids(session: Session, brand_id: uuid.UUID) -> list[uuid.UUID]:
    """The brand's whole family: the main brand and every region, whichever member is asked about
    (a brand without regions is a family of one)."""
    brand = session.get(Brand, brand_id)
    if brand is None:
        return [brand_id]
    root = root_of(session, brand)
    out = [root.id]
    frontier = [root.id]
    while frontier:
        kids = list(session.scalars(sa.select(Brand.id).where(Brand.parent_id.in_(frontier))).all())
        kids = [k for k in kids if k not in out]
        out += kids
        frontier = kids
    return out


def with_regions(session: Session, brand_id: uuid.UUID) -> list[uuid.UUID]:
    """What a "this brand" filter covers: the brand and every region below it (a region covers itself only)."""
    out = [brand_id]
    frontier = [brand_id]
    while frontier:
        kids = [k for k in session.scalars(sa.select(Brand.id).where(Brand.parent_id.in_(frontier))).all() if k not in out]
        out += kids
        frontier = kids
    return out


def regions_of(session: Session, brand_id: uuid.UUID) -> list[Brand]:
    return list(session.scalars(sa.select(Brand).where(Brand.parent_id == brand_id).order_by(Brand.created_at)).all())


def family_domains(session: Session, brand_id: uuid.UUID) -> list[str]:
    """Every domain (official, alias, whitelisted) of every member of the family — what no member may flag."""
    ids = family_ids(session, brand_id)
    return list(session.scalars(sa.select(BrandDomain.domain).where(BrandDomain.brand_id.in_(ids)).order_by(BrandDomain.domain)).all())


def tracked_elsewhere(session: Session, brand_id: uuid.UUID, canonical_url: str) -> Brand | None:
    """The other family member that already tracks this suspect with an open or confirmed finding —
    one suspect, one finding per family."""
    others = [i for i in family_ids(session, brand_id) if i != brand_id]
    if not others:
        return None
    row = session.execute(
        sa.select(Brand)
        .join(Candidate, Candidate.brand_id == Brand.id)
        .join(Finding, Finding.candidate_id == Candidate.id)
        .where(Candidate.brand_id.in_(others), Candidate.canonical_url == canonical_url,
               Finding.state.in_([FindingState.OPEN, FindingState.CONFIRMED]))
        .limit(1)
    ).first()  # fmt: skip
    return row[0] if row else None


def region_name(parent: Brand, region: str) -> str:
    return f"{parent.name} · {region}"[:200]


# ------------------------------------------------------------------------------------ creating a region
def guess_country(domain: str) -> str | None:
    suffix = (split_host(domain).suffix or "").split(".")[-1]
    return CCTLD_COUNTRY.get(suffix)


def inherit(parent: Brand, child_profile: dict[str, Any] | None, countries: list[str]) -> dict[str, Any]:
    """The child's profile: its own countries and the parent's product prices for them, plus the settings
    in ``INHERITED_PROFILE_KEYS``. Whatever the child already has (queries, its own prices) is kept."""
    pp = dict(parent.profile or {})
    prof = dict(child_profile or {})
    for k in INHERITED_PROFILE_KEYS:
        if k in pp:
            prof[k] = pp[k]
    prof["countries"] = list(countries)
    mine = {(p.get("name"), p.get("country")) for p in prof.get("products") or []}
    rows = [p for p in pp.get("products") or [] if p.get("country") in countries and (p.get("name"), p.get("country")) not in mine]
    prof["products"] = [*(prof.get("products") or []), *rows]
    return prof


# ------------------------------------------------------------------------------------ country sites
_LANG_COUNTRY = re.compile(r"^[a-z]{2,3}[-_]([a-z]{2})$", re.I)


def _label_has_brand(host: str, brand_key: str) -> bool:
    parts = split_host(host)
    return bool(brand_key) and len(brand_key) >= 4 and brand_key in re.sub(r"[^a-z0-9]", "", parts.sld.lower())


def country_sites(html: str | None, base_url: str, brand_key: str, official: set[str]) -> list[dict[str, Any]]:
    """The brand's other country sites, read from the official homepage: ``<link rel="alternate"
    hreflang>`` and links to a different registrable domain whose name carries the brand
    (thenorthface.co.il, thenorthface.de). Never the official domains themselves. A domain that
    carries the brand but names no country (thenorthface-help.com) is not a country site: it is an
    *other official site*, listed by ``site_links`` and decided there."""
    if not html or not brand_key:
        return []
    soup = BeautifulSoup(html, "html.parser")
    base_reg = split_host(urlsplit(base_url).hostname or "").registrable
    own = {split_host(d).registrable for d in official} | {base_reg}
    found: dict[str, dict[str, Any]] = {}

    def add(href: str, hreflang: str | None) -> None:
        url = urljoin(base_url, (href or "").strip())
        host = (urlsplit(url).hostname or "").lower()
        if not host or urlsplit(url).scheme not in ("http", "https"):
            return
        reg = split_host(host).registrable
        if not reg or reg in own or not _label_has_brand(host, brand_key):
            return
        country = None
        if hreflang:
            m = _LANG_COUNTRY.match(hreflang.strip())
            country = m.group(1).upper() if m else None
        country = country or guess_country(reg)
        if not country:
            return
        row = found.setdefault(reg, {"domain": reg, "hreflang": None, "country": None})
        row["hreflang"] = row["hreflang"] or (hreflang or None)
        row["country"] = row["country"] or country

    for link in soup.find_all("link", attrs={"rel": re.compile("alternate", re.I)}):
        if link.get("hreflang") and link.get("href"):
            add(str(link["href"]), str(link["hreflang"]))
    for a in soup.find_all("a", href=True):
        add(str(a["href"]), str(a.get("hreflang") or "") or None)
    out = sorted(found.values(), key=lambda r: r["domain"])
    for r in out:
        r["region"] = COUNTRY_NAMES.get(r["country"] or "", "") or (r["country"] or "")
    return out[:30]
