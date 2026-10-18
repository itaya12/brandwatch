"""Every link from the brand's official homepage to another site, sorted into what it is.

The fingerprint already keeps three narrow lists (its Facebook / Instagram accounts, its app listings, its
country sites). This module keeps the whole picture so the analyst can decide about each link once:

* ``country_site``  — the brand on a country domain (thenorthface.co.il, hreflang alternates)
* ``official_site`` — another site of the brand: a domain that carries its name (shopnova-help.com), or the
                      brand's own corner of a service platform (shopnova.zendesk.com, status.shopnova.io)
* ``social``        — an account on a social platform (Facebook, Instagram, X, TikTok, YouTube, LinkedIn,
                      Telegram, WhatsApp, Pinterest, Threads, Discord, Reddit, GitHub)
* ``app``           — an app-store listing
* ``other``         — anything else the homepage links to (a payment provider, a partner, a news site)

Nothing here is added to the brand by itself: the brand page shows the list and the analyst chooses.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

from bs4 import BeautifulSoup

from brandwatch.detection.discovery import split_host
from brandwatch.detection.normalize import is_app_store
from brandwatch.detection.regions import COUNTRY_NAMES, guess_country
from brandwatch.detection.social import parse_profile_url

MAX_LINKS = 60
KINDS = ("country_site", "official_site", "social", "app", "other")

# host (registrable) → platform; the handle is read from the path by _social_handle
SOCIAL_HOSTS = {
    "facebook.com": "facebook", "fb.com": "facebook", "instagram.com": "instagram", "x.com": "x", "twitter.com": "x",
    "tiktok.com": "tiktok", "youtube.com": "youtube", "youtu.be": "youtube", "linkedin.com": "linkedin",
    "t.me": "telegram", "telegram.me": "telegram", "wa.me": "whatsapp", "whatsapp.com": "whatsapp",
    "pinterest.com": "pinterest", "threads.net": "threads", "threads.com": "threads", "discord.gg": "discord",
    "discord.com": "discord", "reddit.com": "reddit", "github.com": "github", "snapchat.com": "snapchat",
}  # fmt: skip
PLATFORM_LABEL = {"facebook": "Facebook", "instagram": "Instagram", "x": "X (Twitter)", "tiktok": "TikTok", "youtube": "YouTube",
                  "linkedin": "LinkedIn", "telegram": "Telegram", "whatsapp": "WhatsApp", "pinterest": "Pinterest",
                  "threads": "Threads", "discord": "Discord", "reddit": "Reddit", "github": "GitHub", "snapchat": "Snapchat"}  # fmt: skip
# paths that are a share button or a page of the platform itself, never an account
_NOT_ACCOUNT = re.compile(r"^/(share|sharer|intent|home|search|explore|watch|hashtag|login|signup|help|legal|privacy|terms|"
                          r"policies|about|settings|i/|dialog|plugins|embed|oembed)", re.I)  # fmt: skip
_LANG_COUNTRY = re.compile(r"^[a-z]{2,3}[-_]([a-z]{2})$", re.I)


def _brand_in(text: str, brand_key: str) -> bool:
    return bool(brand_key) and len(brand_key) >= 4 and brand_key in re.sub(r"[^a-z0-9]", "", text.lower())


def _social_handle(platform: str, url: str) -> str | None:
    """The account a link points to (``"shopnova"``), or None for a share button / a post / the platform's own page."""
    parts = urlsplit(url)
    path = parts.path or "/"
    if platform in ("facebook", "instagram"):
        parsed = parse_profile_url(url)
        return parsed[1] if parsed else None
    if _NOT_ACCOUNT.match(path):
        return None
    segs = [s for s in path.split("/") if s]
    if platform == "youtube":
        if segs and segs[0].startswith("@"):
            return segs[0].lower()
        if len(segs) >= 2 and segs[0] in ("c", "channel", "user"):
            return segs[1]
        return None
    if platform == "linkedin":
        return f"{segs[0]}/{segs[1]}".lower() if len(segs) >= 2 and segs[0] in ("company", "in", "school", "showcase") else None
    if platform == "reddit":
        return f"{segs[0]}/{segs[1]}".lower() if len(segs) >= 2 and segs[0] in ("r", "u", "user") else None
    if platform == "whatsapp":
        phone = segs[0] if segs else (parse_qs(parts.query).get("phone") or [""])[0]
        return re.sub(r"\D", "", phone) or None
    if platform == "discord":
        invite = (parts.hostname or "").endswith("discord.gg") or (len(segs) >= 2 and segs[0] == "invite")
        return segs[-1] if segs and invite else None
    return segs[0].lstrip("@").lower() if segs and re.fullmatch(r"@?[A-Za-z0-9._\-]{1,60}", segs[0]) else None


def _classify(url: str, text: str, hreflang: str | None, brand_key: str, own: set[str]) -> dict[str, Any] | None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https") or not host:
        return None
    sh = split_host(host)
    reg = sh.registrable or host
    if reg in own or host in own:
        return None  # a link to the brand's own site
    platform = SOCIAL_HOSTS.get(reg) or SOCIAL_HOSTS.get(host)
    row: dict[str, Any] = {"url": url, "host": host, "domain": reg, "text": text[:80]}
    if platform:
        handle = _social_handle(platform, url)
        if not handle:
            return None  # a share button or a post: not an account
        return {**row, "kind": "social", "platform": platform, "platform_label": PLATFORM_LABEL.get(platform, platform),
                "handle": handle, "key": f"social:{platform}:{handle}"}  # fmt: skip
    if is_app_store(host):
        return {**row, "kind": "app", "key": f"app:{url.split('?')[0].lower()}"}
    country = None
    if hreflang:
        m = _LANG_COUNTRY.match(hreflang.strip())
        country = m.group(1).upper() if m else None
    if _brand_in(sh.sld or "", brand_key):
        country = country or guess_country(reg)
        if country:
            return {**row, "kind": "country_site", "country": country, "hreflang": hreflang or None,
                    "region": COUNTRY_NAMES.get(country or "", "") or (country or ""), "key": f"site:{reg}"}  # fmt: skip
        return {**row, "kind": "official_site", "why": "the domain carries the brand's name", "key": f"site:{reg}"}
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    if sub and _brand_in(sub, brand_key):
        # shopnova.zendesk.com, shopnova.myshopify.com: the brand's own corner of a service platform, linked from its own site
        return {**row, "domain": host, "kind": "official_site", "why": f"the brand's own page on {reg}", "key": f"site:{host}"}
    return {**row, "kind": "other", "key": f"site:{reg}"}


def external_links(html: str | None, base_url: str, brand_key: str, official: set[str]) -> list[dict[str, Any]]:
    """Every distinct link from the homepage to another site, classified (see the module docstring).
    One row per account or per domain, with how many times the page links to it."""
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    base_reg = split_host(urlsplit(base_url).hostname or "").registrable
    own = {split_host(d).registrable for d in official if d} | {d.lower() for d in official if d} | {base_reg}
    found: dict[str, dict[str, Any]] = {}

    def add(href: str, text: str, hreflang: str | None) -> None:
        url = urljoin(base_url, (href or "").strip())
        row = _classify(url, " ".join(text.split()), hreflang, brand_key, own)
        if row is None:
            return
        if row["key"] in found:
            found[row["key"]]["count"] += 1
            if not found[row["key"]].get("text") and row.get("text"):
                found[row["key"]]["text"] = row["text"]
            return
        found[row["key"]] = {**row, "count": 1}

    for link in soup.find_all("link", attrs={"rel": re.compile("alternate", re.I)}):
        if link.get("hreflang") and link.get("href"):
            add(str(link["href"]), "", str(link["hreflang"]))
    for a in soup.find_all("a", href=True):
        add(str(a["href"]), a.get_text(" ", strip=True) or str(a.get("aria-label") or a.get("title") or ""), str(a.get("hreflang") or "") or None)
    order = {k: i for i, k in enumerate(KINDS)}
    rows = sorted(found.values(), key=lambda r: (order[r["kind"]], -r["count"], r["key"]))
    return rows[:MAX_LINKS]
