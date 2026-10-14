"""Did the official site let BrandWatch in?

Every comparison starts from the brand's own site: its favicon, its screenshot, its colours, its login
form. When that site answers 403 "Access Denied" (Akamai, Cloudflare, Imperva, DataDome … refusing a
scanner), the page BrandWatch received is the *block page*, and a fingerprint built from it is worse than
none: candidates would be compared with an "Access Denied" screenshot, and the words "access" and "denied"
became the brand's keywords.

``assess`` classifies the answer so the baseline can refuse to learn from a block page, and so the analyst
is told — in the scan console, on the brand page, before the first scan — and shown what can be done.

BrandWatch does not solve CAPTCHAs or disguise itself as a person to get past a bot check; the remedies
are legitimate ones: another IP (the residential proxy), another official page of the same brand, and
pictures the analyst supplies.
"""

from __future__ import annotations

import re
from typing import Any

from brandwatch.detection.html import is_bot_challenge, is_cloudflare_phish_warning

PHRASES = {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 406: "Not Acceptable",
           410: "Gone", 429: "Too Many Requests", 451: "Unavailable For Legal Reasons", 500: "Server Error",
           502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"}  # fmt: skip

# a soft block: 200 OK, but the page says no
_BLOCK_TITLE = re.compile(
    r"access\s+denied|forbidden|request\s+blocked|you\s+have\s+been\s+blocked|are\s+you\s+a\s+(?:robot|human)|"
    r"captcha|unusual\s+traffic|pardon\s+our\s+interruption|error\s+403|403\s+error|blocked\s+by", re.I)

VENDORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Akamai", re.compile(r"errors\.edgesuite\.net|akamai|reference\s*#\s*\d+\.[0-9a-f]+", re.I)),
    ("Cloudflare", re.compile(r"cloudflare|cf-ray|cdn-cgi|just a moment|attention required", re.I)),
    ("Imperva / Incapsula", re.compile(r"incapsula|imperva|_incapsula_resource", re.I)),
    ("PerimeterX / HUMAN", re.compile(r"perimeterx|px-captcha|press\s*&?\s*hold", re.I)),
    ("DataDome", re.compile(r"datadome|dd_cookie_test", re.I)),
    ("AWS WAF", re.compile(r"aws\s*waf|awswaf", re.I)),
    ("Sucuri", re.compile(r"sucuri", re.I)),
)


def vendor_of(title: str | None, html: str | None) -> str | None:
    blob = f"{title or ''} {(html or '')[:6000]}"
    return next((name for name, rx in VENDORS if rx.search(blob)), None)


def assess(*, status: int | None, title: str | None = None, html: str | None = None,
           bot_challenge: bool = False, error: str | None = None) -> dict[str, Any]:  # fmt: skip
    """``{ok, kind, status, reason, vendor, title}``. ``kind`` is one of ok, blocked, challenge,
    server_error, not_found, unreachable."""
    vendor = vendor_of(title, html)
    base: dict[str, Any] = {"status": status, "vendor": vendor, "title": (title or "")[:80] or None}
    if status is None:
        return {**base, "ok": False, "kind": "unreachable",
                "reason": f"no answer from the site — {(error or 'it did not respond').strip()[:160]}"}
    on = f" ({vendor})" if vendor else ""
    if is_cloudflare_phish_warning(title, html):
        return {**base, "ok": False, "kind": "challenge", "vendor": vendor or "Cloudflare",
                "reason": "Cloudflare shows its own “Suspected Phishing” warning instead of the site"}
    if status in (401, 403, 429, 451) or status == 406:
        return {**base, "ok": False, "kind": "blocked",
                "reason": f"HTTP {status} {PHRASES.get(status, '')} — the site's bot protection{on} refused BrandWatch's scanner".replace("  ", " ")}
    if status == 404 or status == 410:
        return {**base, "ok": False, "kind": "not_found",
                "reason": f"HTTP {status} {PHRASES.get(status, '')} — there is no page at this address; check the official domain"}
    if status >= 500:
        return {**base, "ok": False, "kind": "server_error",
                "reason": f"HTTP {status} {PHRASES.get(status, '')} — the site had a server error; try again later"}
    if status >= 400:
        return {**base, "ok": False, "kind": "blocked", "reason": f"HTTP {status} — the site refused the request{on}"}
    if bot_challenge or is_bot_challenge(title, html):
        return {**base, "ok": False, "kind": "challenge",
                "reason": f"a bot-check page{on} was shown instead of the site (HTTP {status})"}
    if title and _BLOCK_TITLE.search(title):
        return {**base, "ok": False, "kind": "blocked",
                "reason": f"HTTP {status}, but the page says “{title[:60]}” — a block page{on}"}
    return {**base, "ok": True, "kind": "ok", "reason": f"HTTP {status}"}


def from_fetch(res: Any) -> dict[str, Any]:
    """``assess`` for a browser provider result (``ProviderResult``)."""
    if not res.ok or not res.data:
        return assess(status=None, error=str(getattr(res, "error", None) or "unavailable"))
    d = res.data
    return assess(status=d.get("status"), title=d.get("title"), html=d.get("html"),
                  bot_challenge=bool(d.get("bot_challenge")))  # fmt: skip


FIXES = (
    ("residential", "Try again through the residential proxy",
     "A different IP address — a home connection instead of a data centre. Settings → Residential proxy."),
    ("other_page", "Fingerprint from another official page",
     "A page of the same brand that does not block — a country site (thenorthface.co.il), a help centre, a blog."),
    ("snapshot", "Take it from urlscan.io",
     "A public snapshot of the real site, taken by someone else's browser: its screenshot, colours and title "
     "are enough to compare look-alikes with."),
    ("retry", "Try again later",
     "Some protections only refuse bursts of requests."),
)
