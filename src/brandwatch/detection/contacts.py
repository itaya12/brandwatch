"""The brand's real contact details, read from its own website — and the same extractor for any text.

AI assistants are asked "what is the support phone of <brand>?" (``detection/ai_answers.py``). An
answer is only trustworthy when every number and address in it is one the brand publishes itself, so
BrandWatch first builds an *inventory* of the official contacts:

* **Crawl** the official site from its homepage — every official domain of the brand family, same
  registrable domain only, contact / support / service / about pages first, ``max_pages`` at most.
  A plain request through the SSRF guard first (``browser.peek``); the sandboxed browser only when the
  plain page is empty (a script-built site).
* **Extract**, with the page each one was found on as proof: ``tel:`` / ``mailto:`` links, phone numbers
  in the text (Israeli 0X / 05X / 07X, 1-700 / 1-800, international ``+CC``, North-American), short
  codes ``*2407`` (also written ``2407*`` in right-to-left text), WhatsApp (``wa.me``, ``api.whatsapp.com``)
  and e-mail addresses.
* **Normalise** so the same number always compares equal: ``03-6532407``, ``+972 3 653 2407`` and
  ``972-3-6532407+`` are all ``+97236532407``; a short code is ``*2407``; e-mails are lower-case.

Stored on the brand (``brands.profile["contacts"]``) with when it was read; an analyst can add contacts
the site does not show (``profile["known_contacts"]``).
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urljoin, urlsplit

from bs4 import BeautifulSoup

from brandwatch.detection.discovery import split_host

KINDS = ("phone", "star", "email", "whatsapp")
KIND_LABEL = {"phone": "phone", "star": "short code", "email": "e-mail", "whatsapp": "WhatsApp", "url": "web address"}
MAX_PAGES_DEFAULT = 40
MAX_PAGES_TOP = 150
MAX_DEPTH = 2
STALE_DAYS = 7

# country → international dialling code (the brand's own market decides how "03-…" is read)
DIAL = {"IL": "972", "US": "1", "CA": "1", "GB": "44", "DE": "49", "FR": "33", "ES": "34", "IT": "39", "NL": "31",
        "BE": "32", "CH": "41", "AT": "43", "SE": "46", "NO": "47", "DK": "45", "FI": "358", "PL": "48", "PT": "351",
        "IE": "353", "AU": "61", "NZ": "64", "BR": "55", "MX": "52", "AR": "54", "IN": "91", "JP": "81", "KR": "82",
        "SG": "65", "AE": "971", "SA": "966", "TR": "90", "RU": "7", "UA": "380", "ZA": "27", "GR": "30", "CZ": "420",
        "HU": "36", "RO": "40"}  # fmt: skip

# pages that carry contact details, in the languages BrandWatch searches in
PRIORITY_WORDS = (
    "contact", "support", "help", "service", "customer", "branches", "branch", "about", "faq", "accessibility",
    "terms", "privacy", "phone", "call", "whatsapp", "fraud", "security", "complaint", "inquir", "kontakt",
    "contacto", "contatti", "assistance", "aide", "hilfe", "impressum",
    "צור קשר", "צרו קשר", "יצירת קשר", "תמיכה", "שירות", "סניפים", "אודות", "פניות", "נגישות", "שאלות", "מוקד", "הונא",
    "اتصل", "الدعم", "контакт", "поддерж",
)  # fmt: skip
_SKIP_PATH = re.compile(r"\.(?:pdf|jpe?g|png|gif|svg|webp|ico|css|js|zip|rar|mp4|mp3|xml|json|docx?|xlsx?)(?:$|\?)", re.I)

_EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}(?![\w-])")
_EMAIL_BAD_TLD = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico"}
_EMAIL_BAD_DOMAIN = ("example.com", "example.org", "sentry.io", "wixpress.com", "domain.com", "email.com", "yourdomain.com")
# Israeli: 0X-XXXXXXX (landline), 05X-XXXXXXX (mobile), 07X-XXXXXXX (VoIP), any separators
_IL_LOCAL = re.compile(r"(?<![\d+*])0(?:5\d|7\d|[2-489])[\s\-.]?\d{3}[\s\-.]?\d{4}(?![\d*])")
# Israeli toll-free / premium: 1-700-XXX-XXX, 1-800-…, 1-599-…, 1-801-…
_IL_TOLL = re.compile(r"(?<![\d+*])1[\s\-.]?(?:700|800|599|801)[\s\-.]?\d{3}[\s\-.]?\d{3}(?![\d*])")
# international: +CC and 7–13 more digits, separators allowed
_INTL = re.compile(r"(?<![\w+])(?:\+|00)\s?\d{1,3}(?:[\s\-.()]{0,2}\d){6,13}(?![\d*])")
# right-to-left text writes "+972-3-6532620" as "972-3-6532620+"
_INTL_RTL = re.compile(r"(?<![\w+])(\d{1,3}[\s\-.]\d{1,3}[\s\-.]?\d{3}[\s\-.]?\d{3,4})\+(?![\d])")
# North America: (800) 555-1234 · 1-800-555-1234 · 800.555.1234
_NANP = re.compile(r"(?<![\d+*])(?:1[\s\-.])?\(?[2-9]\d{2}\)?[\s\-.]\d{3}[\s\-.]\d{4}(?![\d*])")
# short codes: *2407, and "2407*" as right-to-left text shows it
_STAR = re.compile(r"(?<![\w*.,])\*\s?(\d{3,5})(?![\d*])|(?<![\w*.,])(\d{3,5})\*(?![\w*])")
_WA = re.compile(r"(?:wa\.me/|api\.whatsapp\.com/send/?\?(?:[^\"'\s]*&)?phone=|whatsapp://send/?\?phone=)\+?(\d{8,15})", re.I)
_URL = re.compile(r"https?://[^\s<>\"'()\[\]]+|(?<![\w@.-])(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:/[^\s<>\"'()\[\]]*)?", re.I)


@dataclass
class Found:
    kind: str  # phone | star | email | whatsapp
    value: str  # normalised: +97236532407 · *2407 · support@shopnova.com
    display: str  # as written the first time
    pages: list[str] = field(default_factory=list)
    context: str = ""  # the words around it on the first page

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "value": self.value, "display": self.display, "pages": self.pages[:6], "context": self.context}


# ------------------------------------------------------------------------------------ normalising
def dial_code(countries: list[str] | tuple[str, ...] | None) -> str:
    for c in countries or ():
        if (c or "").upper() in DIAL:
            return DIAL[c.upper()]
    return "972"


def normalize_phone(raw: str, cc: str = "972") -> str | None:
    """``+<country code><national number>`` — or None when it is not a phone number."""
    s = (raw or "").strip()
    plus = s.startswith("+") or s.endswith("+") or s.startswith("00")
    digits = re.sub(r"\D", "", s)
    if s.startswith("00"):
        digits = digits[2:]
    if plus:
        if not 8 <= len(digits) <= 15:
            return None
        if digits.startswith(cc + "0"):  # "+972 03-…": the trunk 0 does not belong after the code
            digits = cc + digits[len(cc) + 1 :]
        return "+" + digits
    if cc == "1" and len(digits) in (10, 11):
        d = digits[1:] if len(digits) == 11 and digits.startswith("1") else digits
        return "+1" + d if len(d) == 10 else None
    if digits.startswith("0") and 9 <= len(digits) <= 11:
        return "+" + cc + digits[1:]
    if cc == "972" and re.fullmatch(r"1(?:700|800|599|801)\d{6}", digits):
        return "+972" + digits
    if digits.startswith(cc) and 10 <= len(digits) <= 15:
        return "+" + digits
    return None


def normalize_email(raw: str) -> str | None:
    e = (raw or "").strip().strip(".").lower()
    if not _EMAIL.fullmatch(e):
        return None
    dom = e.rsplit("@", 1)[1]
    if dom.rsplit(".", 1)[-1] in _EMAIL_BAD_TLD or any(dom == b or dom.endswith("." + b) for b in _EMAIL_BAD_DOMAIN):
        return None
    return e


def contact_key(kind: str, value: str) -> str:
    """Phones and WhatsApp numbers share one namespace: a WhatsApp number the site lists as a phone is known."""
    return f"{'phone' if kind in ('phone', 'whatsapp') else kind}:{value}"


# ------------------------------------------------------------------------------------ extracting
def _ctx(text: str, start: int, end: int) -> str:
    return " ".join(text[max(0, start - 60) : end + 60].split())[:180]


def plain(text: str) -> str:
    """Markdown emphasis off (``**\\*6700**`` → `` *6700 ``): AI answers come as markdown."""
    return re.sub(r"\\([*_\-.])", r"\1", re.sub(r"\*\*|__|`", " ", text or ""))


def from_text(text: str, *, cc: str = "972") -> list[Found]:
    """Every contact written in plain text (an AI answer, a page's visible text)."""
    text = plain(text)
    out: dict[str, Found] = {}
    taken: list[tuple[int, int]] = []  # a span already read as one thing is not read again as another

    def free(a: int, b: int) -> bool:
        return all(b <= x or a >= y for x, y in taken)

    def add(kind: str, value: str | None, display: str, a: int, b: int) -> None:
        if not value or not free(a, b):
            return
        taken.append((a, b))
        k = contact_key(kind, value)
        if k not in out:
            out[k] = Found(kind, value, display.strip(), context=_ctx(text, a, b))

    for m in _WA.finditer(text):
        add("whatsapp", normalize_phone("+" + m.group(1), cc), m.group(0), m.start(), m.end())
    for m in _EMAIL.finditer(text):
        add("email", normalize_email(m.group(0)), m.group(0), m.start(), m.end())
    for m in _INTL_RTL.finditer(text):
        add("phone", normalize_phone(m.group(1) + "+", cc), "+" + m.group(1), m.start(), m.end())
    for m in _INTL.finditer(text):
        add("phone", normalize_phone(m.group(0), cc), m.group(0), m.start(), m.end())
    # a national number with a trunk 0 (03-…, 054-…) is never North-American: read it whatever the market
    for rx in (_IL_TOLL, _IL_LOCAL) if cc == "972" else (_NANP, _IL_LOCAL) if cc == "1" else (_IL_LOCAL,):
        for m in rx.finditer(text):
            add("phone", normalize_phone(m.group(0), cc), m.group(0), m.start(), m.end())
    for m in _STAR.finditer(text):
        code = m.group(1) or m.group(2)
        add("star", "*" + code, "*" + code, m.start(), m.end())
    return list(out.values())


def visible_text(html: str | None) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return " ".join(soup.get_text(" ").split())


def from_html(html: str | None, page_url: str, *, cc: str = "972") -> list[Found]:
    """Contacts on one page: its ``tel:`` / ``mailto:`` / WhatsApp links first, then its visible text."""
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    out: dict[str, Found] = {}

    def add(f: Found) -> None:
        k = contact_key(f.kind, f.value)
        if k not in out:
            f.pages = [page_url]
            out[k] = f

    for a in soup.find_all("a", href=True):
        href = str(a["href"]).strip()
        low = href.lower()
        label = a.get_text(" ", strip=True)[:80]
        if low.startswith("tel:"):
            num = unquote(href[4:]).split(";")[0]
            star = re.fullmatch(r"\*?\s*(\d{3,5})\s*\*?", num.strip())
            if star and len(re.sub(r"\D", "", num)) <= 5:
                add(Found("star", "*" + star.group(1), "*" + star.group(1), context=label))
            elif (v := normalize_phone(num, cc)) is not None:
                add(Found("phone", v, label if re.search(r"\d{3}", label) else num, context=label))
        elif low.startswith("mailto:"):
            v = normalize_email(unquote(href[7:]).split("?")[0])
            if v:
                add(Found("email", v, v, context=label))
        else:
            m = _WA.search(href)
            if not m and "whatsapp" in low:
                q = parse_qs(urlsplit(href).query).get("phone") or []
                m = re.search(r"(\d{8,15})", q[0]) if q else None
            if m and (v := normalize_phone("+" + m.group(1), cc)):
                add(Found("whatsapp", v, "+" + m.group(1), context=label))
    for f in from_text(visible_text(html), cc=cc):
        add(f)
    return list(out.values())


def urls_in(text: str) -> list[str]:
    """Web addresses written in a text (``https://…`` or a bare ``login.example.co.il``), as hosts."""
    out: list[str] = []
    for m in _URL.finditer(text or ""):
        raw = m.group(0).rstrip(".,;:!?)»”'\"")
        host = (urlsplit(raw if "://" in raw else "https://" + raw).hostname or "").lower().strip(".")
        if host and "." in host and not re.fullmatch(r"[\d.]+", host) and host not in out and "@" not in raw.split("/")[0]:
            out.append(host)
    return out


# ------------------------------------------------------------------------------------ crawling
def _priority(url: str, label: str) -> int:
    s = (unquote(urlsplit(url).path) + " " + label).lower()
    return 0 if any(w in s for w in PRIORITY_WORDS) else 1


@dataclass
class Inventory:
    found: dict[str, Found] = field(default_factory=dict)
    pages: list[dict[str, Any]] = field(default_factory=list)

    def add(self, f: Found, page: str) -> None:
        k = contact_key(f.kind, f.value)
        if k in self.found:
            if page not in self.found[k].pages:
                self.found[k].pages.append(page)
        else:
            f.pages = [page]
            self.found[k] = f

    def as_dict(self) -> dict[str, Any]:
        by: dict[str, list[dict[str, Any]]] = {k: [] for k in KINDS}
        for f in sorted(self.found.values(), key=lambda x: (-len(x.pages), x.value)):
            by[f.kind].append(f.as_dict())
        return {**by, "pages": self.pages, "crawled": sum(1 for p in self.pages if p.get("ok"))}


async def crawl(providers: Any, start_urls: list[str], family_domains: set[str], *, cc: str = "972",
                max_pages: int = MAX_PAGES_DEFAULT, on_page: Any = None) -> Inventory:  # fmt: skip
    """Read the official site from its homepage and collect every contact it publishes (see the module)."""
    own = {split_host(d).registrable for d in family_domains if d} | {d.lower() for d in family_domains if d}
    inv = Inventory()
    seen: set[str] = set()
    queue: deque[tuple[int, int, str]] = deque()
    for u in start_urls:
        queue.append((0, 0, u))
    max_pages = max(1, min(int(max_pages), MAX_PAGES_TOP))
    while queue and len(inv.pages) < max_pages:
        # contact-like pages first, then breadth
        best = min(range(len(queue)), key=lambda i: (queue[i][1], queue[i][0]))
        depth, _prio, url = queue[best]
        del queue[best]
        url = url.split("#")[0]
        if url in seen:
            continue
        seen.add(url)
        html, how = None, "plain"
        try:
            res = await providers.browser().peek(url)
            html = (res.data or {}).get("html") if res.ok and int((res.data or {}).get("status") or 200) < 400 else None
        except Exception:  # noqa: BLE001 - the browser below tries again
            html = None
        if not html or len(visible_text(html)) < 200:
            try:
                res = await providers.browser().fetch(url, profile="datacenter")
                if res.ok and (res.data or {}).get("html"):
                    html, how = res.data["html"], "browser"
            except Exception:  # noqa: BLE001 - one page that will not load is not the end of the crawl
                pass
        if not html:
            inv.pages.append({"url": url, "ok": False, "found": 0})
            continue
        found = from_html(html, url, cc=cc)
        for f in found:
            inv.add(f, url)
        inv.pages.append({"url": url, "ok": True, "found": len(found), "via": how})
        if on_page:
            on_page(url, len(found), len(inv.found))
        if depth >= MAX_DEPTH:
            continue
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            target = urljoin(url, str(a["href"]).strip()).split("#")[0]
            parts = urlsplit(target)
            host = (parts.hostname or "").lower()
            if parts.scheme not in ("http", "https") or not host or target in seen or _SKIP_PATH.search(parts.path):
                continue
            if host not in own and split_host(host).registrable not in own:
                continue
            queue.append((depth + 1, _priority(target, a.get_text(" ", strip=True)), target))
    return inv


def known_set(contacts: dict[str, Any] | None, known: list[Any] | None, *, cc: str = "972") -> set[str]:
    """Every contact key the brand publishes (the crawl) or an analyst added (``known_contacts``)."""
    out: set[str] = set()
    for kind in KINDS:
        for row in (contacts or {}).get(kind) or []:
            if row.get("value"):
                out.add(contact_key(kind, row["value"]))
    for raw in known or []:
        raw = str(raw.get("value") if isinstance(raw, dict) else raw).strip()
        for f in from_text(raw, cc=cc) or []:
            out.add(contact_key(f.kind, f.value))
        if re.fullmatch(r"\*?\d{3,5}\*?", raw):
            out.add(contact_key("star", "*" + raw.strip("*")))
    return out


def page_has(html: str | None, kind: str, value: str, *, cc: str = "972") -> bool:
    """Does this page publish that contact (same normalised value)?"""
    want = contact_key(kind, value)
    return any(contact_key(f.kind, f.value) == want for f in from_html(html, "", cc=cc))
