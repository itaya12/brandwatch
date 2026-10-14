"""HTML feature extraction for the Behavior / Visual signal groups (spec §5, §8).

Pure function over an HTML string: forms (credential / payment / seed-phrase), where forms post
to, brand keywords and lure language in visible text, favicon link, pre-filled e-mail. Keeps the
heavy lifting out of the pipeline stage so it is unit-testable with fixtures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from brandwatch.detection.discovery import key_in

LURE_TERMS: tuple[str, ...] = (
    "verify your account",
    "verify your identity",
    "confirm your identity",
    "account suspended",
    "account has been suspended",
    "unusual activity",
    "suspicious activity",
    "update your payment",
    "payment information",
    "your account will be",
    "limited time",
    "act now",
    "immediately",
    "within 24 hours",
    "locked",
    "session expired",
    "re-enter your password",
)
CARD_HINTS = ("card", "cc-number", "cc_number", "cardnumber", "cvv", "cvc", "expiry", "exp-date")
SEED_HINTS = (
    "seed",
    "mnemonic",
    "recovery phrase",
    "secret phrase",
    "12 words",
    "24 words",
    "passphrase",
)


@dataclass(frozen=True, slots=True)
class FormInfo:
    action: str | None
    method: str
    has_password: bool
    has_email_or_user: bool
    has_card: bool
    has_seed: bool
    external_action: bool
    prefilled_email: bool


@dataclass(slots=True)
class HtmlFeatures:
    title: str | None
    text_excerpt: str
    favicon_url: str | None
    meta_description: str | None = None
    forms: list[FormInfo] = field(default_factory=list)
    brand_keywords: list[str] = field(default_factory=list)
    lure_terms: list[str] = field(default_factory=list)
    is_parked: bool = False
    tracking_ids: list[str] = field(default_factory=list)
    # the CDN in front of the site serves its own phishing warning instead of the site
    cloudflare_phish_warning: bool = False

    @property
    def credential_form(self) -> bool:
        return any(f.has_password for f in self.forms)

    @property
    def payment_form(self) -> bool:
        return any(f.has_card for f in self.forms)

    @property
    def seed_phrase_field(self) -> bool:
        return any(f.has_seed for f in self.forms)

    @property
    def external_form_action(self) -> bool:
        return any(f.external_action and (f.has_password or f.has_card) for f in self.forms)

    @property
    def password_prefill(self) -> bool:
        return any(f.prefilled_email and f.has_password for f in self.forms)


_PARKED_MARKERS = (
    "this domain is for sale",
    "domain parking",
    "buy this domain",
    "parked free",
    "sedoparking",
    "is parked",
    "coming soon",
)


def _attr_blob(tag) -> str:
    return " ".join(
        str(tag.get(a, ""))
        for a in ("name", "id", "type", "autocomplete", "placeholder", "aria-label")
    ).lower()


def extract_features(html: str, base_url: str, brand_keywords: list[str]) -> HtmlFeatures:
    soup = BeautifulSoup(html or "", "html.parser")
    for t in soup(["script", "style", "noscript"]):
        t.decompose()
    tracking_ids = sorted(set(_TRACKING.findall(html or "")))
    title = soup.title.get_text(strip=True) if soup.title else None
    meta_description = _meta_description(soup)
    text = " ".join(soup.get_text(" ").split())
    text_l = text.lower()
    base_host = (urlsplit(base_url).hostname or "").lower()

    favicon_url = None
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel", [])).lower() if link.get("rel") else ""
        if "icon" in rel and link.get("href"):
            favicon_url = urljoin(base_url, link["href"])
            break
    if favicon_url is None and base_host:
        favicon_url = urljoin(base_url, "/favicon.ico")

    forms: list[FormInfo] = []
    for form in soup.find_all("form"):
        inputs = form.find_all(["input", "textarea", "select"])
        blobs = [_attr_blob(i) for i in inputs]
        has_password = any(i.get("type", "").lower() == "password" for i in inputs)
        has_email_or_user = any(
            any(k in b for k in ("email", "user", "login", "phone")) for b in blobs
        )
        has_card = any(any(k in b for k in CARD_HINTS) for b in blobs)
        has_seed = any(any(k in b for k in SEED_HINTS) for b in blobs) or any(
            k in form.get_text(" ").lower() for k in SEED_HINTS
        )
        action = form.get("action")
        action_abs = urljoin(base_url, action) if action else None
        action_host = (urlsplit(action_abs).hostname or "").lower() if action_abs else ""
        external = bool(action_host) and action_host != base_host
        prefilled = any(
            (i.get("value") or "").count("@") == 1 and "email" in _attr_blob(i) for i in inputs
        )
        forms.append(
            FormInfo(
                action=action_abs,
                method=(form.get("method") or "get").lower(),
                has_password=has_password,
                has_email_or_user=has_email_or_user,
                has_card=has_card,
                has_seed=has_seed,
                external_action=external,
                prefilled_email=prefilled,
            )
        )

    # a 2-letter word (the "on" of on.com) is in every English page: it cannot show the brand
    kws = sorted({k for k in (x.lower() for x in brand_keywords) if len(k) >= 3 and key_in(k, text_l)})
    lures = [t for t in LURE_TERMS if t in text_l]
    parked = any(m in text_l for m in _PARKED_MARKERS) or (len(text) < 40 and not forms)

    return HtmlFeatures(
        title=title,
        meta_description=meta_description,
        text_excerpt=text[:500],
        favicon_url=favicon_url,
        forms=forms,
        brand_keywords=kws,
        lure_terms=lures,
        is_parked=parked,
        tracking_ids=tracking_ids,
        cloudflare_phish_warning=is_cloudflare_phish_warning(title, html),
    )


_TRACKING = re.compile(
    r"\b(UA-\d{4,10}-\d{1,3}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,9}|ca-pub-\d{10,20}|AW-\d{6,12})\b"
)


_WORD = re.compile(r"[a-z0-9]{4,}")


def _meta_description(soup: BeautifulSoup) -> str | None:
    for m in soup.find_all("meta"):
        name = str(m.get("name") or m.get("property") or "").lower()
        if name in ("description", "og:description", "twitter:description") and m.get("content"):
            return " ".join(str(m.get("content")).split())[:500] or None
    return None


_AUTH_WORDS: tuple[tuple[str, str], ...] = (
    ("sign up", "signup"), ("signup", "signup"), ("register", "signup"), ("create account", "signup"),
    ("join", "signup"), ("log in", "login"), ("login", "login"), ("sign in", "login"),
    ("signin", "login"), ("my account", "account"), ("account", "account"),
)  # fmt: skip


# what a gate says (the title, or the words on the page), and what only a gate's markup contains. The Cloudflare script that
# ordinary sites carry (/cdn-cgi/challenge-platform/scripts/jsd/…) is neither.
_CHALLENGE = re.compile(
    r"just a moment|attention required|checking your browser|verify you are human|"
    r"enable javascript and cookies to continue|"
    r"access denied.*cloudflare|please wait while we verify",
    re.I,
)
_CHALLENGE_MARKUP = re.compile(r"cf-chl|cf_chl|chl_page|ddos-guard", re.I)


_CF_PHISH = re.compile(r"suspected\s+phishing|/cdn-cgi/phish-bypass|reported\s+for\s+potential\s+phishing", re.I)


def is_cloudflare_phish_warning(title: str | None, html: str | None) -> bool:
    """Cloudflare's own "Suspected Phishing" interstitial (served by Cloudflare *instead of* the site it
    protects, with an "ignore and proceed" form to /cdn-cgi/phish-bypass): Cloudflare's trust & safety
    team has already judged the site — a blocklist verdict, not a bot check."""
    head = (html or "")[:8000]
    t = title or ""
    return bool(("cloudflare" in t.lower() and _CF_PHISH.search(t)) or "/cdn-cgi/phish-bypass" in head.lower())


# A security product's own "this site is phishing" page, shown INSTEAD of the site (a CDN, a DNS filter, an antivirus on the
# machine). Each is a verdict somebody else already made. A vendor name next to a phishing word, or a short page whose
# heading says phishing was blocked / detected / reported - never a long page that merely talks about phishing.
_VENDORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Microsoft Defender SmartScreen", re.compile(r"smartscreen|microsoft defender", re.I)),
    ("Fortinet FortiGuard", re.compile(r"fortiguard|fortinet", re.I)),
    ("Palo Alto Networks", re.compile(r"palo alto|paloaltonetworks", re.I)),
    ("Cisco Umbrella / OpenDNS", re.compile(r"cisco umbrella|opendns|umbrella\.com", re.I)),
    ("Kaspersky", re.compile(r"kaspersky", re.I)),
    ("Bitdefender", re.compile(r"bitdefender", re.I)),
    ("ESET", re.compile(r"\beset\b", re.I)),
    ("Sophos", re.compile(r"sophos", re.I)),
    ("Norton / Avast / AVG / McAfee", re.compile(r"\bnorton\b|\bavast\b|\bavg\b|mcafee|webadvisor|safe ?web", re.I)),
    ("Trend Micro", re.compile(r"trend ?micro", re.I)),
    ("Quad9", re.compile(r"quad9", re.I)),
)
_PHISH_WORD = re.compile(r"phish|deceptive site|social engineering|fraudulent (?:web)?site|scam site", re.I)
_PHISH_BLOCK = re.compile(
    r"(?:blocked|warning|alert|detected|reported|suspected|unsafe|dangerous|deceptive|threat|stopped)\W.{0,60}phish|"
    r"phish\w*\W.{0,60}(?:blocked|warning|alert|detected|reported|suspected|threat)|"
    r"deceptive site ahead|this (?:web)?site (?:is|has been) (?:blocked|reported)",
    re.I,
)
_TAGS = re.compile(r"<script.*?</script>|<style.*?</style>|<[^>]+>", re.S | re.I)
SECURITY_WARNING_MAX_TEXT = 4000  # a vendor's warning page is short; a long page that mentions phishing is an article
SECURITY_WARNING_MAX_TEXT_UNNAMED = 1500  # no vendor named: only a very short page whose own TITLE says phishing was blocked


def security_warning(title: str | None, html: str | None) -> dict[str, str] | None:
    """If the page is a security product's phishing warning rather than the site: ``{vendor, reason}``.
    Cloudflare's "Suspected Phishing" interstitial first; then a named vendor / DNS filter whose page says phishing
    was blocked; then a very short page whose own title says so. A bank's "beware of phishing" notice on a login page,
    a long article, a bot check or a plain "Access Denied" is not a verdict."""
    if is_cloudflare_phish_warning(title, html):
        return {"vendor": "Cloudflare", "reason": "its \u201cSuspected Phishing\u201d warning is shown instead of the site"}
    page = html or ""
    text = " ".join(_TAGS.sub(" ", page[:60000]).split())
    if len(text) > SECURITY_WARNING_MAX_TEXT or (not text and not title):
        return None
    head = f"{title or ''} {text[:1500]}"
    vendor = next((name for name, rx in _VENDORS if rx.search(f"{title or ''} {text[:3000]} {page[:3000]}")), None)
    named = bool(vendor and _PHISH_WORD.search(head) and _PHISH_BLOCK.search(head))
    by_title = bool(title and _PHISH_WORD.search(title) and _PHISH_BLOCK.search(title) and len(text) <= SECURITY_WARNING_MAX_TEXT_UNNAMED)
    if not (named or by_title):
        return None
    return {"vendor": vendor or "a security service", "reason": f"its warning page says: \u201c{(title or text)[:110].strip()}\u201d"}


def visible_text(html: str | None) -> str:
    """The words a visitor reads: no scripts, styles or tags."""
    return " ".join(_TAGS.sub(" ", html or "").split())


CHALLENGE_MAX_TEXT = 1500  # a gate says one thing; a page with this much to read is a site


def is_bot_challenge(title: str | None, html: str | None) -> bool:
    """Cloudflare / DDoS-Guard style interstitials: the page is not the site, it is a gate. The title says it, or the page
    is a thin one that carries the gate's words. The same words inside the scripts of a full page (a login form's "verify you
    are human" error text, a Cloudflare script on an ordinary site) are not a gate: they were taken for one, and ordinary
    sites were rated "blocks bots"."""
    if _CHALLENGE.search(title or "") or _CHALLENGE_MARKUP.search(title or ""):
        return True
    text = visible_text(html)
    if len(text) > CHALLENGE_MAX_TEXT:
        return False
    return bool(_CHALLENGE.search(text) or _CHALLENGE_MARKUP.search((html or "")[:6000]))


# "ClickFix": a fake human-verification screen (often a copy of Cloudflare's) that does not verify anything: it puts a command
# on the visitor's clipboard and tells them to press Win+R, paste it (Ctrl+V) and press Enter - which runs malware - and
# often forces the browser full screen so that the visitor cannot leave. Seen on a look-alike's redirect chain:
# tv4q.roachtraffic.cc, "cloudflare.com needs to review the security of your connection", then "Human Verification".
_CF_STEPS = re.compile(
    r"win(?:dows)?\s*(?:key)?\s*\+\s*r\b|windows\s+key\W{0,12}(?:\+\W{0,3})?\s*r\b|press\s*(?:&|and)?\s*hold\W{0,12}windows|"
    r"\brun\s+(?:dialog|window|box)|open\s+(?:the\s+)?(?:run|terminal|powershell|command\s+prompt)|cmd\s*\+\s*space|"
    r"in\s+the\s+input\s+box|type\s+cmd\b|spotlight",
    re.I,
)
_CF_PASTE = re.compile(r"ctrl\s*\+\s*v\b|cmd\s*\+\s*v\b|\bpaste\b", re.I)
_CF_VERIFY = re.compile(
    r"human\s+verification|verify\s+(?:that\s+)?you(?:\s+are|['\u2019]re)?\s+(?:a\s+)?human|not\s+a\s+robot|verification\s+id|"
    r"captcha|security\s+check|complete\s+(?:the\s+)?(?:steps|verification)|prove\s+you",
    re.I,
)
_CF_CLIPBOARD = re.compile(r"navigator\.clipboard\.writeText|execCommand\(\s*['\"]copy|clipboardData\.setData|\.writeText\(", re.I)
_CF_COMMAND = re.compile(
    r"powershell|mshta|cmd(?:\.exe)?\s*/c|curl\s+[^|;\n]{0,200}\|\s*(?:ba)?sh|\bwscript|msiexec|-encodedcommand|\s-enc\s|"
    r"invoke-expression|\biex\b|certutil|bitsadmin|rundll32|regsvr32|\bnet\s+use\b|atob\s*\(",
    re.I,
)
_CF_FULLSCREEN = re.compile(r"requestFullscreen|webkitRequestFullscreen|keyboard\.lock\s*\(", re.I)
_CF_NAMED = re.compile(r"([a-z0-9][a-z0-9.-]{1,60}\.[a-z]{2,})\s+needs\s+to\s+review\s+the\s+security\s+of\s+your\s+connection", re.I)
_CF_RAY = re.compile(r"ray\s*id\W{0,4}([a-z0-9]{8,24})", re.I)
CLICKFIX_MAX_TEXT = 6000  # a how-to article that explains Win+R is long; the lure is a screen with a few lines


def clickfix_lure(title: str | None, html: str | None, host: str | None = None) -> dict[str, object] | None:
    """A page that tries to make the visitor run a command (ClickFix), or a fake Cloudflare "human verification" of a site that is not
    Cloudflare's. ``{kind, reason, indicators}``; None for anything else. It never follows the instructions: it reads them.

    * *instructs*: a verification screen whose steps are "Win+R / paste (Ctrl+V) / Enter";
    * *clipboard*: a script that writes a shell command (PowerShell, mshta, curl | sh, a decoded string …) to the clipboard;
    * *fake Cloudflare*: "<a domain that is not this site> needs to review the security of your connection", or a Ray ID that is not
      Cloudflare's (16 hex digits), on a host that is not behind Cloudflare's own check;
    * and, with the above, a forced full screen (the visitor cannot leave).
    A long article about Windows shortcuts, or a login page that mentions a CAPTCHA, has none of the combinations."""
    page = html or ""
    text = visible_text(page)
    if len(text) > CLICKFIX_MAX_TEXT:
        return None
    blob = f"{title or ''} {text}"
    verify = bool(_CF_VERIFY.search(blob))
    indicators: list[str] = []
    kind = ""
    if _CF_STEPS.search(blob) and _CF_PASTE.search(blob) and (verify or re.search(r"\benter\b", blob, re.I)):
        indicators.append("its steps tell the visitor to open the Run dialog (Win+R), paste with Ctrl+V and press Enter")
        kind = "instructions"
    scripts = " ".join(re.findall(r"<script\b[^>]*>(.*?)</script>", page, re.I | re.S))
    if _CF_CLIPBOARD.search(scripts) and _CF_COMMAND.search(scripts) and (verify or kind):
        indicators.append("a script puts a command on the visitor's clipboard")
        kind = kind or "clipboard"
    named = _CF_NAMED.search(blob)
    own = (host or "").lower().removeprefix("www.")
    mismatch = bool(named and own and named.group(1).lower().removeprefix("www.") != own and not own.endswith("." + named.group(1).lower()))
    ray = _CF_RAY.search(blob)
    bad_ray = bool(ray and not re.fullmatch(r"[0-9a-f]{16}(?:-[a-z]{3})?", ray.group(1).lower()))
    if mismatch and (verify or bad_ray):
        indicators.append(f"it says “{named.group(1)} needs to review the security of your connection” on {own}: a fake Cloudflare check")
        kind = kind or "fake_cloudflare"
    elif bad_ray and re.search(r"cloudflare", blob, re.I) and verify:
        indicators.append(f"its Ray ID “{ray.group(1)}” is not a Cloudflare Ray ID (16 hex digits): a fake Cloudflare check")
        kind = kind or "fake_cloudflare"
    if not kind:
        return None
    if _CF_FULLSCREEN.search(scripts):
        indicators.append("it forces the browser full screen, so the visitor cannot easily leave")
    reasons = {
        "instructions": "a fake human-verification screen tells the visitor to run a command (Win+R, paste, Enter): the ClickFix malware lure",
        "clipboard": "a fake human-verification page copies a command to the visitor's clipboard: the ClickFix malware lure",
        "fake_cloudflare": "a fake Cloudflare human-verification screen on a site that is not Cloudflare's: the first step of a ClickFix malware lure",
    }
    return {"kind": kind, "reason": reasons[kind], "indicators": indicators}


def auth_links(html: str, base_url: str, official_regs: set[str]) -> list[dict]:
    """Login / sign-up / account links of the official site (same registrable domain), from the
    link text or the URL path (/login, /signup, /register …). One per kind, login first."""
    soup = BeautifulSoup(html or "", "html.parser")
    found: dict[str, dict] = {}
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, str(a["href"]).strip()).split("#", 1)[0]
        parts = urlsplit(href)
        host = (parts.hostname or "").lower()
        if not host or not any(host == r or host.endswith("." + r) for r in official_regs):
            continue
        text = " ".join(a.get_text(" ").split()).lower()[:40]
        path = parts.path.lower().replace("-", "").replace("_", "")
        kind = next((k for w, k in _AUTH_WORDS if w in text or w.replace(" ", "") in path), None)
        if kind is None or kind in found:
            continue
        found[kind] = {"kind": kind, "url": href, "text": text}
    order = {"login": 0, "signup": 1, "account": 2}
    return sorted(found.values(), key=lambda x: order[x["kind"]])


def app_store_links(html: str, base_url: str) -> list[str]:
    """Absolute links from a page to app-store / APK listings (the brand's official apps when the
    page is the brand's own site)."""
    from brandwatch.detection.normalize import canonical_listing_url, is_app_store

    soup = BeautifulSoup(html or "", "html.parser")
    out: list[str] = []
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, str(a["href"]).strip())
        host = (urlsplit(href).hostname or "").lower()
        if host and is_app_store(host):
            clean = canonical_listing_url(href)
            if clean not in out:
                out.append(clean)
        if len(out) >= 20:
            break
    return out


def title_keywords(html: str, limit: int = 12) -> list[str]:
    """Keywords for a brand baseline: words from <title> and <h1>/<h2> (Phase 1; LLM later)."""
    soup = BeautifulSoup(html or "", "html.parser")
    chunks = [soup.title.get_text(" ") if soup.title else ""]
    chunks += [h.get_text(" ") for h in soup.find_all(["h1", "h2"])]
    seen: list[str] = []
    for w in _WORD.findall(" ".join(chunks).lower()):
        if w not in seen:
            seen.append(w)
        if len(seen) >= limit:
            break
    return seen
