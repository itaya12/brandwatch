"""Is this ad, or this page, about the brand at all?

Meta's Ad Library matches the *words* of a keyword, not its meaning: "on cloud" also finds "store
your photos on cloud", "on cloud nine" and "cloud storage". A brand name made of common words needs
a second look before a site is visited and judged as a shop for the brand's products.

The brand's terms come in three strengths:

* **strong** — words nobody else writes: the brand written as one word ("oncloud", "shopnova"),
  product lines ("cloudmonster"), the official domain. One of them is enough.
* **phrase** — the brand as ordinary words ("on cloud", "adidas"). Enough only together with
  **context**: words for what the brand sells ("shoes", "נעליים", "zapatillas", "sizes" …).
* A phrase without context is *maybe*: the AI reads the ad when it is configured, otherwise the ad
  is skipped. Nothing at all about the brand is *no*.

Pure functions, no network: the scanner calls ``ad_relevance`` for every ad and
``page_about_brand`` before it runs the shop checks on a page.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

MIN_STRONG = 5  # a one-word term shorter than this is never "strong"
MIN_STRONG_SINGLE = 7  # a plain dictionary-looking single word needs this length to be strong
MIN_PHRASE = 3
NEAR = 60  # a context word counts only this close to the brand phrase

# What a brand sells, in the languages of the countries BrandWatch scans. Latin words match at the
# start of a word (so "shoe" also finds "shoes"); Hebrew / Arabic / Cyrillic stems match anywhere in
# a word, because those languages glue prefixes and endings on ("הנעליים", "חליפת").
CATEGORY_WORDS: dict[str, tuple[str, ...]] = {
    "footwear": (
        "shoe", "sneaker", "trainers", "running", "runner", "footwear", "boots", "sandal", "pair",
        "size", "נעל", "סניקרס", "זוג", "ריצה", "מידה", "מידות", "zapatill", "zapato", "talla",
        "chaussure", "basket", "pointure", "schuh", "laufschuh", "größe", "scarpe", "sapato", "tênis",
        "кроссов", "обув", "размер", "حذاء", "أحذية", "مقاس", "ayakkabı", "buty", "rozmiar", "schoen",
    ),
    "apparel": (
        "apparel", "clothing", "clothes", "jacket", "hoodie", "shirt", "pants", "leggings", "shorts",
        "tracksuit", "dress", "sweater", "size", "ביגוד", "בגד", "חולצ", "מכנס", "קפוצ", "חליפ",
        "טייץ", "שמל", "מעיל", "מידה", "מידות", "ropa", "chaqueta", "sudadera", "talla", "vêtement",
        "veste", "kleidung", "jacke", "abbigliamento", "roupa", "одежд", "куртк", "размер", "ملابس",
        "giyim", "ubrani", "kleding",
    ),
    "bags": (
        "bag", "handbag", "backpack", "wallet", "purse", "luggage", "תיק", "ארנק", "bolso", "mochila",
        "sac", "tasche", "borsa", "сумк", "рюкзак", "حقيب", "çanta", "torebk",
    ),
    "watches": (
        "watch", "jewelry", "jewellery", "ring", "necklace", "bracelet", "שעון", "תכשיט", "reloj",
        "montre", "uhr", "orologio", "часы", "ساعة", "saat", "zegarek",
    ),
    "beauty": (
        "perfume", "fragrance", "cosmetic", "makeup", "skincare", "cream", "serum", "lipstick", "בושם",
        "קרם", "איפור", "parfum", "maquillaje", "crema", "kosmetik", "духи", "крем", "عطر", "parfüm",
    ),
    "electronics": (
        "phone", "headphone", "earbud", "laptop", "tablet", "charger", "speaker", "camera", "console",
        "אוזני", "טלפון", "מחשב", "מטען", "auricular", "écouteur", "kopfhörer", "наушник", "سماع",
        "kulaklık", "słuchawk",
    ),
    "sports": (
        "fitness", "gym", "training", "workout", "yoga", "outdoor", "ספורט", "אימון", "deporte",
        "entrenamiento", "sport", "спорт", "رياض", "spor",
    ),
}  # fmt: skip

# how a free-text vertical ("footwear and apparel", "consumer electronics") maps onto the lexicon
_VERTICAL_HINTS: dict[str, tuple[str, ...]] = {
    "footwear": ("footwear", "shoe", "sneaker", "running", "boot"),
    "apparel": ("apparel", "clothing", "fashion", "wear", "garment", "textile"),
    "bags": ("bag", "luggage", "leather goods", "accessor"),
    "watches": ("watch", "jewel"),
    "beauty": ("beauty", "cosmetic", "fragrance", "perfume", "skincare"),
    "electronics": ("electronic", "phone", "audio", "computer", "gadget", "device"),
    "sports": ("sport", "fitness", "outdoor", "athlet", "running"),
}


def normalize(text: str | None) -> str:
    """Lower-case, NFKC, one space between words; URL punctuation becomes a space."""
    t = unicodedata.normalize("NFKC", text or "").lower()
    return " ".join(re.sub(r"[_/\\?=&+%#|]+", " ", t).split())


def compact(text: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", text or "").lower())


def url_words(url: str | None) -> str:
    """The words in a link: host and path, punctuation as spaces ("oncloud-sale.com/cloud-6")."""
    if not url:
        return ""
    parts = urlsplit(url if "://" in url else "https://" + url)
    return normalize(f"{parts.hostname or ''} {parts.path or ''}".replace("-", " ").replace(".", " "))


def _latin(s: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9 .\-']+", s))


def term_pattern(term: str, *, prefix: bool) -> re.Pattern[str]:
    """A term as a regex: its words in order, any spaces / hyphens / dots between them, starting at
    a word boundary. ``prefix`` lets the last word run on ("oncloud" finds "#onclouds"); phrases
    must end at a boundary ("on cloud" must not find "on cloudy days")."""
    words = [re.escape(w) for w in re.split(r"[\s\-_.]+", term.strip().lower()) if w]
    body = r"[\s\-_.]*".join(words)
    if not _latin(term.lower()):
        return re.compile(body)
    tail = "" if prefix else r"(?![a-z])"
    return re.compile(r"(?<![a-z0-9])" + body + tail)


@dataclass(frozen=True)
class BrandTerms:
    """The words that tie an ad or a page to one brand."""

    brand: str
    strong: tuple[str, ...] = ()
    phrases: tuple[str, ...] = ()
    products: tuple[str, ...] = ()  # product names as the analyst saved them (for prices / catalogue)
    context: tuple[str, ...] = ()
    sells: str = ""  # what the brand sells, in words, for people and the AI ("footwear and apparel")
    _strong_rx: tuple[re.Pattern[str], ...] = field(default=(), repr=False, compare=False)
    _phrase_rx: tuple[re.Pattern[str], ...] = field(default=(), repr=False, compare=False)

    def find(self, text: str) -> dict[str, list[str]]:
        """Which strong terms and phrases occur in ``text``, and which context words stand next to a
        phrase (within ``NEAR`` characters: "חליפת ON CLOUD" yes; "on cloud nine … wedding dress" no)."""
        t = normalize(text)
        strong = [s for s, rx in zip(self.strong, self._strong_rx, strict=True) if rx.search(t)]
        phrases: list[str] = []
        context: list[str] = []
        for p, rx in zip(self.phrases, self._phrase_rx, strict=True):
            hits = list(rx.finditer(t))
            if not hits:
                continue
            phrases.append(p)
            for m in hits:
                window = t[max(0, m.start() - NEAR) : m.end() + NEAR]
                context += [w for w in self.context if w not in context and _has_word(window, w)]
        return {"strong": strong, "phrases": phrases, "context": context}

    @property
    def usable(self) -> bool:
        return bool(self.strong or self.phrases)


def _has_word(text: str, word: str) -> bool:
    if _latin(word):
        return re.search(r"(?<![a-z0-9])" + re.escape(word), text) is not None
    return word in text


def categories_for(vertical: str | None, keywords: Iterable[str] = ()) -> list[str]:
    """The lexicon groups that fit the brand's vertical ("footwear and apparel" → footwear, apparel)."""
    blob = " ".join([vertical or "", *keywords]).lower()
    return [k for k, hints in _VERTICAL_HINTS.items() if any(h in blob for h in hints)]


# words that describe *what* is sold, not *whose* it is — a keyword made of these finds every brand
GENERIC_WORDS = frozenset(
    "the a an and of for with by new men mens women womens kids unisex sale outlet discount deal deals offer official "
    "store shop online buy cheap best original genuine authentic premium classic collection edition series pro plus "
    "jacket jackets coat coats parka vest fleece hoodie hoodies sweater shirt shirts tee t-shirt pants trousers shorts "
    "leggings tights dress skirt jeans apparel clothing clothes wear sportswear outerwear down puffer insulated "
    "insulation thermal waterproof rain windbreaker softshell hardshell shell base layer gloves hat cap beanie socks "
    "shoe shoes sneaker sneakers trainer trainers running runner runners trail hiking walking boot boots sandal sandals "
    "slipper slippers footwear lifestyle tennis basketball football soccer golf gym training yoga sport sports "
    "mountain outdoor outdoors camping backpacking climbing ski snow winter summer travel adventure expedition "
    "gear equipment backpack backpacks bag bags duffel tent sleeping pack daypack accessories "
    "watch watches phone phones headphones earbuds laptop tablet speaker charger case cover".split()
)
_BRAND_STOP = frozenset("the and of & co inc ltd llc gmbh by for".split())


def _words(text: str) -> list[str]:
    return re.findall(r"[^\W_]+(?:-[^\W_]+)*", (text or "").lower())


def is_generic_phrase(term: str) -> bool:
    """Only category words ("mountain jacket", "trail running shoes")."""
    ws = _words(term)
    return not ws or all(w in GENERIC_WORDS or w.isdigit() for w in ws)


def brand_terms(
    brand_name: str,
    brand_key: str,
    *,
    ad_keywords: Iterable[str] = (),
    products: Iterable[str] = (),
    official_domains: Iterable[str] = (),
    vertical: str | None = None,
    keywords: Iterable[str] = (),
) -> BrandTerms:
    """Build the brand's terms from what the brand and its profile already say."""
    strong: list[str] = []
    phrases: list[str] = []

    def add(term: str) -> None:
        term = " ".join(term.lower().split())
        c = compact(term)
        if len(c) < MIN_PHRASE:
            return
        multi = " " in term or "-" in term
        if multi and len(c) >= MIN_STRONG:
            if c not in strong:  # "on cloud" → "oncloud" is strong; the spaced form stays a phrase
                strong.append(c)
            if term not in phrases:
                phrases.append(term)
            return
        if len(c) >= MIN_STRONG_SINGLE or (len(c) >= MIN_STRONG and not c.isalpha()):
            if c not in strong:
                strong.append(c)
        elif term not in phrases:
            phrases.append(term)

    add(brand_name)
    bare = " ".join(w for w in _words(brand_name) if w not in _BRAND_STOP)
    if bare and bare != brand_name.lower().strip():
        add(bare)  # "The North Face" → also "north face", the way most ads write it
    add(brand_key)
    for k in ad_keywords:
        if not is_generic_phrase(k):  # "mountain jacket" says nothing about *which* brand
            add(k)
    product_names: list[str] = []
    for p in products:
        name = " ".join(str(p).split())
        if name and not is_generic_phrase(name):
            product_names.append(name)
            add(name)
    for d in official_domains:
        d = (d or "").lower().strip(".")
        if "." in d and len(d) >= 6 and d not in strong:
            strong.append(d)
    # a phrase that is itself a strong term adds nothing
    phrases = [p for p in phrases if compact(p) not in strong or " " in p]
    cats = categories_for(vertical, keywords)
    context = list(dict.fromkeys(w for c in cats for w in CATEGORY_WORDS[c]))
    sells = (vertical or ", ".join(cats) or "").strip()
    return BrandTerms(
        brand=brand_name,
        strong=tuple(strong),
        phrases=tuple(phrases),
        products=tuple(dict.fromkeys(product_names)),
        context=tuple(context),
        sells=sells,
        _strong_rx=tuple(
            term_pattern(s, prefix=True)
            if "." not in s
            else re.compile(r"(?<![a-z0-9\-])" + re.escape(s) + r"(?![a-z0-9])")
            for s in strong
        ),
        _phrase_rx=tuple(term_pattern(p, prefix=False) for p in phrases),
    )


def _quote(s: str) -> str:
    return f"“{s}”"


def standalone_phrase(p: str) -> bool:
    """A name of two or more long words ("north face", "golden goose") points to the brand by itself;
    one with a short word ("on cloud") can mean anything without a product word next to it."""
    ws = _words(p)
    return len(ws) >= 2 and all(len(w) >= 4 for w in ws) and not is_generic_phrase(p)


def ad_relevance(ad: dict, terms: BrandTerms) -> tuple[str, str]:
    """``("yes" | "maybe" | "no", why)`` for one ad: does it sell or promote this brand's products?"""
    if not terms.usable:
        return "yes", "no brand terms to check against"
    fields = {
        "the advertiser's page name": ad.get("page_name") or "",
        "the ad text": " ".join(str(ad.get(k) or "") for k in ("text", "title", "link_description")),
        "the link": url_words(ad.get("landing_url") or ad.get("link_url")),
    }
    found = {where: terms.find(text) for where, text in fields.items()}
    for where, f in found.items():
        if f["strong"]:
            return "yes", f"{where} names {_quote(f['strong'][0])}"
        sure = [p for p in f["phrases"] if standalone_phrase(p)]
        if sure:
            return "yes", f"{where} names {_quote(sure[0])}"
    phrases = [p for f in found.values() for p in f["phrases"]]
    context = [c for f in found.values() for c in f["context"]]
    if phrases and context:
        return "yes", f"{_quote(phrases[0])} together with {_quote(context[0])}"
    if phrases:
        what = terms.sells or "the brand's products"
        return "maybe", f"says {_quote(phrases[0])} but nothing about {what} — the words may mean something else"
    return "no", "the brand is not in the ad's text, page name or link — Meta matched the words in another sense"


def page_about_brand(text: str | None, title: str | None, terms: BrandTerms) -> str | None:
    """Why a page is about the brand (it names the brand / a product, or the brand's words next to
    what it sells), or ``None`` when it is not."""
    if not terms.usable:
        return "no brand terms to check against"
    blob = f"{title or ''} {text or ''}"
    f = terms.find(blob)
    if f["strong"]:
        return f"the page names {_quote(f['strong'][0])}"
    sure = [p for p in f["phrases"] if standalone_phrase(p)]
    if sure:
        return f"the page names {_quote(sure[0])}"
    if f["phrases"] and f["context"]:
        return f"the page says {_quote(f['phrases'][0])} next to {_quote(f['context'][0])}"
    return None


def product_lines_on_page(text: str | None, terms: BrandTerms) -> list[str]:
    """The brand's product names that appear on a page (each once, as the analyst wrote them)."""
    t = normalize(text)
    out = []
    for name in terms.products:
        if len(compact(name)) >= MIN_STRONG and term_pattern(name, prefix=True).search(t):
            out.append(name)
    return out


def mentions_brand(text: str | None, terms: BrandTerms) -> bool:
    f = terms.find(text or "")
    return bool(f["strong"] or f["phrases"])
