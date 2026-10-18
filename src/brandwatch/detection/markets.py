"""The markets a brand is searched in: countries, and in each country one or more languages.

Google answers differently by country and by language: a Hebrew phishing page for an Israeli brand is found by a Hebrew query on google.co.il, an
Italian one by an Italian query on google.it, and in the United States a kit can be written in English *and* Spanish. A *market* is one country
with its languages (``{"country": "us", "langs": ["en", "es"]}``); a scan runs every approved query once per (country, language) pair.

The older single fields ``search_geo`` ("us,il") and ``search_lang`` ("en") stay in the config and are kept in step with the markets (the
countries, and the first language), so an older client and the ads search (which only needs countries) keep working. A config without markets
means "every country in ``search_geo``, in ``search_lang``".
"""

from __future__ import annotations

import json
from typing import Any

# (code, name): the languages Google's ``hl`` parameter understands and that phishing kits are written in
LANGUAGES: tuple[tuple[str, str], ...] = (
    ("en", "English"), ("es", "Spanish"), ("he", "Hebrew"), ("ar", "Arabic"), ("fr", "French"), ("de", "German"), ("it", "Italian"),
    ("pt", "Portuguese"), ("nl", "Dutch"), ("ru", "Russian"), ("pl", "Polish"), ("tr", "Turkish"), ("uk", "Ukrainian"), ("cs", "Czech"),
    ("sv", "Swedish"), ("no", "Norwegian"), ("da", "Danish"), ("fi", "Finnish"), ("el", "Greek"), ("hu", "Hungarian"), ("ro", "Romanian"),
    ("bg", "Bulgarian"), ("sr", "Serbian"), ("hr", "Croatian"), ("sk", "Slovak"), ("sl", "Slovenian"), ("lt", "Lithuanian"),
    ("lv", "Latvian"), ("et", "Estonian"), ("ja", "Japanese"), ("ko", "Korean"), ("zh", "Chinese"), ("hi", "Hindi"), ("bn", "Bengali"),
    ("ur", "Urdu"), ("fa", "Persian"), ("id", "Indonesian"), ("ms", "Malay"), ("th", "Thai"), ("vi", "Vietnamese"), ("tl", "Filipino"),
    ("sw", "Swahili"), ("af", "Afrikaans"),
)  # fmt: skip
LANG_CODES = frozenset(c for c, _ in LANGUAGES)
# the language a country's searches start with when only the country is chosen
DEFAULT_LANG = {
    "us": "en", "gb": "en", "au": "en", "ca": "en", "ie": "en", "nz": "en", "za": "en", "in": "en", "sg": "en", "ph": "en", "ng": "en", "ke": "en",
    "il": "he", "de": "de", "at": "de", "ch": "de", "fr": "fr", "be": "fr", "lu": "fr", "es": "es", "mx": "es", "ar": "es", "cl": "es", "co": "es",
    "it": "it", "nl": "nl", "br": "pt", "pt": "pt", "pl": "pl", "ru": "ru", "by": "ru", "kz": "ru", "ua": "uk", "jp": "ja", "se": "sv",
    "no": "no", "dk": "da", "fi": "fi", "tr": "tr", "gr": "el", "cy": "el", "cz": "cs", "sk": "sk", "hu": "hu", "ro": "ro", "md": "ro",
    "bg": "bg", "rs": "sr", "hr": "hr", "si": "sl", "lt": "lt", "lv": "lv", "ee": "et", "kr": "ko", "cn": "zh", "tw": "zh", "hk": "zh",
    "ae": "ar", "sa": "ar", "eg": "ar", "ir": "fa", "pk": "ur", "bd": "bn", "id": "id", "my": "ms", "th": "th", "vn": "vi",
}  # fmt: skip
MAX_MARKETS, MAX_LANGS = 12, 4


def default_lang(country: str) -> str:
    return DEFAULT_LANG.get((country or "").strip().lower(), "en")


def _split(value: Any) -> list[str]:
    return [p.strip().lower() for p in str(value or "").replace(";", ",").split(",") if p.strip()]


def normalize(raw: Any) -> list[dict[str, Any]]:
    """Whatever came in (a JSON string, a list of ``{"country", "langs"}``) as a clean list: two-letter lower-case countries, known languages,
    no duplicates, at most 12 countries and 4 languages each. A country without a valid language gets its default."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw) if raw.strip() else []
        except ValueError:
            return []
    out: dict[str, list[str]] = {}
    for m in raw if isinstance(raw, list) else []:
        if not isinstance(m, dict):
            continue
        cc = str(m.get("country") or "").strip().lower()
        if len(cc) != 2 or not cc.isalpha():
            continue
        langs = m.get("langs") if m.get("langs") is not None else m.get("lang")
        want = [str(x).strip().lower() for x in (langs if isinstance(langs, list) else _split(langs))]
        mine = out.setdefault(cc, [])
        for lang in want:
            if lang in LANG_CODES and lang not in mine:
                mine.append(lang)
    result = []
    for cc, langs in out.items():
        langs = langs[:MAX_LANGS] or [default_lang(cc)]
        result.append({"country": cc, "langs": langs})
    return result[:MAX_MARKETS]


def pairs(search_geo: str | None, search_lang: str | None, markets: Any = None) -> list[tuple[str, str]]:
    """Every (country, language) a scan searches, in order, without duplicates."""
    mk = normalize(markets) if markets else []
    if mk:
        flat = [(m["country"], lang) for m in mk for lang in m["langs"]]
    else:
        lang = ((search_lang or "en").strip().lower() or "en")
        flat = [(g, lang) for g in (_split(search_geo) or ["us"])]
    return list(dict.fromkeys(flat))


def countries(prs: list[tuple[str, str]]) -> list[str]:
    return list(dict.fromkeys(c for c, _ in prs))


def describe(prs: list[tuple[str, str]]) -> str:
    """``US (en, es) · IL (he)``"""
    by: dict[str, list[str]] = {}
    for c, lang in prs:
        by.setdefault(c, []).append(lang)
    return " · ".join(f"{c.upper()} ({', '.join(ls)})" for c, ls in by.items())


# a country-code TLD that is not its ISO code, and ccTLDs sold as generic names (.co, .io, .tv …: not a country)
_CC_ALIAS = {"uk": "gb"}
_NOT_A_COUNTRY = {"co", "io", "tv", "me", "ai", "fm", "ly", "to", "cc", "ws", "gg", "sh", "ac", "eu", "app", "dev"}


def for_domain(domain: str) -> list[dict[str, Any]]:
    """The markets an official domain points to: ``shopnova.co.il`` → Israel in Hebrew and English. A generic TLD (.com,
    .net) or a ccTLD sold as a generic name (.io, .co) says nothing: empty."""
    host = (domain or "").strip().lower().rstrip(".").split("/")[0]
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if len(tld) != 2 or tld in _NOT_A_COUNTRY:
        return []
    cc = _CC_ALIAS.get(tld, tld)
    if cc not in DEFAULT_LANG:
        return []
    lang = default_lang(cc)
    return normalize([{"country": cc, "langs": [lang] + (["en"] if lang != "en" else [])}])


def tld_markets() -> dict[str, list[dict[str, Any]]]:
    """{"il": [{"country": "il", "langs": ["he", "en"]}], "uk": …} for every country-code TLD :func:`for_domain` knows."""
    out = {tld: for_domain(f"x.{tld}") for tld in [*DEFAULT_LANG, *_CC_ALIAS]}
    return {k: v for k, v in out.items() if v}


def legacy(markets: list[dict[str, Any]]) -> tuple[str, str]:
    """The ``search_geo`` / ``search_lang`` a list of markets stands for: all the countries, and the language of the first."""
    if not markets:
        return "us", "en"
    return ",".join(m["country"] for m in markets), markets[0]["langs"][0]


def from_legacy(search_geo: str | None, search_lang: str | None) -> list[dict[str, Any]]:
    """The markets the older two fields mean (what the picker starts from)."""
    return normalize([{"country": c, "langs": [lang]} for c, lang in pairs(search_geo, search_lang)])
