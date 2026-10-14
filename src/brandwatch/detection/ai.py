"""LLM-assisted analysis (spec §8 co-hosted triage step 3, §11 onboarding, §5 "AI as augmentation,
never source of truth"), Phase 5.

Three uses, all **advisory**:

* ``second_opinion`` — for Medium+ findings: "is this page phishing, which brand?". Shown in Explain
  Finding next to the score; it never changes the score or the severity.
* ``triage_page``    — co-hosted triage during investigation: a neighbour on the kit's server with no
  link signals is classified; only a confident "phishing for *this* brand" verdict includes it, and
  "phishing for another brand" is recorded as threat intel (the actor hits other brands too).
* ``brand_profile``  — onboarding: expected keywords and lure phrases for the brand; validated
  (lower-case words, length and count limits) before it touches the baseline.

Page text is attacker-controlled: it is truncated, framed as data, and the model must answer in a
strict JSON schema. A provider failure simply means "no AI opinion".
"""

from __future__ import annotations

import re
from typing import Any

from brandwatch.detection.relevance import (  # noqa: F401
    _BRAND_STOP,
    GENERIC_WORDS,
    _words,
    is_generic_phrase,
)
from brandwatch.providers.registry import ProviderRegistry

MAX_TEXT_CHARS = 4000

TRIAGE_SCHEMA: dict[str, Any] = {
    "title": "phishing_triage",
    "type": "object",
    "properties": {
        "is_phishing": {"type": "boolean"},
        "impersonated_brand": {"type": ["string", "null"]},
        "confidence": {"type": "number"},
        "rationale": {"type": "string"},
    },
    "required": ["is_phishing", "impersonated_brand", "confidence", "rationale"],
    "additionalProperties": False,
}

BRAND_PROFILE_SCHEMA: dict[str, Any] = {
    "title": "brand_profile",
    "type": "object",
    "properties": {
        "keywords": {"type": "array", "items": {"type": "string"}},
        "lures": {"type": "array", "items": {"type": "string"}},
        "search_queries": {"type": "array", "items": {"type": "string"}},
        "vertical": {"type": "string"},
    },
    "required": ["keywords", "lures", "search_queries", "vertical"],
    "additionalProperties": False,
}

_KW = re.compile(r"^[a-z0-9][a-z0-9 \-]{1,28}[a-z0-9]$")


def page_brief(
    *,
    url: str,
    title: str | None,
    text: str,
    forms: list[dict[str, Any]],
    brand_hint: str | None = None,
) -> str:
    """The *data* the model sees. Untrusted content is clearly delimited and truncated."""
    form_lines = (
        "; ".join(
            f"form(password={f.get('has_password')}, card={f.get('has_card')}, seed={f.get('has_seed')}, external_action={f.get('external_action')})"
            for f in forms
        )
        or "no forms"
    )
    hint = f"Brand under protection: {brand_hint}\n" if brand_hint else ""
    return (
        f"{hint}URL: {url}\nTitle: {title or '-'}\nForms: {form_lines}\n"
        f"--- BEGIN UNTRUSTED PAGE TEXT ---\n{(text or '')[:MAX_TEXT_CHARS]}\n--- END UNTRUSTED PAGE TEXT ---"
    )


def _forms(features) -> list[dict[str, Any]]:
    if features is None:
        return []
    return [
        {
            "has_password": f.has_password,
            "has_card": f.has_card,
            "has_seed": f.has_seed,
            "external_action": f.external_action,
        }
        for f in features.forms
    ]


def _clean_verdict(data: dict[str, Any], provider: str) -> dict[str, Any] | None:
    try:
        conf = float(data.get("confidence", 0))
    except (TypeError, ValueError):
        return None
    brand = data.get("impersonated_brand")
    return {
        "is_phishing": bool(data.get("is_phishing")),
        "impersonated_brand": str(brand)[:80] if brand else None,
        "confidence": max(0.0, min(1.0, conf)),
        "rationale": str(data.get("rationale", ""))[:400],
        "model": provider,
        "advisory": True,
    }


async def second_opinion(
    providers: ProviderRegistry, *, url: str, features, brand_name: str
) -> dict[str, Any] | None:
    brief = page_brief(url=url, title=features.title if features else None, text=features.text_excerpt if features else "",
                       forms=_forms(features), brand_hint=brand_name)  # fmt: skip
    res = await providers.llm().analyze(brief, TRIAGE_SCHEMA)
    if not res.ok or not res.data:
        return None
    return _clean_verdict(res.data, res.provider)


async def triage_page(
    providers: ProviderRegistry, *, url: str, html_features, brand_name: str
) -> dict[str, Any] | None:
    return await second_opinion(providers, url=url, features=html_features, brand_name=brand_name)


def misspellings(key: str) -> list[str]:
    """The typos people make in a brand token: a space inside ("crypto hopper"), a squeezed
    double letter ("cryptohoper"), two adjacent letters swapped ("crytpohopper")."""
    out: list[str] = []
    if len(key) >= 8:
        mid = len(key) // 2
        out.append(key[:mid] + " " + key[mid:])
    squeezed = re.sub(r"(.)\1", r"\1", key)
    if squeezed != key:
        out.append(squeezed)
    if len(key) >= 6:
        i = len(key) // 2
        out.append(key[: i - 1] + key[i] + key[i - 1] + key[i + 1 :])
    return [x for x in dict.fromkeys(out) if x and x != key]


# Search intent words per kind of business. A shoe brand's customers search "sale" and "outlet",
# not "wallet" or "bonus" — those belong to crypto, banking and betting brands only.
SERVICE_INTENTS = ("login", "sign in", "sign up", "support", "app", "official site")
RETAIL_INTENTS = ("sale", "outlet", "discount", "official store", "buy online", "login")
_FINANCE_VERTICAL = re.compile(
    r"crypto|bitcoin|blockchain|defi|nft|bank|financ|fintech|payment|wallet|trading|exchange|broker|"
    r"forex|invest|lend|loan|insur|casino|betting|gambl|poker|lottery|gaming",
    re.I,
)
_FINANCE_ONLY = re.compile(
    r"\b(wallet|withdraw\w*|deposit\w*|airdrop|staking|stake|seed phrase|recovery phrase|bonus\w*|"
    r"free spins?|cashback)\b"
)


def finance_like(vertical: str | None) -> bool:
    return bool(vertical and _FINANCE_VERTICAL.search(vertical))


def fit_queries(queries: list[str], *, vertical: str | None, kind: str | None) -> list[str]:
    """Drop search queries / lures whose intent does not fit the business: "wallet", "deposit",
    "bonus" … only for crypto, banking, payments and betting brands. Also cleans lists saved before
    this rule existed (an "on cloud wallet" query for a shoe brand)."""
    if finance_like(vertical) and (kind or "service") != "retail":
        return list(queries)
    return [q for q in queries if not _FINANCE_ONLY.search(q.lower())]


_SHOPPING = re.compile(r"\b(sale|outlet|discount|store|shop|buy|cheap|price|deal)s?\b")


def shopping_first(queries: list[str], brand_name: str, key: str) -> list[str]:
    """A retail brand's saved queries from before the business-aware prompt are all "login / sign
    in / support": put the shopping ones (sale, outlet, discount …) first until the next rebuild."""
    if any(_SHOPPING.search(q) for q in queries):
        return list(queries)
    shopping = [q for q in default_search_queries(brand_name, key, "retail") if _SHOPPING.search(q)]
    return list(dict.fromkeys(shopping + list(queries)))


def default_search_queries(brand_name: str, key: str, kind: str | None = None) -> list[str]:
    """What victims type and impersonators target in Google, when no LLM is configured:
    the brand with intent words that fit the business, plus its most common misspellings."""
    name = " ".join(brand_name.lower().split()) or key
    retail = (kind or "service") == "retail"
    out = [f"{name} {i}" for i in (RETAIL_INTENTS if retail else SERVICE_INTENTS)]
    for variant in misspellings(key)[:3]:
        out += [f"{variant} {'sale' if retail else 'login'}", variant]
    return validate_phrases(out, limit=15)


def validate_keywords(items: list[Any], *, limit: int = 20) -> list[str]:
    out: list[str] = []
    for raw in items:
        kw = str(raw).strip().lower()
        if _KW.match(kw) and kw not in out:
            out.append(kw)
        if len(out) >= limit:
            break
    return out


_PHRASE = re.compile(r"^[a-z0-9][a-z0-9 ,'\-]{2,58}[a-z0-9]$")


def validate_phrases(items: list[Any], *, limit: int = 15) -> list[str]:
    out: list[str] = []
    for raw in items:
        p = " ".join(str(raw).strip().lower().split())
        if _PHRASE.match(p) and p not in out:
            out.append(p)
        if len(out) >= limit:
            break
    return out


async def brand_profile(
    providers: ProviderRegistry, *, brand_name: str, homepage_text: str, kind: str | None = None
) -> dict[str, Any] | None:
    retail = (kind or "service") == "retail"
    business = (
        "This brand sells physical products that other shops also resell. "
        if retail
        else "Work out from the page what kind of business this is. "
    )
    brief = (
        f"Brand: {brand_name}\nTask: {business}List the words a customer associates with this brand (product "
        "names, slogans), the business vertical in 2-4 words (e.g. 'footwear and apparel', 'crypto trading "
        "bot', 'online bank'), and the lure phrases impostors would likely use. Also list 8-15 Google search "
        "queries (lowercase) that a customer of THIS business might type and an impostor would target. Choose "
        "the intent words from the business type:\n"
        "- online accounts / software: login, sign in, sign up, support, app\n"
        "- crypto, banking, payments, trading: login, wallet, withdraw, deposit, support, app\n"
        "- betting / casino / games: login, bonus, promo code, deposit\n"
        "- brands whose products people buy (shoes, clothes, electronics, cosmetics): sale, outlet, discount, "
        "official store, buy online, a product line + sale, and at most one login\n"
        "Never use intent words that do not fit the business (no 'wallet' or 'bonus' for a shoe brand). Add "
        "3-5 common misspellings of the brand name (a missing or doubled letter, a space inside the name).\n"
        f"--- BEGIN UNTRUSTED PAGE TEXT ---\n{(homepage_text or '')[:MAX_TEXT_CHARS]}\n--- END UNTRUSTED PAGE TEXT ---"
    )
    res = await providers.llm().analyze(brief, BRAND_PROFILE_SCHEMA)
    if not res.ok or not res.data:
        return None
    vertical = str(res.data.get("vertical", ""))[:40].lower() or None
    key = re.sub(r"[^a-z0-9]", "", brand_name.lower())
    queries = fit_queries(
        validate_phrases(res.data.get("search_queries", []), limit=15), vertical=vertical, kind=kind
    )
    if len(queries) < 5:  # the filter emptied it: top up with the defaults for this kind of business
        queries = validate_phrases(queries + default_search_queries(brand_name, key, kind), limit=15)
    return {
        "keywords": validate_keywords(res.data.get("keywords", [])),
        "lures": fit_queries(validate_phrases(res.data.get("lures", [])), vertical=vertical, kind=kind),
        "search_queries": queries,
        "vertical": vertical,
        "model": res.provider,
    }


# --------------------------------------------------------------------------- suspicious shops
# A brand whose products other shops resell (shoes, electronics) is impersonated differently from a
# login page: scam shops advertise the products on Facebook / Instagram and ship replicas. These two
# questions are advisory like everything here — the analyst confirms the profile, and the shop
# verdict is shown next to the deterministic shop score, never inside it.

COMMERCE_PROFILE_SCHEMA: dict[str, Any] = {
    "title": "brand_commerce_profile",
    "type": "object",
    "properties": {
        "resold_by_retailers": {"type": "boolean"},
        "why": {"type": "string"},
        "ad_keywords": {"type": "array", "items": {"type": "string"}},
        "model_lines": {"type": "array", "items": {"type": "string"}},
        "products": {"type": "array", "items": {
            "type": "object",
            "properties": {"name": {"type": "string"}, "typical_price": {"type": "number"},
                           "currency": {"type": "string"}, "country": {"type": "string"}},
            "required": ["name", "typical_price", "currency", "country"], "additionalProperties": False}},
        "authorized_retailers": {"type": "array", "items": {
            "type": "object",
            "properties": {"name": {"type": "string"}, "domain": {"type": "string"}, "country": {"type": "string"}},
            "required": ["name", "domain", "country"], "additionalProperties": False}},
    },
    "required": ["resold_by_retailers", "why", "ad_keywords", "model_lines", "products", "authorized_retailers"],
    "additionalProperties": False,
}  # fmt: skip

AD_RELEVANCE_SCHEMA: dict[str, Any] = {
    "title": "ad_relevance",
    "type": "object",
    "properties": {
        "ads": {"type": "array", "items": {
            "type": "object",
            "properties": {"id": {"type": "string"}, "about_brand": {"type": "boolean"}, "why": {"type": "string"}},
            "required": ["id", "about_brand", "why"], "additionalProperties": False}},
    },
    "required": ["ads"],
    "additionalProperties": False,
}  # fmt: skip


async def ads_about_brand(
    providers: ProviderRegistry,
    *,
    brand_name: str,
    sells: str,
    products: list[str],
    keyword: str,
    ads: list[dict[str, Any]],
) -> dict[str, tuple[bool, str]] | None:
    """For ads that contain the brand's words but nothing else that ties them to the brand: does
    each one sell or promote this brand's products? ``{ad_id: (about_brand, why)}``, or ``None``
    when no AI is configured / it did not answer (the caller then skips those ads)."""
    if not ads:
        return {}
    lines = []
    for ad in ads[:30]:
        text = " ".join(str(ad.get("text") or "").split())[:300]
        lines.append(f"[{ad.get('ad_id')}] page: {str(ad.get('page_name') or '')[:60]} | link: "
                     f"{str(ad.get('landing_url') or '')[:100]} | text: {text}")  # fmt: skip
    brief = (
        f"Brand: {brand_name}\nWhat it sells: {sells or 'products'}\n"
        f"Its product names: {', '.join(products[:12]) or '-'}\n"
        f"Each ad below matched the words “{keyword}” in Meta's Ad Library. For each ad decide whether "
        "it sells or promotes THIS brand's products (genuine or fake). An ad that uses the words in another "
        "sense (cloud storage, 'on cloud nine', apps, games, series, unrelated products) is NOT about the "
        "brand. Answer for every id.\n--- BEGIN UNTRUSTED ADS ---\n"
        + "\n".join(lines)
        + "\n--- END UNTRUSTED ADS ---"
    )
    res = await providers.llm().analyze(brief, AD_RELEVANCE_SCHEMA)
    if not res.ok or not res.data:
        return None
    wanted = {str(a.get("ad_id")) for a in ads}
    out: dict[str, tuple[bool, str]] = {}
    for row in res.data.get("ads") or []:
        if isinstance(row, dict) and str(row.get("id")) in wanted:
            out[str(row["id"])] = (bool(row.get("about_brand")), str(row.get("why") or "")[:160])
    return out


SOCIAL_SCHEMA: dict[str, Any] = {
    "title": "social_impersonation",
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["impersonation", "fan_or_community", "reseller_or_partner", "unrelated", "unclear"]},
        "confidence": {"type": "number"},
        "claims_to_be_brand": {"type": "boolean"},
        "asks_for": {"type": "array", "items": {"type": "string"}},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
    },
    "required": ["verdict", "confidence", "claims_to_be_brand", "asks_for", "reasons", "summary"],
    "additionalProperties": False,
}  # fmt: skip
SOCIAL_VERDICTS = ("impersonation", "fan_or_community", "reseller_or_partner", "unrelated", "unclear")


async def social_verdict(providers: ProviderRegistry, *, brief: str) -> dict[str, Any] | None:
    """Does this Facebook page / Instagram profile pose as the brand? Reads the public content
    (name, bio, about text, links, recent posts, page history). Shown with its reasons; it is one
    capped signal of the separate social score, and "unrelated" keeps the account out of findings."""
    res = await providers.llm().analyze(brief, SOCIAL_SCHEMA)
    if not res.ok or not res.data:
        return None
    d = res.data
    try:
        conf = max(0.0, min(1.0, float(d.get("confidence", 0))))
    except (TypeError, ValueError):
        conf = 0.0
    verdict = d.get("verdict") if d.get("verdict") in SOCIAL_VERDICTS else "unclear"
    return {
        "verdict": verdict, "confidence": conf, "claims_to_be_brand": bool(d.get("claims_to_be_brand")),
        "asks_for": [str(x)[:60] for x in d.get("asks_for") or []][:6],
        "reasons": [str(x)[:200] for x in d.get("reasons") or []][:6],
        "summary": str(d.get("summary") or "")[:400], "model": res.provider, "advisory": True,
    }  # fmt: skip


SHOP_LEGITIMACY_SCHEMA: dict[str, Any] = {
    "title": "shop_legitimacy",
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["legitimate", "suspicious", "likely_scam"]},
        "sells_replicas_likely": {"type": "boolean"},
        "confidence": {"type": "number"},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "review_summary": {"type": "string"},
    },
    "required": ["verdict", "sells_replicas_likely", "confidence", "reasons", "review_summary"],
    "additionalProperties": False,
}

_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def clean_term(raw: Any, *, max_len: int = 60) -> str | None:
    """A short free-text term in any script (ad keywords are often not English)."""
    t = " ".join(str(raw or "").split()).strip().lower()
    if len(t) < 2 or len(t) > max_len or any(ord(c) < 32 for c in t):
        return None
    return t


def clean_domain(raw: Any) -> str | None:
    d = str(raw or "").strip().lower()
    d = re.sub(r"^https?://", "", d).split("/")[0].removeprefix("www.")
    return d if _DOMAIN.match(d) else None


def clean_country(raw: Any) -> str | None:
    c = str(raw or "").strip().upper()
    return {"UK": "GB"}.get(c, c) if re.fullmatch(r"[A-Z]{2}", c) else None


def brand_specific(term: str, brand_name: str, models: list[str] | tuple[str, ...] = ()) -> bool:
    """Does this keyword point to the brand alone — its name (or every distinctive word of it), or one
    of its own model names? "the north face nuptse", "north face", "nuptse" yes; "mountain jacket" no."""
    compact = lambda s: re.sub(r"[\W_]+", "", (s or "").lower())  # noqa: E731
    c = compact(term)
    if not c:
        return False
    words = _words(brand_name)
    names = {compact(brand_name), compact(" ".join(w for w in words if w not in _BRAND_STOP))}
    initials = "".join(w[0] for w in words if w)  # "the north face" → tnf
    if len(words) >= 3 and len(initials) >= 3 and c == initials:
        return True
    if any(n and len(n) >= 3 and n in c for n in names):
        return True
    if any(compact(m) and len(compact(m)) >= 3 and compact(m) in c for m in models):
        return True
    distinctive = [w for w in _words(brand_name) if w not in _BRAND_STOP and w not in GENERIC_WORDS and len(w) >= 3]
    ws = set(_words(term))
    return bool(distinctive) and all(w in ws for w in distinctive)


async def commerce_profile(
    providers: ProviderRegistry, *, brand_name: str, domain: str | None, countries: list[str]
) -> dict[str, Any] | None:
    """Is this a brand whose products other shops resell? Which words do ads for them use, what do
    they cost officially in each chosen country, and which retailers are authorised there?
    From the model's own knowledge — nothing is fetched — and always shown as a suggestion."""
    brief = (
        f"Brand: {brand_name}\nOfficial site: {domain or '-'}\nCountries: {', '.join(countries) or 'US'}\n"
        "Task: (1) Are this brand's physical products commonly sold by third-party shops and retailers "
        "(true for shoe, clothing or electronics brands; false for software, finance or service brands)? "
        "(2) model_lines: the names of the brand's OWN product lines and models that no other brand uses "
        "(for The North Face: nuptse, denali, thermoball, mcmurdo; for On: cloudmonster, cloudnova) — an empty "
        "list if the brand has none. (3) Up to 8 ad keywords, lower-case, in the language the ads use: the brand's "
        "name and its common spellings / abbreviations, and model_lines. Every keyword must point to THIS brand "
        "only — NEVER a generic product or category phrase such as 'mountain jacket', 'hiking boots', "
        "'running shoes' or 'thermal fleece' (those find every brand's ads). (4) For each country, 3-6 of the "
        "best-known products, named as the brand names them (e.g. 'The North Face 1996 Retro Nuptse Jacket', "
        "never a category), with the typical official retail price per single item, in the local currency (ISO). "
        "(5) Authorised retailers per country (name and website domain) — only ones you are confident about; "
        "an empty list is fine."
    )
    res = await providers.llm().analyze(brief, COMMERCE_PROFILE_SCHEMA)
    if not res.ok or not res.data:
        return None
    d = res.data
    # the brand's own model / line names — a line made only of category words is not one
    models: list[str] = []
    for m in d.get("model_lines") or []:
        t = clean_term(m)
        if t and not is_generic_phrase(t) and t not in models:
            models.append(t)
    # keywords that point to this brand only: its name, or one of its own models
    keywords: list[str] = []
    dropped: list[str] = []
    for k in [brand_name, *(d.get("ad_keywords") or []), *models]:
        t = clean_term(k)
        if not t or t in keywords or t in dropped:
            continue
        (keywords if brand_specific(t, brand_name, models) else dropped).append(t)
    products = []
    for p in d.get("products") or []:
        raw_name = clean_term(p.get("name"), max_len=80)
        if raw_name and not brand_specific(raw_name, brand_name, models):
            raw_name = clean_term(f"{brand_name} {raw_name}", max_len=80)  # "mountain jacket" → the brand's one
        name, cur, country = (
            raw_name,
            str(p.get("currency") or "").upper(),
            clean_country(p.get("country")),
        )
        try:
            price = float(p.get("typical_price"))
        except (TypeError, ValueError):
            continue
        if name and re.fullmatch(r"[A-Z]{3}", cur) and country and 0 < price < 100_000:
            products.append(
                {
                    "name": name,
                    "price": round(price, 2),
                    "currency": cur,
                    "country": country,
                    "source": "ai",
                }
            )
    retailers = []
    for r in d.get("authorized_retailers") or []:
        dom, country = clean_domain(r.get("domain")), clean_country(r.get("country"))
        if dom and country and not any(x["domain"] == dom for x in retailers):
            retailers.append(
                {"name": str(r.get("name") or dom)[:80], "domain": dom, "country": country}
            )
    return {
        "resold_by_retailers": bool(d.get("resold_by_retailers")),
        "why": str(d.get("why") or "")[:300],
        "ad_keywords": keywords[:8],
        "model_lines": models[:12],
        "dropped_keywords": dropped[:12],
        "products": products[:30],
        "authorized_retailers": retailers[:30],
        "model": res.provider,
    }  # fmt: skip


async def shop_legitimacy(providers: ProviderRegistry, *, brief: str) -> dict[str, Any] | None:
    """ "Is this web shop legitimate?" — the question an analyst asked a chatbot by hand, asked with the
    evidence BrandWatch collected. Advisory only."""
    res = await providers.llm().analyze(brief, SHOP_LEGITIMACY_SCHEMA)
    if not res.ok or not res.data:
        return None
    d = res.data
    verdict = (
        d.get("verdict")
        if d.get("verdict") in ("legitimate", "suspicious", "likely_scam")
        else "suspicious"
    )
    try:
        conf = max(0.0, min(1.0, float(d.get("confidence", 0))))
    except (TypeError, ValueError):
        conf = 0.0
    return {
        "verdict": verdict,
        "sells_replicas_likely": bool(d.get("sells_replicas_likely")),
        "confidence": round(conf, 2),
        "reasons": [str(r)[:200] for r in (d.get("reasons") or [])][:6],
        "review_summary": str(d.get("review_summary") or "")[:500],
        "model": res.provider,
        "advisory": True,
    }
