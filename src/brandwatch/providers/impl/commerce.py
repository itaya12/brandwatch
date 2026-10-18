"""Connectors for the suspicious-shop checks.

* **SearchApi.io — Meta Ad Library** (kind ``ads``): ads on Facebook / Instagram that match a keyword
  in one country. Meta's own Ad Library API returns commercial ads only when they ran in the EU/UK,
  so a third-party API is the only way to search, say, Israel.
* **Business registries** (kind ``registry``) — does the company number printed on a shop exist?
  Free, official sources first; each one covers some countries and answers ``NOT_APPLICABLE`` for
  the rest, so "no registry for this country" is never read as "valid":

  ========================  =========  =============================================
  il_companies              keyless    Israel — Registrar of Companies on data.gov.il
  companies_house           free key   United Kingdom
  vies                      keyless    EU VAT numbers (and Northern Ireland, XI)
  gleif                     keyless    any country, by company name — LEI holders only
  opencorporates            paid key   140+ jurisdictions (off unless a key is added)
  ========================  =========  =============================================

Result statuses: ``POSITIVE`` = found (``data.status`` "active" or "dissolved"), ``NEGATIVE`` = the
registry has no such number, ``NOT_APPLICABLE`` = not this registry's country / kind of number,
``UNKNOWN`` = asked but no usable answer.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

import httpx

from brandwatch.db.enums import ProviderStatus
from brandwatch.providers.base import ProviderError, ProviderResult
from brandwatch.providers.impl.clients import _UA, HttpClientMixin, _ipv4_transport

EU_VAT_COUNTRIES = frozenset(
    "AT BE BG CY CZ DE DK EE EL ES FI FR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK XI".split()
)


def _na(name: str, why: str) -> ProviderResult:
    return ProviderResult(
        name, ProviderStatus.NOT_APPLICABLE, {"status": "not_checked", "why": why}
    )


# ------------------------------------------------------------------------------------ social accounts
def _walk(obj: Any, key: str) -> list[Any]:
    """Every value stored under ``key`` anywhere in a JSON tree (the page-info answer nests its
    transparency data at different depths depending on the page)."""
    out: list[Any] = []
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k == key:
                    out.append(v)
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


def _first(obj: Any, *keys: str) -> Any:
    for k in keys:
        for v in _walk(obj, k):
            if v not in (None, "", [], {}):
                return v
    return None


def _iso(v: Any) -> str | None:
    """Unix seconds or an ISO string → ``YYYY-MM-DD``."""
    if v in (None, ""):
        return None
    if isinstance(v, (int, float)) or (isinstance(v, str) and v.isdigit()):
        import datetime as _dt

        return _dt.datetime.fromtimestamp(int(v), tz=_dt.UTC).date().isoformat()
    return str(v)[:10]


class SocialMixin:
    """SearchApi.io engines for social accounts (kind ``social``), same key as the ads engine:

    * ``meta_ad_library_page_search`` — Facebook pages by name: likes, verification, linked IG.
    * ``meta_ad_library_page_info`` — one page: about text, creation date, name changes, the
      countries its admins are in (Meta's page-transparency data).
    * ``instagram_profile`` — one profile: bio, links, followers, verification, recent posts.
    Only public data an API returns; BrandWatch never logs in to Facebook or Instagram."""

    async def _social(self, params: dict[str, Any]) -> tuple[Any, int]:
        if not self._api_key:
            raise ProviderError("searchapi: no API key", retryable=False)
        raw, latency = await self._get(self.URL, params=params, headers={"Authorization": f"Bearer {self._api_key}"})
        if isinstance(raw, dict) and raw.get("error"):
            raise ProviderError(f"searchapi: {str(raw['error'])[:160]}", retryable=False)
        return raw, latency

    @staticmethod
    def normalize_page(p: dict[str, Any]) -> dict[str, Any] | None:
        pid = str(p.get("page_id") or p.get("id") or "")
        if not pid:
            return None
        alias = p.get("page_alias") or None
        ver = str(p.get("verification") or p.get("page_verification") or "")
        return {
            "platform": "facebook", "page_id": pid, "name": p.get("name") or p.get("page_name") or "",
            "alias": alias, "category": p.get("category") or p.get("page_category"), "verified": ver.upper() == "BLUE_VERIFIED",
            "verification": ver or None, "entity_type": p.get("entity_type"), "image": p.get("image_uri") or p.get("profile_photo"),
            "likes": p.get("likes"), "ig_username": p.get("ig_username") or None, "ig_followers": p.get("ig_followers"),
            "url": f"https://www.facebook.com/{alias or pid}",
        }  # fmt: skip

    async def page_search(self, query: str, country: str = "ALL") -> ProviderResult:
        raw, latency = await self._social({"engine": "meta_ad_library_page_search", "q": query,
                                           "country": (country or "ALL").upper(), "ad_type": "all"})  # fmt: skip
        pages = [x for x in (self.normalize_page(p) for p in (raw or {}).get("page_results") or []) if x]
        return self._result(ProviderStatus.POSITIVE if pages else ProviderStatus.UNKNOWN,
                            {"query": query, "pages": pages}, {"page_results": ((raw or {}).get("page_results") or [])[:30]},
                            latency, cost=self.cost_per_call)  # fmt: skip

    async def page_info(self, page_id: str) -> ProviderResult:
        raw, latency = await self._social({"engine": "meta_ad_library_page_info", "page_id": str(page_id)})
        history = [h for items in _walk(raw, "history_items") if isinstance(items, list) for h in items if isinstance(h, dict)]
        created = next((_iso(h.get("event_time")) for h in history if str(h.get("item_type", "")).upper() == "CREATION"), None)
        renames = [{"at": _iso(h.get("event_time")), "item": h.get("item_type")} for h in history
                   if str(h.get("item_type", "")).upper() == "NAME_CHANGE"]
        counts: dict[str, int] = {}
        for rows in _walk(raw, "admin_country_counts"):
            for r in rows if isinstance(rows, list) else []:
                if isinstance(r, dict) and r.get("country"):
                    counts[str(r["country"]).upper()[:2]] = int(r.get("count") or r.get("admin_count") or 1)
        about = _first(raw, "about")
        about_text = about.get("text") if isinstance(about, dict) else about
        ver = str(_first(raw, "page_verification", "verification") or "")
        data = {
            "platform": "facebook", "page_id": str(page_id), "name": _first(raw, "page_name", "name"),
            "about": str(about_text or "")[:1500], "created": created, "name_changes": renames, "admin_countries": counts,
            "verified": ver.upper() == "BLUE_VERIFIED", "verification": ver or None, "likes": _first(raw, "likes"),
            "category": _first(raw, "page_category", "category"), "ig_username": _first(raw, "ig_username"),
            "ig_followers": _first(raw, "ig_followers"), "image": _first(raw, "profile_photo", "image_uri"),
            "owner": (_first(raw, "confirmed_page_owner") or {}).get("name") if isinstance(_first(raw, "confirmed_page_owner"), dict) else None,
        }  # fmt: skip
        return self._result(ProviderStatus.POSITIVE, data, raw if isinstance(raw, dict) else None, latency, cost=self.cost_per_call)

    async def instagram_profile(self, username: str) -> ProviderResult:
        raw, latency = await self._social({"engine": "instagram_profile", "username": username.lstrip("@")})
        prof = (raw or {}).get("profile") or {}
        if not prof:
            return self._result(ProviderStatus.UNKNOWN, {"username": username, "found": False}, raw, latency, cost=self.cost_per_call)
        posts = [{"caption": str(x.get("caption") or "")[:400], "permalink": x.get("permalink"), "date": str(x.get("iso_date") or "")[:10],
                  "likes": x.get("likes"), "comments": x.get("comments")} for x in ((raw or {}).get("posts") or [])[:12] if isinstance(x, dict)]
        data = {
            "platform": "instagram", "found": True, "username": prof.get("username") or username, "name": prof.get("name") or "",
            "bio": str(prof.get("bio") or "")[:600], "image": prof.get("avatar_hd") or prof.get("avatar"),
            "verified": bool(prof.get("is_verified")), "business": bool(prof.get("is_business")),
            "followers": prof.get("followers"), "following": prof.get("following"), "posts_count": prof.get("posts"),
            "external_link": prof.get("external_link"), "bio_links": [b.get("url") for b in prof.get("bio_links") or [] if isinstance(b, dict) and b.get("url")],
            "posts": posts, "url": f"https://www.instagram.com/{prof.get('username') or username}/",
        }  # fmt: skip
        return self._result(ProviderStatus.POSITIVE, data, {"profile": prof, "posts": ((raw or {}).get("posts") or [])[:12]},
                            latency, cost=self.cost_per_call)  # fmt: skip


# ------------------------------------------------------------------------------------ AI answers
AI_ENGINES = ("chatgpt", "gemini", "google_ai_mode")


def normalize_ai_answer(engine: str, prompt: str, raw: dict[str, Any] | None) -> dict[str, Any]:
    """One SearchApi AI answer → ``{engine, prompt, answer, references[{title, link, snippet, source}],
    conversation_token, model, web_search}``. ``answer`` is the full markdown (the text blocks joined
    when the engine sends no markdown)."""
    raw = raw or {}
    text = str(raw.get("markdown") or "").strip()
    if not text:
        parts: list[str] = []
        for b in raw.get("text_blocks") or []:
            if not isinstance(b, dict):
                continue
            if b.get("answer"):
                parts.append(str(b["answer"]))
            for it in b.get("items") or []:
                parts.append("- " + str(it.get("answer") if isinstance(it, dict) else it))
        text = "\n".join(parts).strip()
    refs = []
    for r in raw.get("reference_links") or []:
        if isinstance(r, dict) and r.get("link"):
            refs.append({"title": str(r.get("title") or "")[:200], "link": str(r["link"])[:500],
                         "snippet": str(r.get("snippet") or "")[:400], "source": str(r.get("source") or "")[:80]})  # fmt: skip
    meta = raw.get("response_metadata") or {}
    token = ((raw.get("pagination") or {}).get("conversation_token")) or meta.get("conversation_token")
    return {
        "engine": engine, "prompt": prompt, "answer": text[:12000], "references": refs[:20],
        "conversation_token": token, "model": meta.get("model"),
        "web_search": bool(meta.get("is_web_search_performed", engine != "chatgpt")),
    }  # fmt: skip


class AiAnswersMixin:
    """SearchApi.io engines for what AI assistants tell their users (kind ``ai_answers``), same key:

    * ``chatgpt`` — ChatGPT with web search on (``web_search=true``): answer, ``reference_links``,
      ``citations`` that point into them.
    * ``gemini`` — the Gemini app's answer with its ``reference_links``.
    * ``google_ai_mode`` — Google's AI Mode in a country / language (``gl`` / ``hl``); a follow-up
      question continues the same conversation through ``conversation_token``.

    These are the consumer answers — what a real user sees — not a raw model. One request each."""

    async def ask(self, engine: str, prompt: str, *, gl: str | None = None, hl: str | None = None,
                  conversation_token: str | None = None) -> ProviderResult:  # fmt: skip
        if engine not in AI_ENGINES:
            raise ProviderError(f"searchapi: unknown AI engine {engine!r}", retryable=False)
        params: dict[str, Any] = {"engine": engine, "q": prompt[:4000]}
        if engine == "chatgpt":
            params["web_search"] = "true"
        if engine == "google_ai_mode":
            if conversation_token:
                params["conversation_token"] = conversation_token
            else:
                if gl:
                    params["gl"] = gl.lower()
                if hl:
                    params["hl"] = hl.lower()
        raw, latency = await self._social(params)
        data = normalize_ai_answer(engine, prompt, raw if isinstance(raw, dict) else None)
        return self._result(ProviderStatus.POSITIVE if data["answer"] else ProviderStatus.UNKNOWN, data,
                            {k: (raw or {}).get(k) for k in ("markdown", "reference_links", "citations", "response_metadata",
                                                            "search_metadata", "pagination")} if isinstance(raw, dict) else None,
                            latency, cost=self.cost_per_call)  # fmt: skip


# ------------------------------------------------------------------------------------ Meta ads
class SearchApiAdsClient(AiAnswersMixin, SocialMixin, HttpClientMixin):
    """SearchApi.io ``meta_ad_library`` engine: keyword search of Meta's Ad Library per country.
    Bearer key; one request per page; ~$0.004 per request on the entry plan."""

    name, cost_per_call = "searchapi", 0.004
    URL = "https://www.searchapi.io/api/v1/search"
    timeout = httpx.Timeout(45.0, connect=8.0)

    @staticmethod
    def normalize_ad(ad: dict[str, Any], country: str) -> dict[str, Any] | None:
        snap = ad.get("snapshot") or {}
        link = snap.get("link_url") or ""
        if not link:  # no landing page (a video view or a page-like ad) → nothing to check
            cards = snap.get("cards") or []
            link = next((c.get("link_url") for c in cards if c.get("link_url")), "")
        if not link:
            return None
        ad_id = str(ad.get("ad_archive_id") or "")
        images = snap.get("images") or []
        cards = snap.get("cards") or []
        image = (images[0].get("resized_image_url") or images[0].get("original_image_url")) if images else (
            (cards[0].get("resized_image_url") or cards[0].get("original_image_url")) if cards else None)  # fmt: skip
        return {
            "ad_id": ad_id, "page_id": str(ad.get("page_id") or ""), "page_name": ad.get("page_name") or "",
            "text": ((snap.get("body") or {}).get("text") or snap.get("title") or "")[:600],
            "title": str(snap.get("title") or "")[:200], "link_description": str(snap.get("link_description") or "")[:200],
            "link_url": link, "image": image, "start_date": (ad.get("start_date") or "")[:10] or None,
            "platforms": [p.lower() for p in ad.get("publisher_platform") or []], "country": country,
            "active": bool(ad.get("is_active", True)),
            "library_url": f"https://www.facebook.com/ads/library/?id={ad_id}" if ad_id else None,
        }  # fmt: skip

    async def meta_ads(
        self, query: str, country: str, active_status: str = "active", next_page_token: str | None = None
    ) -> ProviderResult:
        """One page of the Ad Library (~30 ads); ``next_page_token`` from the previous page's answer
        asks for the next one (each page is one request)."""
        if not self._api_key:
            raise ProviderError("searchapi: no API key", retryable=False)
        params = {
            "engine": "meta_ad_library", "q": query, "search_type": "keyword_exact_phrase",
            "country": country.upper(), "active_status": active_status, "ad_type": "all",
            "platforms": "facebook,instagram", "sort_by": "most_recent",
        }  # fmt: skip
        if next_page_token:
            params["next_page_token"] = next_page_token
        raw, latency = await self._get(
            self.URL, params=params, headers={"Authorization": f"Bearer {self._api_key}"}
        )
        if isinstance(raw, dict) and raw.get(
            "error"
        ):  # 200 with an error body (bad parameter, plan limit)
            raise ProviderError(f"searchapi: {str(raw['error'])[:160]}", retryable=False)
        ads = [
            a
            for a in (self.normalize_ad(x, country.upper()) for x in (raw or {}).get("ads") or [])
            if a
        ]
        total = ((raw or {}).get("search_information") or {}).get("total_results")
        nxt = ((raw or {}).get("pagination") or {}).get("next_page_token") or None
        return self._result(
            ProviderStatus.POSITIVE if ads else ProviderStatus.UNKNOWN,
            {"query": query, "country": country.upper(), "ads": ads, "total": total, "next_page_token": nxt},
            {"ads": ((raw or {}).get("ads") or [])[:30]}, latency, cost=self.cost_per_call,
        )  # fmt: skip


# ------------------------------------------------------------------------------------ registries
class _KeylessRegistry(HttpClientMixin):
    requires_key = False

    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(20.0, connect=6.0), headers={"User-Agent": _UA, "Accept": "application/json"},
                follow_redirects=True, transport=_ipv4_transport(),
            )  # fmt: skip
        return self._client


class IsraelCompaniesClient(_KeylessRegistry):
    """Israel's Registrar of Companies, published as an open dataset (data.gov.il CKAN
    ``datastore_search``). Companies, partnerships and public-benefit companies have 9-digit numbers
    starting with 5; an osek murshe / patur (sole trader) number is a personal ID and is not in it."""

    name = "il_companies"
    URL = "https://data.gov.il/api/3/action/datastore_search"
    RESOURCE = "f004176c-b85f-4542-8901-7b3176f9a054"
    HUMAN = "https://data.gov.il/dataset/ica_companies"

    async def lookup(self, number: str, country: str, name: str | None = None) -> ProviderResult:
        digits = re.sub(r"\D", "", number or "")
        if country.upper() != "IL":
            return _na(self.name, "not an Israeli number")
        if not re.fullmatch(r"5\d{8}", digits):
            return _na(
                self.name, "not a company number (sole traders are not in the companies registry)"
            )
        params = {
            "resource_id": self.RESOURCE,
            "filters": json.dumps({"מספר חברה": int(digits)}),
            "limit": 1,
        }
        raw, latency = await self._get(self.URL, params=params)
        records = (((raw or {}).get("result") or {}).get("records")) or []
        if not (raw or {}).get("success", True):
            return ProviderResult(
                self.name,
                ProviderStatus.UNKNOWN,
                {"status": "not_checked", "why": "registry error"},
                latency_ms=latency,
            )
        if not records:
            return self._result(ProviderStatus.NEGATIVE, {"status": "not_found", "number": digits, "registry": "Israeli Registrar of Companies",
                                                          "source_url": self.HUMAN}, raw or {}, latency)  # fmt: skip
        r = records[0]
        status_he = str(r.get("סטטוס חברה") or "")
        dissolved = any(w in status_he for w in ("מחוקה", "פורקה", "בפירוק", "מחיקה"))
        return self._result(ProviderStatus.POSITIVE, {
            "status": "dissolved" if dissolved else "active", "number": digits,
            "name": r.get("שם חברה"), "name_en": r.get("שם באנגלית"), "registered": r.get("תאריך התאגדות"),
            "registry_status": status_he, "registry": "Israeli Registrar of Companies", "source_url": self.HUMAN,
        }, {"record": r}, latency)  # fmt: skip


class CompaniesHouseClient(HttpClientMixin):
    """UK Companies House public data API: free key (HTTP Basic, key as the user name)."""

    name = "companies_house"
    URL = "https://api.company-information.service.gov.uk/company/{number}"

    async def lookup(self, number: str, country: str, name: str | None = None) -> ProviderResult:
        num = re.sub(r"[\s-]", "", number or "").upper()
        if country.upper() not in ("GB", "UK"):
            return _na(self.name, "not a UK number")
        if not re.fullmatch(r"(\d{8}|[A-Z]{2}\d{6})", num):
            return _na(self.name, "not a UK company number")
        if not self._api_key:
            raise ProviderError("companies_house: no API key", retryable=False)
        r = await self.client().get(self.URL.format(number=num), auth=(self._api_key, ""))
        if r.status_code == 404:
            return ProviderResult(self.name, ProviderStatus.NEGATIVE, {
                "status": "not_found", "number": num, "registry": "UK Companies House",
                "source_url": f"https://find-and-update.company-information.service.gov.uk/company/{num}"})  # fmt: skip
        if r.status_code in (401, 403):
            raise ProviderError(f"companies_house: HTTP {r.status_code}", retryable=False)
        if r.status_code >= 400:
            raise ProviderError(
                f"companies_house: HTTP {r.status_code}", retryable=r.status_code >= 500
            )
        d = r.json()
        st = str(d.get("company_status") or "")
        return ProviderResult(self.name, ProviderStatus.POSITIVE, {
            "status": "dissolved" if st in ("dissolved", "liquidation", "converted-closed") else "active",
            "number": num, "name": d.get("company_name"), "registered": d.get("date_of_creation"),
            "registry_status": st, "registry": "UK Companies House",
            "source_url": f"https://find-and-update.company-information.service.gov.uk/company/{num}",
        }, raw={"company": d})  # fmt: skip


class ViesClient(_KeylessRegistry):
    """EU VIES VAT check (keyless REST). Only for VAT numbers of EU member states."""

    name = "vies"
    URL = "https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number"

    async def lookup(self, number: str, country: str, name: str | None = None) -> ProviderResult:
        raw_num = re.sub(r"[\s.-]", "", number or "").upper()
        cc = raw_num[:2] if re.match(r"^[A-Z]{2}", raw_num) else country.upper()
        cc = {"GR": "EL"}.get(cc, cc)
        vat = raw_num[2:] if raw_num[:2] in (cc, "GR") else raw_num
        if cc not in EU_VAT_COUNTRIES or not re.fullmatch(r"[0-9A-Z]{2,13}", vat):
            return _na(self.name, "not an EU VAT number")
        raw, latency = await self._post(self.URL, json={"countryCode": cc, "vatNumber": vat})
        if not isinstance(raw, dict) or "valid" not in raw:
            return ProviderResult(
                self.name,
                ProviderStatus.UNKNOWN,
                {"status": "not_checked", "why": "VIES gave no answer"},
                latency_ms=latency,
            )
        human = "https://ec.europa.eu/taxation_customs/vies/"
        if not raw.get("valid"):
            return self._result(ProviderStatus.NEGATIVE, {"status": "not_found", "number": f"{cc}{vat}", "registry": "EU VIES",
                                                          "source_url": human}, raw, latency)  # fmt: skip
        nm = raw.get("name")
        return self._result(ProviderStatus.POSITIVE, {
            "status": "active", "number": f"{cc}{vat}", "name": None if nm in (None, "---") else nm,
            "address": raw.get("address"), "registry": "EU VIES", "source_url": human}, raw, latency)  # fmt: skip


class GleifClient(_KeylessRegistry):
    """GLEIF LEI records by company name (keyless). Only companies with a Legal Entity Identifier are
    listed — mostly larger ones — so *not finding* a small shop here proves nothing: that case is
    UNKNOWN, never NEGATIVE."""

    name = "gleif"
    URL = "https://api.gleif.org/api/v1/lei-records"

    async def lookup(self, number: str, country: str, name: str | None = None) -> ProviderResult:
        if not name or len(name.strip()) < 3:
            return _na(self.name, "no company name to search")
        params = {"filter[entity.legalName]": name.strip(), "page[size]": 3}
        if re.fullmatch(r"[A-Za-z]{2}", country or ""):
            params["filter[entity.legalAddress.country]"] = country.upper()
        raw, latency = await self._get(
            self.URL, params=params, headers={"Accept": "application/vnd.api+json"}
        )
        data = (raw or {}).get("data") or []
        if not data:
            return ProviderResult(self.name, ProviderStatus.UNKNOWN, {"status": "not_checked", "why": "no LEI record (small companies rarely have one)"},
                                  latency_ms=latency)  # fmt: skip
        ent = (data[0].get("attributes") or {}).get("entity") or {}
        lei = data[0].get("id")
        return self._result(ProviderStatus.POSITIVE, {
            "status": "dissolved" if str(ent.get("status") or "").upper() == "INACTIVE" else "active",
            "number": ent.get("registeredAs") or lei, "name": (ent.get("legalName") or {}).get("name"),
            "lei": lei, "registry": "GLEIF (LEI)", "source_url": f"https://search.gleif.org/#/record/{quote(str(lei))}",
        }, {"data": data[:1]}, latency)  # fmt: skip


class OpenCorporatesClient(HttpClientMixin):
    """OpenCorporates (paid; 140+ jurisdictions). Off unless a key is added in Settings."""

    name = "opencorporates"
    URL = "https://api.opencorporates.com/v0.4/companies/{jurisdiction}/{number}"

    async def lookup(self, number: str, country: str, name: str | None = None) -> ProviderResult:
        if not self._api_key:
            raise ProviderError("opencorporates: no API key", retryable=False)
        num = re.sub(r"\s", "", number or "")
        jur = {"UK": "gb"}.get(country.upper(), country.lower())
        if not num or not re.fullmatch(r"[a-z]{2}", jur):
            return _na(self.name, "no number or country")
        raw, latency = await self._get(
            self.URL.format(jurisdiction=jur, number=quote(num)),
            params={"api_token": self._api_key},
        )
        if raw is None:  # 404
            return ProviderResult(self.name, ProviderStatus.NEGATIVE, {"status": "not_found", "number": num, "registry": "OpenCorporates",
                                                                       "source_url": f"https://opencorporates.com/companies/{jur}/{quote(num)}"},
                                  latency_ms=latency)  # fmt: skip
        c = ((raw or {}).get("results") or {}).get("company") or {}
        return self._result(ProviderStatus.POSITIVE, {
            "status": "dissolved" if c.get("dissolution_date") or c.get("inactive") else "active", "number": num,
            "name": c.get("name"), "registered": c.get("incorporation_date"), "registry": "OpenCorporates",
            "source_url": c.get("opencorporates_url") or f"https://opencorporates.com/companies/{jur}/{quote(num)}",
        }, {"company": c}, latency, cost=0.0)  # fmt: skip


COMMERCE_CLIENTS: tuple[type, ...] = (
    SearchApiAdsClient,
    IsraelCompaniesClient,
    CompaniesHouseClient,
    ViesClient,
    GleifClient,
    OpenCorporatesClient,
)
