"""Only ads and shops that are about the brand get checked.

The cases come from a real live scan of the brand "On Cloud" (on.com): Meta's Ad Library matched
"on cloud" inside cloud-storage, USB-drive and TV-series ads, and every landing site became a shop
to check. The AI also suggested "on cloud wallet" as a Google query for a shoe brand, and the
2-letter domain label "on" matched "phone", "london" and every other word.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest

from brandwatch.db.enums import ProviderStatus
from brandwatch.detection import ai, merchant, relevance
from brandwatch.detection.baseline import brand_key_for
from brandwatch.detection.discovery import key_in, split_host
from brandwatch.detection.html import extract_features
from brandwatch.detection.sources import (
    _looks_related,
    short_label_aliases,
    stream_dnstwist,
    stream_meta_ads,
    stream_urlscan,
)
from brandwatch.providers.base import ProviderResult
from brandwatch.providers.mock import MockLLMProvider

PRODUCTS = [
    {"name": "cloudstratus", "price": 170, "currency": "USD", "country": "US"},
    {"name": "cloudswift", "price": 150, "currency": "USD", "country": "US"},
    {"name": "cloudnova", "price": 140, "currency": "USD", "country": "US"},
    {"name": "cloudmonster", "price": 180, "currency": "USD", "country": "US"},
]


def on_terms() -> relevance.BrandTerms:
    return relevance.brand_terms(
        "on cloud", "oncloud", ad_keywords=["on cloud"], products=[p["name"] for p in PRODUCTS],
        official_domains=["on.com"], vertical="footwear and apparel",
    )  # fmt: skip


# what the live scan's ads looked like (page name, text, landing link)
LIVE_ADS = [
    ("Kalos Venus2", "Disrupted by her fiancé's pregnant mistress, Natalia walks out of her wedding and is on cloud nine with Javier",
     "https://website.kalostv.com/share/middle/5dpno/"),
    ("Future Path", "Learn about cloud storage services and explore what options are available for 2026.",
     "https://articlespeaks.com/learn-about-cloud-storage-services-2026-info/"),
    ("Shiftaken.shop", "Tired of monthly storage payments? One-time buy for 250,000 photos. Keep everything on cloud and offline",
     "https://www.shiftaken.com/products/32-256gbb-micro-usb-mobile-phone-u-disk/"),
    ("StretchLab", "Feel Your BEST This Fall At StretchLab With HALF OFF Your First Stretch!", "http://fb.me/"),
    ("Running Oncloud", "Comfortable shoes make every day better. Lightweight, breathable.",
     "https://stridorax.com/products/cloud-6-all-day-comfort/?variant=1"),
    ("mhmed.store", "חליפת ON CLOUD החדשה 🔥 לוק ספורטיבי ✅ איכות גבוהה 📏 מידות", "https://instagram.com/mhmed.store"),
]  # fmt: skip


def _ad(page: str, text: str, url: str) -> dict:
    return {"page_name": page, "text": text, "landing_url": url}


# ------------------------------------------------------------------------------- ad relevance
def test_live_scan_ads_only_the_brand_ones_pass():
    t = on_terms()
    verdicts = {page: relevance.ad_relevance(_ad(page, text, url), t)[0] for page, text, url in LIVE_ADS}
    assert verdicts["Running Oncloud"] == "yes"  # the page name writes the brand as one word
    assert verdicts["mhmed.store"] == "yes"  # "ON CLOUD" next to "suit" / "sizes" in Hebrew
    assert verdicts["Future Path"] == "no" and verdicts["StretchLab"] == "no"
    # the words are there, but nothing about shoes or clothes: unclear, the AI (or nobody) decides
    assert verdicts["Kalos Venus2"] == "maybe" and verdicts["Shiftaken.shop"] == "maybe"


def test_context_word_far_from_the_phrase_does_not_count():
    t = on_terms()
    far = "She is on cloud nine. " + "x " * 60 + "Watch her pick the perfect wedding dress"
    assert relevance.ad_relevance(_ad("Drama", far, "https://drama.example/"), t)[0] == "maybe"
    near = "New On Cloud sneakers — sizes 36-46, free shipping"
    assert relevance.ad_relevance(_ad("Shop", near, "https://shop.example/"), t)[0] == "yes"


def test_product_names_and_link_words_are_strong():
    t = on_terms()
    assert relevance.ad_relevance(_ad("Deals", "Only today 59$", "https://x.example/cloudmonster-sale"), t)[0] == "yes"
    assert relevance.ad_relevance(_ad("Deals", "Cloudnova Form for 59$", "https://x.example/"), t)[0] == "yes"
    assert "oncloud" in t.strong and "on cloud" in t.phrases and "on.com" in t.strong


def test_plain_word_brand_needs_context():
    t = relevance.brand_terms("Adidas", "adidas", vertical="sportswear and footwear")
    assert t.strong == () and "adidas" in t.phrases  # 6 letters, a plain word: never strong alone
    assert relevance.ad_relevance(_ad("p", "adidas samba, all sizes", "https://s.example/"), t)[0] == "yes"
    assert relevance.ad_relevance(_ad("p", "adidas fan quiz", "https://s.example/"), t)[0] == "maybe"


def test_page_about_brand():
    t = on_terms()
    assert relevance.page_about_brand("Cloudswift 4 · Cloudnova Form 2 · Contact", None, t)
    assert relevance.page_about_brand("32-256GB micro USB U-disk, store photos on cloud", "U disk", t) is None


# ------------------------------------------------------------------------------- the stream
class _Ads:
    def __init__(self, ads):
        self.ads = ads

    async def meta_ads(self, query, country, active_status="active", next_page_token=None):
        return ProviderResult("searchapi", ProviderStatus.POSITIVE, {"ads": self.ads})


class _NoLLM:
    async def analyze(self, text, schema):
        return ProviderResult.failure("llm", "no LLM configured")


def _providers(llm) -> SimpleNamespace:
    raw = [{"ad_id": str(i), "page_id": str(100 + i), "page_name": p, "text": t, "link_url": u,
            "library_url": f"https://www.facebook.com/ads/library/?id={i}"} for i, (p, t, u) in enumerate(LIVE_ADS)]  # fmt: skip
    return SimpleNamespace(ads=lambda: _Ads(raw), llm=lambda: llm)


def test_meta_ads_stream_skips_ads_that_only_share_the_words():
    r = asyncio.run(stream_meta_ads(_providers(_NoLLM()), ["on cloud"], ["US"], {"on.com"}, terms=on_terms()))
    hosts = [h.raw_value.split("/")[2] for h in r.hits]
    assert hosts == ["stridorax.com"]  # the one shop that sells On; Instagram is a platform, fb.me a page
    assert r.not_about_brand == 4 and r.ai_checked == 2  # 2 unclear ads, no AI → skipped
    by = {e["label"]: e for e in r.seen}
    assert by["Future Path"]["tag"].startswith("not about the brand")
    assert "no AI configured" in by["Kalos Venus2"]["verdict"]
    assert by["mhmed.store"]["relevance"] == "platform" and "about the brand" in by["mhmed.store"]["verdict"]
    assert r.ads_by_host["stridorax.com"][0]["page_name"] == "Running Oncloud"


def test_meta_ads_stream_lets_the_ai_read_unclear_ads():
    r = asyncio.run(stream_meta_ads(_providers(MockLLMProvider()), ["on cloud"], ["US"], {"on.com"}, terms=on_terms()))
    by = {e["label"]: e for e in r.seen}
    assert by["Kalos Venus2"]["verdict"].startswith("the AI read the ad")
    assert not by["Kalos Venus2"]["visit"] and not by["Shiftaken.shop"]["visit"]
    assert [h.raw_value.split("/")[2] for h in r.hits] == ["stridorax.com"]


# ------------------------------------------------------------------------------- search queries
def test_wallet_and_bonus_queries_only_for_finance_brands():
    live = ["on cloud login", "on cloud wallet", "on cloud bonus", "on cloud promo code", "on clouud wallet", "on cloud sale"]
    kept = ai.fit_queries(live, vertical="footwear and apparel", kind="retail")
    assert kept == ["on cloud login", "on cloud promo code", "on cloud sale"]
    assert ai.fit_queries(live, vertical="crypto trading bot", kind="service") == live
    retail = ai.default_search_queries("On Cloud", "oncloud", "retail")
    assert "on cloud sale" in retail and "on cloud outlet" in retail and not any("wallet" in q for q in retail)


def test_brand_profile_prompt_is_vertical_aware():
    seen = {}

    class _LLM:
        async def analyze(self, text, schema):
            seen["brief"] = text
            return ProviderResult("openai", ProviderStatus.POSITIVE, {
                "keywords": ["cloudmonster"], "lures": ["access your on cloud wallet", "on cloud sale ends today"],
                "search_queries": ["on cloud wallet", "on cloud bonus", "on cloud login"], "vertical": "Footwear and apparel"})  # fmt: skip

    out = asyncio.run(ai.brand_profile(SimpleNamespace(llm=lambda: _LLM()), brand_name="on cloud",
                                       homepage_text="Swiss running shoes", kind="retail"))  # fmt: skip
    assert "no 'wallet' or 'bonus' for a shoe brand" in seen["brief"]
    assert not any("wallet" in q or "bonus" in q for q in out["search_queries"])
    assert len(out["search_queries"]) >= 5 and "on cloud sale" in out["search_queries"]
    assert out["lures"] == ["on cloud sale ends today"]


# ------------------------------------------------------------------------------- short brand keys
def test_short_domain_label_uses_the_brand_name():
    class _Session:
        def __init__(self, domains):
            self.domains = domains

        def scalars(self, _q):
            return SimpleNamespace(all=lambda: self.domains)

    on_cloud = SimpleNamespace(id=uuid.uuid4(), name="On Cloud")
    assert brand_key_for(on_cloud, _Session(["on.com"])) == "oncloud"
    assert brand_key_for(SimpleNamespace(id=uuid.uuid4(), name="On"), _Session(["on.com"])) == "on"
    assert brand_key_for(SimpleNamespace(id=uuid.uuid4(), name="Acme Corp"), _Session(["hp.com"])) == "hp"
    assert brand_key_for(SimpleNamespace(id=uuid.uuid4(), name="ShopNova EU"), _Session(["shopnova.com"])) == "shopnova"


@pytest.mark.parametrize(("host", "related"), [
    ("phone-cases.com", False), ("london-shop.co.uk", False), ("online.store", False),
    ("on-sale.com", True), ("buy.on.shop", True),
])  # fmt: skip
def test_short_key_matches_only_as_a_word(host, related):
    assert _looks_related(host, "on") is related
    assert key_in("on", host) is related


def test_short_keyword_in_page_text_needs_a_word_boundary():
    f = extract_features("<html><body>Buy a phone online in London</body></html>", "https://x.example/", ["on", "cloudnova"])
    assert f.brand_keywords == []
    f = extract_features("<html><body>On sale: Cloudnova</body></html>", "https://x.example/", ["on", "cloudnova"])
    assert f.brand_keywords == ["cloudnova"]  # "on" is in every English page, even as a word


def test_dnstwist_permutes_the_brand_name_instead_of_a_two_letter_label():
    aliases = short_label_aliases(["on.com"], "oncloud")
    assert aliases == {"on.com": "oncloud.com"}
    r = asyncio.run(stream_dnstwist(["on.com"], tlds="common", max_hits=None, aliases=aliases))
    names = [h.raw_value for h in r.hits]
    assert names[0] == "oncloud.com" and "on.com" not in names
    assert all(h.matched_pattern.endswith(":oncloud.com") for h in r.hits)  # every name comes from "oncloud"
    assert "on-cloud.com" in names and "oncloud-login.com" in names or "login-oncloud.com" in names
    # no 2-3 letter typos of "on" ("oon.com", "o.com"); dotted variants of oncloud ("oncl.oud.com") are fine
    assert not any(len(split_host(h.raw_value).sld) <= 3 for h in r.hits if not h.matched_pattern.startswith("subdomain:"))
    # a short label with no longer name keeps only its keyword combinations
    r2 = asyncio.run(stream_dnstwist(["on.com"], tlds="common", max_hits=None))
    assert r2.hits and all(h.matched_pattern.startswith("dictionary:") for h in r2.hits)


def test_urlscan_refuses_a_two_letter_token():
    r = asyncio.run(stream_urlscan(SimpleNamespace(), "on", {"on.com"}))
    assert r.degraded and "too short" in r.note


# ------------------------------------------------------------------------------- shop checks
STRIDORAX = """<html lang="en"><head><title>Cloud 6 Lightweight Comfort Built for Every Run – Stridorax</title>
<link href="https://cdn.shopify.com/x.css"></head><body>
<nav><a href="/c/cloud-6">Cloud 6</a> <a href="/c/cloudtilt">Cloudtilt</a> <a href="/c/cloudswift">Cloudswift 4</a>
<a href="/c/cloudmonster">Cloudmonster 3</a> <a href="/c/cloudnova">Cloudnova Form 2</a></nav>
<h1>Cloud 6 Lightweight Comfort Built for Every Run</h1>
<p>$119.00 Regular price $160.00 Sale price $119.00</p><p>Limited Stock Available</p>
<button>Add to cart</button>
<h2>Products</h2>
<p>Ambrose Leather Monk Strap Shoes $99.99 Regular price $179.99 Sale price $99.99</p>
<p>Andros Leather Slip On Sandal $49.99 Regular price $149.99 Sale price $49.99</p>
<p>Anvello Slip On Sneaker $49.99 Regular price $119.99 Sale price $49.99</p>
<p>Bambi Thong Sandal $39.99 Regular price $99.99 Sale price $39.99</p>
<footer><a href="/pages/privacy-policy">Privacy Policy</a> <a href="/pages/terms-of-service">Terms of Service</a>
<a href="/pages/return-policy">Return Policy</a> Email: info@stridorax.com</footer></body></html>"""


def test_the_live_counterfeit_shop_now_scores_medium():
    t = on_terms()
    facts = merchant.shop_facts(STRIDORAX, "https://stridorax.com/products/cloud-6", "US")
    assert facts.company_name is None  # "Limited Stock" is not a company
    assert len([d for d in facts.discounts if d["off"] >= 0.5]) == 3
    text = merchant.visible_text(STRIDORAX)
    fired, price = merchant.page_signals(
        facts, host="stridorax.com", country="US", age_days=138, products=PRODUCTS, terms=t, text=text,
        ads=[{"page_name": "Running Oncloud", "page_id": "1"}],
    )  # fmt: skip
    for sig in ("shop_ad_page_uses_brand", "shop_brand_catalog", "shop_deep_discounts", "shop_young_domain",
                "shop_no_company_details"):  # fmt: skip
        assert sig in fired, sig
    # the $39.99 sandal is not an On product: it is never compared with the Cloudnova price
    assert "shop_price_far_below_official" not in fired and price["offer"] is None
    s = merchant.score_shop(fired, {}, thresholds={"medium": 25, "high": 50, "critical": 75}, checks_done=2, unavailable=[])
    assert s["severity"].value == "medium"


def test_price_check_compares_the_named_product():
    t = on_terms()
    html = "<html><body><p>Cloudnova Form 2 $59.00</p><p>Beach Sandal $9.99</p><button>Add to cart</button></body></html>"
    facts = merchant.shop_facts(html, "https://x.example/", "US")
    fired, price = merchant.page_signals(facts, host="x.example", country="US", age_days=None, products=PRODUCTS,
                                         terms=t, text=merchant.visible_text(html))  # fmt: skip
    assert price["reference"]["name"] == "cloudnova" and price["ratio"] == 0.42
    assert "shop_price_far_below_official" in fired


def test_scam_checker_titles_are_not_warnings():
    neutral = [{"title": "pages.farsunpteltd.com Reviews | scam or legit check", "snippet": "Check if the site is a scam or legit."},
               {"title": "Is stridorax.com a scam?", "snippet": "Read our analysis"}]  # fmt: skip
    assert merchant._scam_hits(neutral) == []
    real = [{"title": "stridorax.com reviews", "snippet": "Never arrived. Paid $119, it is a scam."}]
    assert merchant._scam_hits(real)[0]["word"] in ("scam", "never arrived")


def test_a_shop_that_sells_something_else_gets_no_shop_checks():
    from brandwatch.detection.runner import _shop_stage

    events = []
    em = SimpleNamespace(done=lambda *a, **k: events.append(a), running=lambda *a, **k: events.append(a))
    ctx = SimpleNamespace(emitter=em)
    page = ("<html><head><title>GardenBox tools</title></head><body><h1>Hedge trimmers</h1>"
            "<p>Ships on cloud-free days. $49.99</p><button>Add to cart</button></body></html>")  # fmt: skip
    cand = SimpleNamespace(hostname="oncloud-garden.com", canonical_url="https://oncloud-garden.com/", sources=[])
    col = SimpleNamespace(html=page, features=SimpleNamespace(title="GardenBox tools"))
    shop = {"terms": on_terms(), "ads_by_host": {}, "checked": 0, "brand_name": "on cloud"}
    an, risk = object(), object()
    out = asyncio.run(_shop_stage(ctx, cand, col, an, risk, shop))
    assert out == (an, risk, "phishing") and shop["checked"] == 0
    assert "sells something else" in events[-1][2]


def test_saved_service_queries_get_shopping_queries_first_for_a_retail_brand():
    old = ["on cloud login", "on cloud sign in", "on cloud support", "on cloud wallet"]
    out = ai.shopping_first(ai.fit_queries(old, vertical="footwear and apparel", kind="retail"), "On Cloud", "oncloud")
    assert out[0] == "on cloud sale" and "on cloud wallet" not in out and "on cloud login" in out
    assert ai.shopping_first(["x sale", "x login"], "X", "x") == ["x sale", "x login"]
