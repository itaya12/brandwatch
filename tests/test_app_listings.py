"""App-store / APK listings: judged by their title and description, never excluded; the brand's
own listings (linked from its official site) are learned at baseline time and skipped."""

import uuid

from brandwatch.config.brand_config import ScoringConfig
from brandwatch.detection.analysis import analyze
from brandwatch.detection.baseline import BrandBaseline
from brandwatch.detection.enrichment import CollectedEvidence
from brandwatch.detection.html import app_store_links, extract_features
from brandwatch.detection.normalize import (
    canonical_listing_url,
    is_app_store,
    is_known_platform,
    is_shared_hosting,
)

LISTING = """<html><head><title>CryptoHopper Pro - Auto Trading Bot</title>
<meta name="description" content="The official Cryptohopper trading app. Connect your exchange.">
</head><body><h1>CryptoHopper Pro</h1><p>Install now.</p></body></html>"""


def _baseline(official_apps: tuple[str, ...] = ()) -> BrandBaseline:
    return BrandBaseline(
        brand_id=uuid.uuid4(), brand_key="cryptohopper", official_domains=("cryptohopper.com",),
        favicon_mmh3=None, favicon_phash=None, screenshot_phash=None,
        keywords=("cryptohopper",), official_apps=official_apps,
    )  # fmt: skip


def _evidence(url: str) -> CollectedEvidence:
    host = url.split("/")[2]
    ev = CollectedEvidence(
        candidate_id=uuid.uuid4(), url=url, host=host, registrable=".".join(host.split(".")[-2:])
    )
    ev.final_url = url
    ev.features = extract_features(LISTING, url, ["cryptohopper"])
    return ev


def test_platform_helpers():
    assert is_known_platform("www.youtube.com") and is_known_platform("youtu.be")
    assert not is_known_platform("apps.apple.com") and not is_known_platform("play.google.com")
    assert is_app_store("play.google.com") and is_app_store("apkpure.com")
    assert is_app_store("apps.apple.com") and not is_app_store("apple.com")
    assert is_shared_hosting("kit.pages.dev") and not is_shared_hosting("example.com")
    assert (
        canonical_listing_url("https://play.google.com/store/apps/details?id=com.x.y&hl=en#top")
        == "play.google.com/store/apps/details?id=com.x.y"
    )
    assert (
        canonical_listing_url("https://apps.apple.com/us/app/x/id1?mt=8")
        == "apps.apple.com/us/app/x/id1"
    )


def test_meta_description_is_extracted():
    f = extract_features(
        LISTING, "https://play.google.com/store/apps/details?id=a", ["cryptohopper"]
    )
    assert f.title.startswith("CryptoHopper Pro") and "official Cryptohopper" in f.meta_description


def test_app_listing_named_after_brand_fires_signals():
    an = analyze(
        _evidence("https://play.google.com/store/apps/details?id=com.fake.hopper"),
        _baseline(),
        ScoringConfig(),
    )
    assert "app_listing_brand_title" in an.signals
    assert "app_listing_brand_description" in an.signals
    assert "official_app_listing" not in an.fp_flags


def test_official_app_listing_is_not_flagged():
    url = "https://apps.apple.com/us/app/cryptohopper/id123456"
    an = analyze(_evidence(url + "?mt=8"), _baseline(official_apps=(url,)), ScoringConfig())
    assert "app_listing_brand_title" not in an.signals
    assert "official_app_listing" in an.fp_flags


def test_ordinary_site_never_gets_app_listing_signals():
    an = analyze(_evidence("https://cryptohopper-pro.com/"), _baseline(), ScoringConfig())
    assert "app_listing_brand_title" not in an.signals


def test_official_site_app_links_are_learned():
    html = (
        '<a href="https://apps.apple.com/us/app/cryptohopper/id123456?mt=8">iOS</a>'
        '<a href="/pricing">pricing</a>'
        '<a href="https://play.google.com/store/apps/details?id=com.cryptohopper&hl=en">Android</a>'
        '<a href="https://twitter.com/cryptohopper">tw</a>'
    )
    assert app_store_links(html, "https://cryptohopper.com/") == [
        "apps.apple.com/us/app/cryptohopper/id123456",
        "play.google.com/store/apps/details?id=com.cryptohopper",
    ]
