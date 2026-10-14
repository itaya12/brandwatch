"""Live-mode dnstwist: every permutation is DNS-checked concurrently and only registered names
become candidates; the lexicon produces the combosquats analysts expect; "all" is every TLD."""

from brandwatch.config.settings import Settings
from brandwatch.detection import sources
from brandwatch.detection.discovery import DEFAULT_DICTIONARY, TLD_SETS, permutations
from brandwatch.providers.registry import ProviderRegistry


def test_all_tld_set_is_the_whole_root_zone_and_combosquats_exist():
    assert (
        len(TLD_SETS["all"]) > 1000
        and TLD_SETS["all"][: len(TLD_SETS["popular"])] == TLD_SETS["popular"]
    )
    names = {
        d
        for _, d in permutations(
            "cryptohopper.com", dictionary=list(DEFAULT_DICTIONARY), tlds="common"
        )
    }
    for want in (
        "cryptohoppertrading.com", "cryptohopperlogin.com", "crypto-hopper.com",
        "cryptohopper-login.com", "cryptohopper.io", "cryptohoper.com", "cryptohopper-trading.com",
    ):  # fmt: skip
        assert want in names, want


async def test_live_dnstwist_keeps_only_registered_names():
    registered = {"crypto-hopper.com", "cryptohopperlogin.com", "cryptohopper.io"}
    calls: list[str] = []

    def fake_resolver(name: str) -> bool:
        calls.append(name)
        return name in registered

    r = await sources.stream_dnstwist(
        ["cryptohopper.com"],
        tlds="common",
        max_hits=50,
        dictionary=["login"],
        resolver=fake_resolver,
    )
    assert {h.raw_value for h in r.hits} == registered
    assert r.generated == len(calls) > 100 and r.tlds == len(TLD_SETS["common"])
    assert "3 registered" in (r.note or "") and r.seen and all("tag" in x for x in r.seen)
    # demo / tests without a resolver: every permutation is a candidate, capped
    d = await sources.stream_dnstwist(["cryptohopper.com"], tlds="common", max_hits=20)
    assert len(d.hits) == 20 and d.generated > 20


async def test_search_runs_every_query_in_every_country(tmp_path):
    reg = ProviderRegistry(Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path)))
    r = await sources.stream_search(
        reg, "ShopNova", {"shopnova.com"}, geo="us", lang="en",
        queries=["shopnova login", "shopnova support"], geos=["us", "uk", "es"],
    )  # fmt: skip
    assert r.api_calls == 6 and not r.degraded
    assert {h.matched_pattern.split(":")[1] for h in r.hits} <= {"us/en", "uk/en", "es/en"}


def test_search_result_triage_explains_each_result():
    from brandwatch.detection.sources import triage_search_result

    officials = {"cryptohopper.com", "www.cryptohopper.com"}
    tag, _v, visit = triage_search_result(
        "www.cryptohopper.com",
        "Cryptohopper",
        "https://www.cryptohopper.com/",
        officials,
        "cryptohopper",
    )
    assert tag == "official" and not visit
    tag, _v, visit = triage_search_result(
        "www.youtube.com",
        "CryptoHopper review",
        "https://www.youtube.com/watch?v=1",
        officials,
        "cryptohopper",
    )
    assert tag.startswith("skipped") and not visit
    tag, _v, visit = triage_search_result(
        "cryptohoppertrader.com",
        "Crypto Hopper Login",
        "https://cryptohoppertrader.com/login",
        officials,
        "cryptohopper",
    )
    assert tag == "suspicious" and visit
    tag, _v, visit = triage_search_result(
        "apps.apple.com",
        "CryptoHopper Pro",
        "https://apps.apple.com/app/id1",
        officials,
        "cryptohopper",
    )
    assert tag == "app listing" and visit
    tag, _v, visit = triage_search_result(
        "kit.pages.dev", "Welcome", "https://kit.pages.dev/", officials, "cryptohopper"
    )
    assert tag == "free hosting" and visit
    tag, _v, visit = triage_search_result(
        "news.example", "Markets today", "https://news.example/a", officials, "cryptohopper"
    )
    assert tag == "low priority" and visit


async def test_search_stream_reports_every_result_per_query(tmp_path):
    calls: list[tuple[str, str, int]] = []
    reg = ProviderRegistry(Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path)))
    r = await sources.stream_search(
        reg, "ShopNova", {"shopnova.com", "www.shopnova.com"}, geo="us", lang="en",
        queries=["shopnova login"], brand_key="shopnova",
        on_query=lambda q, g, res: calls.append((q, g, len(res))),
    )  # fmt: skip
    assert calls and calls[0][:2] == ("shopnova login", "us") and calls[0][2] == len(r.seen)
    assert all(
        {"label", "url", "host", "tag", "note", "visit", "official"} <= set(x) for x in r.seen
    )
    assert all(x["tag"].startswith("#") for x in r.seen)
    assert {h.raw_value for h in r.hits} == {x["url"] for x in r.seen if x["visit"]}


async def test_dns_timeouts_are_unknown_not_free_and_a_dead_resolver_stops_the_check():
    def dead(_name: str):
        return None  # every look-up times out

    r = await sources.stream_dnstwist(
        ["cryptohopper.com"], tlds="common", max_hits=None, resolver=dead
    )
    assert r.dns_broken and r.degraded and r.hits == []
    assert r.checked < r.generated  # gave up after the first batch instead of grinding on
    assert "DNS is not answering" in (r.note or "")

    def flaky(name: str):
        return None if name.endswith(".net") else name.endswith(".io")

    r2 = await sources.stream_dnstwist(
        ["cryptohopper.com"], tlds="common", max_hits=None, resolver=flaky
    )
    assert (
        not r2.dns_broken and r2.unknown > 0 and all(h.raw_value.endswith(".io") for h in r2.hits)
    )
    assert "without a DNS answer" in (r2.note or "")


def test_visit_cap_takes_the_smallest_of_request_track_and_workspace():
    from brandwatch.config.brand_config import BrandConfig
    from brandwatch.detection.runner import visit_cap

    cfg = BrandConfig.for_preset("standard")  # track: 500
    cfg.economic_limits.max_candidate_count = 100  # Settings → Workspace & budget
    assert visit_cap(None, cfg) == 100
    assert visit_cap(20, cfg) == 20
    assert visit_cap(1000, cfg) == 100  # the workspace cap is a hard cap
    cfg.economic_limits.max_candidate_count = 0  # 0 = no workspace cap
    assert visit_cap(None, cfg) == 500 and visit_cap(1000, cfg) == 1000
