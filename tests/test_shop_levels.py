"""Suspicious shops, v2: a calibrated score, a conclusion that matches the evidence, and words that
claim no more than that conclusion.

* shop-v2 caps related signals (an invisible company counts once) and takes points off for a
  registered company with the shop's own name and an old domain — the genuine shops of the golden
  set that shop-v1 scored Medium are Low now, and every scam shop is still High.
* BrandWatch reads "likely counterfeit seller" only from evidence about the goods *and* the seller;
  "confirmed counterfeit" needs a person and the proof written down.
* The takedown letter, its subject and the text for Meta follow the conclusion.
* Re-scoring a brand's config never touches shop / social findings; the phishing classifier never
  learns from a confirmed shop.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from tests.conftest import make_brand, make_workspace

import brandwatch.db.models as m
from brandwatch.config.settings import Settings
from brandwatch.db.enums import AnalystVerdict, FindingState
from brandwatch.detection import finding as finding_stage
from brandwatch.detection import merchant, relevance, shop_levels
from brandwatch.providers.mock.fixtures import default_store
from brandwatch.providers.registry import ProviderRegistry

PROFILE = {
    "countries": ["IL", "US"],
    "ad_keywords": ["shopnova runner"],
    "products": [
        {"name": "ShopNova Runner", "price": 799, "currency": "ILS", "country": "IL", "source": "analyst"},
        {"name": "ShopNova Runner", "price": 150, "currency": "USD", "country": "US", "source": "analyst"},
    ],
}
TH = {"medium": 25, "high": 50, "critical": 75}

# shop-v1 as it was (points per signal, one penalty, no caps) — kept here to prove the calibration
V1 = {"shop_company_not_in_registry": 25, "shop_company_dissolved": 20, "shop_price_far_below_official": 20,
      "shop_reviews_warn": 15, "shop_ad_page_uses_brand": 15, "shop_no_policy_pages": 12, "shop_free_email_only": 12,
      "shop_new_domain": 12, "shop_no_web_presence": 10, "shop_brand_catalog": 10, "shop_no_company_details": 8,
      "shop_deep_discounts": 8, "shop_young_domain": 6, "shop_tld_language_mismatch": 6, "shop_chat_or_phone_only": 6,
      "shop_multibuy_bait": 6}  # fmt: skip


def _v1(fired: dict, registry: dict, age: int | None) -> int:
    pen = 15 if registry.get("status") == "found" and age is not None and age > 3 * 365 else 0
    return max(0, min(100, sum(V1.get(k, 0) for k in fired) - pen))


def _assess(host: str) -> dict:
    """The shop checks for one golden scenario, exactly as the scan runs them (demo providers)."""
    sc = default_store().get(host)
    country = "US" if host.endswith(".com") and (sc.http or {}).get("html", "").find('lang="en"') > 0 else "IL"
    ads = [{**a, "country": (a.get("countries") or [country])[0], "ad_id": f"{host}:{i}",
            "library_url": f"https://www.facebook.com/ads/library/?id={i}"} for i, a in enumerate(sc.ads)]  # fmt: skip
    terms = relevance.brand_terms("ShopNova", "shopnova", ad_keywords=PROFILE["ad_keywords"],
                                  products=[p["name"] for p in PROFILE["products"]], official_domains=["shopnova.com"])  # fmt: skip
    providers = ProviderRegistry(Settings(_env_file=None, demo_mode=True))
    return asyncio.run(merchant.assess(
        providers, brand_name="ShopNova", host=sc.host, url=sc.url, html=sc.http["html"], age_days=sc.whois.get("age_days"),
        ads=ads, profile=PROFILE, thresholds=TH, external=True, terms=terms, about="advertised as ShopNova Runner",
    ))  # fmt: skip


SHOPS = [(sc.host, sc.label) for sc in default_store().all() if sc.ads]


def test_the_golden_set_has_scams_and_genuine_shops():
    labels = [lbl for _h, lbl in SHOPS]
    assert labels.count("scam_shop") >= 5 and labels.count("brand_related_legit") >= 5


@pytest.mark.parametrize(("host", "label"), SHOPS)
def test_shop_v2_calibration(host, label):
    res = _assess(host)
    s, rec = res["score"], res["record"]
    if label == "scam_shop":  # every scam: High or above, and BrandWatch reads "likely counterfeit"
        assert s["severity"].value in ("high", "critical"), (host, s["score"], sorted(res["fired"]))
        assert rec["level"]["level"] == "likely_counterfeit", (host, rec["level"])
    else:  # every genuine shop: below a finding
        assert s["severity"].value == "low", (host, s["score"], sorted(res["fired"]), res["penalties"])
        assert rec["level"]["level"] == "suspicious_retailer"
    assert rec["scoring_version"].startswith("shop-v2-")


def test_the_genuine_shops_v1_flagged_are_low_now():
    """The point of the calibration: three genuine shops scored Medium under shop-v1."""
    was_medium = []
    for host in ("outlet-sportive.co.il", "nofim-sport.co.il", "runimport.com"):
        res = _assess(host)
        v1 = _v1(res["fired"], res["record"]["registry"], default_store().get(host).whois.get("age_days"))
        assert v1 >= 25, (host, v1, sorted(res["fired"]))
        assert res["score"]["score"] < 25, (host, res["score"]["score"])
        was_medium.append(host)
    assert len(was_medium) == 3


def test_caps_count_one_cause_once():
    fired = {k: "x" for k in ("shop_company_not_in_registry", "shop_no_web_presence", "shop_no_company_details",
                              "shop_tld_language_mismatch")}  # fmt: skip
    s = merchant.score_shop(fired, {}, thresholds=TH, checks_done=3, unavailable=[])
    assert s["score"] == merchant.SHOP_GROUP_CAPS["seller"] == 25  # 51 points of one cause → 25
    assert s["breakdown"]["group_detail"]["seller"] == {"total": 51.0, "cap": 25.0, "capped": 25.0}
    assert sum(merchant.SHOP_GROUP_CAPS.values()) == merchant.SHOP_RAW_MAX == 100


def test_a_borrowed_company_number_is_not_reassuring():
    assert merchant.same_company('ספורט זון בע"מ', 'ספורט זון בע"מ') is True
    assert merchant.same_company(None, "Sport Zone Ltd", "sportzone-il.co.il") is True
    assert merchant.same_company("ONE STYLE", "Kfir Technologies Ltd", "onestyle-shopping.com") is False
    assert merchant.same_company(None, "Acme Holdings Ltd", "") is None


# ------------------------------------------------------------------------------------ the levels
def test_levels_need_goods_and_seller_evidence():
    rec = {"price": {"reference": {"price": 799}}, "external": True, "web": {"warnings": []}}
    only_seller = {"shop_company_not_in_registry": "x", "shop_free_email_only": "x"}
    assert shop_levels.system_level(only_seller, rec, "high")["level"] == "suspicious_retailer"
    both = {"shop_price_far_below_official": "x", "shop_no_company_details": "x"}
    assert shop_levels.system_level(both, rec, "high")["level"] == "likely_counterfeit"
    assert shop_levels.system_level(both, rec, "medium")["level"] == "suspicious_retailer"  # needs High
    # a scam that never delivers is fraud, not (yet) evidence of fakes
    fraud = {"shop_reviews_warn": "x", "shop_company_not_in_registry": "x"}
    rec2 = {**rec, "web": {"warnings": [{"title": "never arrived", "snippet": "scam"}]}}
    assert shop_levels.families(fraud, rec2)["goods"] == []
    rec3 = {**rec, "web": {"warnings": [{"title": "got a replica", "snippet": ""}]}}
    assert shop_levels.system_level(fraud, rec3, "high")["level"] == "likely_counterfeit"
    # no official price: the reading says what to add
    nxt = shop_levels.system_level(only_seller, {"price": {}, "external": True}, "high")["next"]
    assert any("official price" in n for n in nxt)


def test_confirmed_counterfeit_needs_proof():
    with pytest.raises(ValueError, match="proof"):
        shop_levels.validate("confirmed_counterfeit", None, "", "likely_counterfeit")
    with pytest.raises(ValueError, match="description"):
        shop_levels.validate("confirmed_counterfeit", "test_purchase", "fake", "likely_counterfeit")
    shop_levels.validate("confirmed_counterfeit", "test_purchase", "order 1042 arrived — a replica", "suspicious_retailer")
    with pytest.raises(ValueError, match="why"):  # more than the evidence supports needs a reason
        shop_levels.validate("likely_counterfeit", None, "", "suspicious_retailer")
    shop_levels.validate("suspicious_retailer", None, "", "likely_counterfeit")  # less is always allowed


def test_wording_claims_only_the_conclusion():
    sus = shop_levels.wording("suspicious_retailer", "ShopNova")
    likely = shop_levels.wording("likely_counterfeit", "ShopNova")
    conf = shop_levels.wording("confirmed_counterfeit", "ShopNova", {"proof": "test_purchase", "note": "order 1042"})
    assert "counterfeit" not in sus["subject"].lower() and "have not established" in sus["claim"]
    assert "likely" in likely["subject"].lower() and "likely" in likely["meta"]
    assert conf["subject"].startswith("Shop selling counterfeit") and "test purchase" in conf["claim"] and "order 1042" in conf["claim"]


# ------------------------------------------------------------------------------------ end to end
def _app_client(engine, tmp_path):
    from tests.test_demo_story import _api, _app, _ui

    app = _app(engine, tmp_path)
    return app, _api, _ui


def test_confirm_at_a_conclusion_then_upgrade_after_a_test_purchase(engine, tmp_path):
    from tests.test_shops import _retail_brand_scanned

    app, _api, _ui = _app_client(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b, rows = _retail_brand_scanned(app, c)
        fid = rows["footstyle-il.com"]["id"]
        assert rows["footstyle-il.com"]["shop_level"]["system"]["level"] == "likely_counterfeit"
        # confirming counterfeits outright needs the proof
        r = c.post(f"/api/findings/{fid}/confirm", json={"reason": "", "conclusion": "confirmed_counterfeit"})
        assert r.status_code == 422 and "proof" in r.json()["detail"]
        # a careful analyst confirms less than BrandWatch read: always allowed
        r = c.post(f"/api/findings/{fid}/confirm", json={"reason": "waiting for a test buy", "conclusion": "suspicious_retailer"})
        assert r.status_code == 200 and r.json()["shop_level"]["level"] == "suspicious_retailer"
        tid = c.post(f"/api/findings/{fid}/takedown").json()["id"]
        t = c.get(f"/api/takedowns/{tid}").json()
        assert "Suspected fraudulent shop" in t["body"] and "have not established that its goods are counterfeit" in t["body"]
        assert "selling counterfeit" not in t["body"]
        ui = _ui(app)
        tpage = ui.get(f"/ui/takedowns/{tid}").text
        assert "Conclusion: <b>Suspicious shop</b>" in tpage and "do not say the goods are counterfeit" in tpage
        assert "use them once the conclusion is" in tpage  # the trademark forms wait for a stronger conclusion
        # the test purchase arrives: confirmed counterfeit, with the proof
        r = c.post(f"/api/findings/{fid}/conclusion", json={"level": "confirmed_counterfeit", "proof": "test_purchase",
                                                            "reason": "test order #1042 arrived — a replica"})  # fmt: skip
        assert r.status_code == 200 and r.json()["shop_level"]["level"] == "confirmed_counterfeit"
        tpage = ui.get(f"/ui/takedowns/{tid}").text
        assert "written for a different conclusion" in tpage and "Rewrite the letter" in tpage
        assert ui.post(f"/ui/takedowns/{tid}/rewrite", follow_redirects=False).status_code == 303
        body = c.get(f"/api/takedowns/{tid}").json()["body"]
        assert "Shop selling counterfeit" in body and "a test purchase" in body and "#1042" in body
        page = ui.get(f"/ui/findings/{fid}").text
        assert "Confirmed · Confirmed counterfeit" in page and "proof: a test purchase" in page
    from brandwatch.db.base import make_session_factory

    with make_session_factory(engine)() as s:
        acts = {a.action for a in s.scalars(sa.select(m.AuditEvent).where(m.AuditEvent.object_id == uuid.UUID(fid)))}
        assert {"finding.confirmed", "finding.conclusion_updated"} <= acts
        labels = [lb.label for lb in s.scalars(sa.select(m.AnalystLabel).where(m.AnalystLabel.finding_id == uuid.UUID(fid))
                                             .order_by(m.AnalystLabel.at))]
        assert labels == ["suspicious_retailer", "confirmed_counterfeit"]


def test_the_finding_page_offers_the_three_conclusions(engine, tmp_path):
    from tests.test_shops import _retail_brand_scanned

    app, _api, _ui = _app_client(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        b, rows = _retail_brand_scanned(app, c)
        fid = rows["onestyle-shopping.com"]["id"]
        ui = _ui(app)
        page = ui.get(f"/ui/findings/{fid}").text
        for needle in ('name="conclusion" value="suspicious_retailer"', 'value="likely_counterfeit" checked',
                       'name="conclusion" value="confirmed_counterfeit"', 'name="proof"', "What would move it up",
                       "BrandWatch reads “Likely counterfeit seller” because"):  # fmt: skip
            assert needle in page, needle
        r = ui.post(f"/ui/findings/{fid}/verdict", data={"action": "confirm", "conclusion": "confirmed_counterfeit",
                                                         "proof": "test_purchase", "reason": ""})  # fmt: skip
        assert r.status_code == 200 and "needs a short description of the proof" in r.text  # shown, nothing saved
        assert c.get(f"/api/findings/{fid}").json()["finding"]["state"] == "open"


# ------------------------------------------------------------------------------------ the two fixes
def test_rescore_never_touches_shop_or_social_findings(engine, tmp_path):
    from tests.test_shop_scan import PROFILE as SCAN_PROFILE

    from brandwatch.db.base import make_session_factory
    from brandwatch.detection import rescore
    from brandwatch.detection.runner import run_scan

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"rescore-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, "ShopNova")
        brand.kind, brand.profile = "retail", SCAN_PROFILE
        s.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="brand_scan")
        s.add(job)
        s.flush()
        asyncio.run(run_scan(s, job.id, settings=settings, max_candidates=60))
        s.commit()
        shops = s.scalars(sa.select(m.Finding).where(m.Finding.brand_id == brand.id, m.Finding.kind == "shop")).all()
        assert shops
        before = {f.id: (f.current_score.score, f.current_score.scoring_version) for f in shops}
        cfg = finding_stage.ScoringConfig()
        preview = rescore.preview(s, brand.id, cfg)
        assert not ({str(f.id) for f in shops} & {r["finding_id"] for r in preview["findings"]})
        rescore.apply(s, brand.id, cfg, actor=None)
        s.flush()
        for f in shops:
            s.refresh(f)
            assert (f.current_score.score, f.current_score.scoring_version) == before[f.id]


def test_the_phishing_classifier_never_learns_from_a_confirmed_shop(engine):
    from brandwatch.db.base import make_session_factory
    from brandwatch.detection import ml

    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"ml-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, "ShopNova")
        for i, kind in enumerate(("phishing", "shop")):
            cand = m.Candidate(brand_id=brand.id, canonical_domain=f"x{i}.com", canonical_url=f"https://x{i}.com/",
                               hostname=f"x{i}.com", surface="name", last_analysis={"signals": ["credential_form"]})  # fmt: skip
            s.add(cand)
            s.flush()
            s.add(m.Finding(candidate_id=cand.id, brand_id=brand.id, severity="high", kind=kind,
                            state=FindingState.CONFIRMED, analyst_verdict=AnalystVerdict.PHISHING))  # fmt: skip
        s.flush()
        rows = ml.training_set(s, ws.id, brand_id=brand.id)
        assert [h for _x, _y, h in rows] == ["x0.com"]


# ------------------------------------------------------------------------------------ a scam shop seen in a live scan
def test_company_names_are_whole_words_or_labelled():
    page = merchant.shop_facts("<html lang='he'><body><p>יש מספר סוגים. ניתן לבחור את האפשרויות בעמוד המוצר</p>"
                               "<p>Adizero Adistar Ultra Boost X5 SL</p></body></html>", "https://x.com/", "IL")  # fmt: skip
    assert page.company_name is None  # "בעמוד" is not בע"מ, "X5 SL" is not an S.L.
    terms = merchant.shop_facts("<html lang='he'><body><p>שם העסק: One Style; ח.פ. / ע.מ.: 215539636; "
                                "דוא״ל: onestyle@gmail.com</p></body></html>", "https://x.com/terms", "IL")  # fmt: skip
    assert terms.company_name == "One Style" and terms.free_emails == ["onestyle@gmail.com"]
    assert terms.company_ids[0]["kind"] == "il_person" and terms.company_ids[0]["valid"]
    he = merchant.shop_facts('<html lang="he"><body>· ספורט זון בע"מ · ח.פ. 514445550</body></html>', "https://x.co.il/", "IL")
    assert he.company_name == 'ספורט זון בע"מ' and he.company_ids[0]["kind"] == "il"


def test_israeli_numbers_check_digit_and_sole_traders():
    assert merchant.il_check_digit("516728391") and merchant.il_check_digit("215539636")
    assert not merchant.il_check_digit("123456789") and not merchant.il_check_digit("12345")

    class _NoRegistry:  # a sole trader's or an impossible number never reaches a registry
        def single(self, *_a, **_k):
            raise AssertionError("registry called")

    sole = merchant.ShopFacts(company_ids=[{"number": "215539636", "kind": "il_person", "valid": True, "label": "ע.מ."}])
    reg = asyncio.run(merchant.check_registry(_NoRegistry(), sole, "IL"))
    assert reg["status"] == "not_checked" and reg["sole_trader"] and "sole trader" in reg["why"]
    fake = merchant.ShopFacts(company_ids=[{"number": "123456789", "kind": "il", "valid": False, "label": "ח.פ."}])
    reg = asyncio.run(merchant.check_registry(_NoRegistry(), fake, "IL"))
    assert reg["status"] == "not_found" and reg["invalid"]


def test_the_shops_own_social_accounts_are_not_a_footprint():
    from brandwatch.providers.base import ProviderResult

    class _Search:
        async def search(self, q, geo="us", lang="en"):
            hits = [{"url": "https://www.instagram.com/onestyle.israel/", "title": "One Style IL"},
                    {"url": "https://www.tiktok.com/@onestyle.israel", "title": "One Style"},
                    {"url": "https://stylehub-israel.com/terms/", "title": "תקנון"}]  # fmt: skip
            return ProviderResult(provider="t", status=__import__("brandwatch.db.enums", fromlist=["x"]).ProviderStatus.POSITIVE,
                                  data={"hits": hits})  # fmt: skip

    class _P:
        def search(self):
            return _Search()

    facts = merchant.ShopFacts(company_ids=[{"number": "215539636", "kind": "il_person"}])
    web = asyncio.run(merchant.check_web(_P(), facts, "stylehub-israel.com", "he", "IL"))
    assert web["presence"] == "none" and web["queries"][0] == '"215539636"'  # the unique number, not a generic name


def test_the_onestyle_pattern_is_a_likely_counterfeit_seller():
    """stylehub-israel.com replays what a live scan saw on a real scam shop."""
    res = _assess("stylehub-israel.com")
    rec, fired = res["record"], res["fired"]
    assert [p["kind"] for p in rec["pages_read"]][:1] == ["terms"] and rec["pages_read"][0]["ok"]
    assert rec["facts"]["company_name"] == "Style Hub" and rec["registry"]["sole_trader"]
    for sig in ("shop_free_email_only", "shop_multibrand_bundle", "shop_no_web_presence", "shop_price_far_below_official"):
        assert sig in fired, sig
    assert "golden goose" in fired["shop_multibrand_bundle"].lower()
    assert res["score"]["severity"].value == "high" and rec["level"]["level"] == "likely_counterfeit"
    # without the brand's official prices it is still a finding — a suspicious shop
    prof = {**PROFILE, "products": []}
    sc = default_store().get("stylehub-israel.com")
    ads = [{**a, "country": "IL", "ad_id": "x", "library_url": "u"} for a in sc.ads]
    terms = relevance.brand_terms("ShopNova", "shopnova", ad_keywords=PROFILE["ad_keywords"], official_domains=["shopnova.com"])
    res2 = asyncio.run(merchant.assess(
        ProviderRegistry(Settings(_env_file=None, demo_mode=True)), brand_name="ShopNova", host=sc.host, url=sc.url,
        html=sc.http["html"], age_days=1128, ads=ads, profile=prof, thresholds=TH, external=True, terms=terms, about="ad",
    ))  # fmt: skip
    assert res2["score"]["severity"].value == "medium" and res2["record"]["level"]["level"] == "suspicious_retailer"
    assert any("official price" in n for n in res2["record"]["level"]["next"])


def test_a_retail_scan_without_official_prices_says_so(engine, tmp_path):
    from brandwatch.db.base import make_session_factory
    from brandwatch.detection.runner import run_scan
    from brandwatch.events.emitter import replay

    settings = Settings(_env_file=None, demo_mode=True, evidence_dir=str(tmp_path / "ev"))
    with make_session_factory(engine)() as s:
        ws = make_workspace(s, f"noprice-{uuid.uuid4().hex[:6]}")
        brand = make_brand(s, ws, "ShopNova")
        brand.kind, brand.profile = "retail", {"countries": ["IL"], "ad_keywords": ["shopnova runner"], "products": []}
        s.add(m.BrandDomain(brand_id=brand.id, domain="shopnova.com"))
        job = m.ScanJob(workspace_id=ws.id, brand_id=brand.id, kind="brand_scan")
        s.add(job)
        s.flush()
        summary = asyncio.run(run_scan(s, job.id, settings=settings, max_candidates=40))
        alerts = [e.data["alert"] for e in replay(s, job.id) if (e.data or {}).get("alert", {}).get("kind") == "profile"]
        assert len(alerts) == 1 and "IL" in alerts[0]["title"] and alerts[0]["settings_url"].endswith("#profile")
        assert any(st["title"].startswith("No official prices for IL") for st in summary.steps)
