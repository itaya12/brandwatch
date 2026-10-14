"""Suspicious-shop connectors: SearchApi.io Meta Ad Library and the company registries (respx).
A registry that does not cover a number's country answers NOT_APPLICABLE — never "valid"."""

import json

import httpx
import pytest
import respx

from brandwatch.db.enums import ProviderStatus
from brandwatch.providers.base import ProviderError
from brandwatch.providers.impl.commerce import (
    CompaniesHouseClient,
    GleifClient,
    IsraelCompaniesClient,
    SearchApiAdsClient,
    ViesClient,
)

SEARCHAPI = "https://www.searchapi.io/api/v1/search"
DATAGOV = "https://data.gov.il/api/3/action/datastore_search"
VIES = "https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number"


@respx.mock
async def test_searchapi_meta_ads_request_and_normalisation():
    route = respx.get(SEARCHAPI).mock(return_value=httpx.Response(200, json={
        "search_information": {"total_results": 2},
        "ads": [
            {"ad_archive_id": "1234567890", "page_id": "99", "page_name": "OneStyle.Israel", "is_active": True,
             "start_date": "2026-10-01T00:00:00Z", "publisher_platform": ["FACEBOOK", "INSTAGRAM"],
             "snapshot": {"body": {"text": "2 זוגות ON CLOUD ב-699 ₪"}, "link_url": "https://stylehub-israel.com/?fbclid=x",
                          "images": [{"resized_image_url": "https://img/1.jpg"}]}},
            {"ad_archive_id": "555", "page_id": "7", "page_name": "No link", "snapshot": {"body": {"text": "video"}}},
        ],
    }))  # fmt: skip
    res = await SearchApiAdsClient(api_key="k").meta_ads("on cloud", "il")
    sent = route.calls.last.request
    assert sent.headers["authorization"] == "Bearer k"
    q = dict(sent.url.params)
    assert q["engine"] == "meta_ad_library" and q["q"] == "on cloud" and q["country"] == "IL"
    assert q["search_type"] == "keyword_exact_phrase" and q["platforms"] == "facebook,instagram"
    assert res.status is ProviderStatus.POSITIVE and res.cost_usd == 0.004
    (ad,) = res.data["ads"]  # the ad without a landing page is dropped
    assert ad["page_name"] == "OneStyle.Israel" and ad["link_url"].startswith(
        "https://stylehub-israel.com/"
    )
    assert ad["library_url"] == "https://www.facebook.com/ads/library/?id=1234567890"
    assert (
        ad["platforms"] == ["facebook", "instagram"]
        and ad["start_date"] == "2026-10-01"
        and ad["image"]
    )


@respx.mock
async def test_searchapi_error_body_and_missing_key():
    respx.get(SEARCHAPI).mock(return_value=httpx.Response(200, json={"error": "Invalid country"}))
    with pytest.raises(ProviderError, match="Invalid country"):
        await SearchApiAdsClient(api_key="k").meta_ads("on cloud", "zz")
    with pytest.raises(ProviderError, match="no API key"):
        await SearchApiAdsClient().meta_ads("on cloud", "IL")


@respx.mock
async def test_israel_registry_found_not_found_and_not_applicable():
    route = respx.get(DATAGOV).mock(side_effect=[
        httpx.Response(200, json={"success": True, "result": {"records": [
            {"מספר חברה": 515151515, "שם חברה": "וואן סטייל בע~מ", "סטטוס חברה": "פעילה", "תאריך התאגדות": "01/01/2020"}]}}),
        httpx.Response(200, json={"success": True, "result": {"records": []}}),
    ])  # fmt: skip
    c = IsraelCompaniesClient()
    found = await c.lookup("51-515151-5", "IL")
    assert (
        found.status is ProviderStatus.POSITIVE
        and found.data["status"] == "active"
        and found.data["name"]
    )
    assert json.loads(dict(route.calls[0].request.url.params)["filters"]) == {
        "מספר חברה": 515151515
    }
    missing = await c.lookup("516666666", "IL")
    assert missing.status is ProviderStatus.NEGATIVE and missing.data["status"] == "not_found"
    # a sole trader's number (personal ID) and a foreign number are not this registry's business
    assert (await c.lookup("034567891", "IL")).status is ProviderStatus.NOT_APPLICABLE
    assert (await c.lookup("515151515", "GB")).status is ProviderStatus.NOT_APPLICABLE
    assert route.call_count == 2


@respx.mock
async def test_israel_registry_marks_dissolved():
    respx.get(DATAGOV).mock(return_value=httpx.Response(200, json={"success": True, "result": {"records": [
        {"מספר חברה": 512222222, "שם חברה": "ישנה בע~מ", "סטטוס חברה": "מחוקה"}]}}))  # fmt: skip
    res = await IsraelCompaniesClient().lookup("512222222", "IL")
    assert res.status is ProviderStatus.POSITIVE and res.data["status"] == "dissolved"


@respx.mock
async def test_companies_house():
    respx.get("https://api.company-information.service.gov.uk/company/00000006").mock(
        return_value=httpx.Response(200, json={"company_name": "MARINE LTD", "company_status": "active"}))  # fmt: skip
    respx.get("https://api.company-information.service.gov.uk/company/12345678").mock(
        return_value=httpx.Response(404)
    )
    c = CompaniesHouseClient(api_key="ch")
    ok = await c.lookup("00000006", "GB")
    assert ok.status is ProviderStatus.POSITIVE and ok.data["name"] == "MARINE LTD"
    assert (await c.lookup("12345678", "UK")).status is ProviderStatus.NEGATIVE
    assert (await c.lookup("12345678", "IL")).status is ProviderStatus.NOT_APPLICABLE


@respx.mock
async def test_vies_and_gleif():
    respx.post(VIES).mock(side_effect=[
        httpx.Response(200, json={"valid": True, "name": "ACME GMBH", "address": "Berlin"}),
        httpx.Response(200, json={"valid": False, "name": "---"}),
    ])  # fmt: skip
    v = ViesClient()
    assert (await v.lookup("DE123456789", "DE")).data["name"] == "ACME GMBH"
    assert (await v.lookup("FR12345678901", "FR")).status is ProviderStatus.NEGATIVE
    assert (
        await v.lookup("123456789", "US")
    ).status is ProviderStatus.NOT_APPLICABLE  # not an EU VAT number

    respx.get("https://api.gleif.org/api/v1/lei-records").mock(side_effect=[
        httpx.Response(200, json={"data": [{"id": "529900T8BM49AURSDO55", "attributes": {"entity": {
            "legalName": {"name": "On Holding AG"}, "registeredAs": "CHE-123", "status": "ACTIVE"}}}]}),
        httpx.Response(200, json={"data": []}),
    ])  # fmt: skip
    g = GleifClient()
    assert (await g.lookup("", "CH", "On Holding AG")).data["lei"] == "529900T8BM49AURSDO55"
    # a small shop without an LEI proves nothing either way
    assert (await g.lookup("", "IL", "OneStyle")).status is ProviderStatus.UNKNOWN
