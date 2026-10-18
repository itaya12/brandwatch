"""AI answers: what ChatGPT / Gemini / Google AI Mode tell users about the brand's contacts, checked
against the contacts on its own website (detection/contacts.py, ai_prompts.py, ai_answers.py)."""

from __future__ import annotations

import uuid

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui

from brandwatch.detection import ai_prompts, contacts
from brandwatch.providers.impl.commerce import SearchApiAdsClient

ANSWER = """מספר הטלפון של תמיכת בנק הפועלים הוא: *2407 או 03-9817777
* שירות: 2407* (או בחיוג ישיר: 03-6532407) · תמיכה דיגיטלית: 2409* · הונאות (24/7): 9391*
* מחו"ל: 972-3-6532620+ · WhatsApp: 054-9882407 · מיקוד 6688314 · שעות 06:30 – 22:00 · 2026-10-18
* support@shopnova-help.net · כניסה: login.bankhapoalim.co.il"""


# ------------------------------------------------------------------------------------ extracting
def test_every_contact_is_read_and_normalised_whatever_the_writing():
    got = {(f.kind, f.value) for f in contacts.from_text(ANSWER)}
    assert {("phone", "+97239817777"), ("phone", "+97236532407"), ("phone", "+97236532620"), ("phone", "+972549882407"),
            ("star", "*2407"), ("star", "*2409"), ("star", "*9391"), ("email", "support@shopnova-help.net")} <= got  # fmt: skip
    values = {v for _k, v in got}
    assert not any("6688314" in v or "2026" in v or "0630" in v for v in values)  # a postal code, a date, opening hours
    assert contacts.normalize_phone("+972 3 653 2407") == contacts.normalize_phone("03-6532407") == contacts.normalize_phone("00972-3-6532407")
    assert contacts.normalize_phone("(800) 555-1234", "1") == "+18005551234"
    assert [(f.kind, f.value) for f in contacts.from_text("call **\\*6700** now")] == [("star", "*6700")]  # markdown from an AI
    assert contacts.urls_in(ANSWER) == ["login.bankhapoalim.co.il"]  # never the domain of an e-mail address
    page = ('<a href="tel:*2407">*2407</a><a href="tel:+97236532407">03-6532407</a><a href="mailto:Help@Bank.co.il?subject=x">x</a>'
            '<a href="https://api.whatsapp.com/send?phone=972549882407">WhatsApp</a><img src="logo@2x.png">')  # fmt: skip
    rows = {(f.kind, f.value) for f in contacts.from_html(page, "https://bank.co.il/contact")}
    assert rows == {("star", "*2407"), ("phone", "+97236532407"), ("email", "help@bank.co.il"), ("whatsapp", "+972549882407")}
    known = contacts.known_set({"phone": [{"value": "+97236532407"}]}, ["*2407", {"value": "054-9882407"}])
    assert {"phone:+97236532407", "star:*2407", "phone:+972549882407"} <= known  # a WhatsApp number counts as a known phone


def test_the_proposal_asks_like_a_user_in_each_language_of_the_brand():
    from brandwatch.config.brand_config import DetectionConfig

    det = DetectionConfig(search_markets=[{"country": "il", "langs": ["he", "en"]}])
    rows = ai_prompts.proposal("בנק הפועלים", det, limit=8)
    assert len(rows) == 8 and {r["lang"] for r in rows} == {"he", "en"} and {r["topic"] for r in rows} == set(ai_prompts.TOPICS)
    assert rows[0]["text"] == "מה מספר הטלפון של שירות הלקוחות של בנק הפועלים?"
    assert ai_prompts.retracted("I apologize — that number was not accurate") and ai_prompts.retracted("זו הייתה טעות")
    assert "אני חושד שזו הונאה" in ai_prompts.follow_up("he", brand="בנק הפועלים", contact="03-9817777", kind="phone")
    assert ai_prompts.clean([{"text": "hi"}, "What is the phone of X?", "what is the phone of x?"]) == [
        {"text": "What is the phone of X?", "topic": "custom", "lang": "en"}]


# ------------------------------------------------------------------------------------ the engines
@respx.mock
async def test_searchapi_ai_engines_are_asked_as_a_user_and_their_sources_kept():
    route = respx.get("https://www.searchapi.io/api/v1/search").mock(return_value=httpx.Response(200, json={
        "markdown": "Call **\\*6700**", "reference_links": [{"index": 1, "title": "Contact", "link": "https://shopnova.com/contact", "source": "shopnova.com"}],
        "response_metadata": {"model": "gpt-x", "is_web_search_performed": True}, "pagination": {"conversation_token": "tok"}}))  # fmt: skip
    c = SearchApiAdsClient("k", client=httpx.AsyncClient())
    r = await c.ask("chatgpt", "What is the ShopNova phone?")
    assert r.ok and r.data["answer"] == "Call **\\*6700**" and r.data["references"][0]["link"] == "https://shopnova.com/contact"
    sent = dict(route.calls[-1].request.url.params)
    assert sent["engine"] == "chatgpt" and sent["web_search"] == "true" and route.calls[-1].request.headers["authorization"] == "Bearer k"
    await c.ask("google_ai_mode", "again", gl="il", hl="iw")
    assert dict(route.calls[-1].request.url.params) == {"engine": "google_ai_mode", "q": "again", "gl": "il", "hl": "iw"}
    await c.ask("google_ai_mode", "proof?", conversation_token="tok")
    assert dict(route.calls[-1].request.url.params)["conversation_token"] == "tok" and "gl" not in dict(route.calls[-1].request.url.params)
    from brandwatch.providers.base import ProviderError

    with pytest.raises(ProviderError, match="unknown AI engine"):
        await c.ask("claude", "x")


# ------------------------------------------------------------------------------------ the whole run (demo)
def _brand(c):
    b = c.post("/api/brands", json={"name": f"ShopNova AI {uuid.uuid4().hex[:4]}", "domains": ["shopnova.com"]}).json()
    return b


def _run(app, c, bid, **body):
    r = c.post(f"/api/brands/{bid}/scan", json=body)
    assert r.status_code == 202, r.text
    job = uuid.UUID(r.json()["job_id"])
    app.state.queue.wait(job, timeout=180)
    return job


def test_ai_answers_find_the_made_up_and_the_scam_contacts_and_nothing_else(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _brand(c)
        bid = b["id"]
        view = c.get(f"/api/brands/{bid}").json()["ai_answers"]
        assert view["on"] is False and view["prompts"]["approved"] is False and view["requests"] > 0
        assert c.post(f"/api/brands/{bid}/scan", json={"only": "ai"}).status_code == 409  # questions not approved yet
        # read the official contacts first (free): homepage → /contact
        _run(app, c, bid, only="contacts")
        got = c.get(f"/api/brands/{bid}").json()["ai_answers"]
        assert {r["value"] for r in got["contacts"]["star"]} >= {"*6700", "*6711"}
        assert "+97236000000" in {r["value"] for r in got["contacts"]["phone"]} and got["contacts"]["email"][0]["value"] == "support@shopnova.com"
        assert got["contacts"]["whatsapp"][0]["pages"] == ["https://shopnova.com/contact"]  # the page is the proof
        # approve the proposed questions, then ask the assistants
        r = c.put(f"/api/brands/{bid}/ai-prompts", json={"prompts": got["prompts"]["proposal"]})
        assert r.status_code == 200 and r.json()["ai_answers"]["prompts"]["approved"]
        _run(app, c, bid, only="ai")
        rows = {f["hostname"]: f for f in c.get("/api/findings", params={"brand_id": bid, "kind": "ai_answer"}).json()}
        assert set(rows) == {"03-9817777", "help@shopnova-care.net", "shopnova-login.com"}, set(rows)
        assert rows["03-9817777"]["severity"] == "critical"  # published only on a look-alike site that ChatGPT cited
        assert rows["help@shopnova-care.net"]["severity"] == "high"  # made up; asked for proof, Gemini took it back
        assert rows["shopnova-login.com"]["severity"] == "critical"  # a look-alike login address
        d = c.get(f"/api/findings/{rows['03-9817777']['id']}").json()
        rec = d["score"]["ai_answer"]
        assert rec["verdict"] == "offsite" and rec["engines"] == ["chatgpt"]
        assert any(ch["host"] == "shopnova-support-center.com" and ch["found"] and not ch["official"] for ch in rec["checks"])
        assert any(ch["host"] == "shopnova.com" and ch["official"] and not ch["found"] for ch in rec["checks"])
        mail = c.get(f"/api/findings/{rows['help@shopnova-care.net']['id']}").json()["score"]["ai_answer"]
        assert mail["verdict"] == "hallucinated" and mail["followups"][0]["retracted"] and "ai_retracted" in mail["why"]
        page = ui.get(f"/ui/findings/{rows['03-9817777']['id']}").text
        assert "AI answer" in page and "shopnova-support-center.com" in page and "This is our contact" in page
        assert "<mark>03-9817777</mark>" in page and "&lt;mark&gt;" not in page  # highlighted, not printed as text
        assert len(rec["followups"]) == 1  # one follow-up per assistant, however many questions it answered
        assert not any(ch["lookalike"] for ch in rec["checks"] if ch["official"])  # the brand's own site is never a look-alike
        listing = ui.get(f"/ui/findings?brand_id={bid}&kind=ai_answer").text
        assert "03-9817777" in listing and "help@shopnova-care.net" in listing
        # "this is our contact": dismissed, remembered, never raised again
        r = ui.post(f"/ui/findings/{rows['help@shopnova-care.net']['id']}/our-contact", follow_redirects=False)
        assert r.status_code == 303
        assert "help@shopnova-care.net" in {k["value"] for k in c.get(f"/api/brands/{bid}").json()["ai_answers"]["known_contacts"]}
        _run(app, c, bid, only="ai")
        again = {f["hostname"]: f for f in c.get("/api/findings", params={"brand_id": bid, "kind": "ai_answer", "state": "open"}).json()}
        assert "help@shopnova-care.net" not in again and "03-9817777" in again


def test_the_brand_page_switches_ai_answers_on_and_approves_its_questions(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        b = _brand(c)
        bid = b["id"]
        page = ui.get(f"/ui/brands/{bid}").text
        assert "AI answers off · turn on" in page and 'id="ai-answers"' in page and "approve the questions first" in page
        r = ui.post(f"/ui/brands/{bid}/ai-answers", data={"on": "1"}, follow_redirects=False)
        assert r.status_code == 303
        got = c.get(f"/api/brands/{bid}").json()
        assert got["config"]["detection"]["ai_answers"] is True and got["config_custom"] is False
        assert "ai_answers" in got["schedule"]["tasks"]  # an automatic scan would ask them too
        texts = [p["text"] for p in got["ai_answers"]["prompts"]["proposal"]][:2] + ["Where is the ShopNova help desk?"]
        r = ui.post(f"/ui/brands/{bid}/ai-prompts", data={"q": texts, "action": "approve"}, follow_redirects=False)
        assert r.status_code == 303
        st = c.get(f"/api/brands/{bid}").json()["ai_answers"]["prompts"]
        assert st["approved"] and [p["text"] for p in st["prompts"]] == texts
        r = ui.post(f"/ui/brands/{bid}/known-contacts", data={"value": "*1234", "action": "add"}, follow_redirects=False)
        assert r.status_code == 303 and {"*1234"} <= {k["value"] for k in c.get(f"/api/brands/{bid}").json()["ai_answers"]["known_contacts"]}
        assert ui.post(f"/ui/brands/{bid}/known-contacts", data={"value": "hello", "action": "add"}).status_code == 200  # said on the page
        page = ui.get(f"/ui/brands/{bid}").text
        assert "AI answers on · turn off" in page and 'value="ai"' in page


def test_ai_answers_are_chosen_when_the_brand_is_added_and_approved_on_the_set_up_page(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        name = f"AiNew {uuid.uuid4().hex[:4]}"
        r = ui.post("/ui/brands", data={"name": name, "entry": ["shopnova.com"], "preset": "standard", "ai_answers_form": "1",
                                        "ai_answers": "on", "ai_engines": ["chatgpt", "gemini"]}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303
        b = next(x for x in c.get("/api/brands").json() if x["name"] == name)
        got = c.get(f"/api/brands/{b['id']}").json()
        det = got["config"]["detection"]
        assert det["ai_answers"] is True and det["ai_engines"] == ["chatgpt", "gemini"] and got["config_custom"] is False
        page = ui.get(f"/ui/brands/{b['id']}/setup").text
        assert 'id="s-ai"' in page and 'name="aiq"' in page and "ChatGPT, Gemini" in page
        texts = [p["text"] for p in got["ai_answers"]["prompts"]["proposal"]][:3]
        r = ui.post(f"/ui/brands/{b['id']}/setup", data={"action": "save", "aiq": texts, "ailang": ["en"] * 3, "aitopic": ["support_phone"] * 3,
                                                         "max_candidates": "100", "max_names_checked": "1000"}, follow_redirects=False)  # fmt: skip
        assert r.status_code == 303, r.text[:300]
        st = c.get(f"/api/brands/{b['id']}").json()["ai_answers"]["prompts"]
        assert st["approved"] and [p["text"] for p in st["prompts"]] == texts
