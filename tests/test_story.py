"""How it works: the six-chapter story on the workspace's own data and the illustrated fallback
for an empty workspace."""

from fastapi.testclient import TestClient
from tests.conftest import (
    make_brand,
    make_candidate,
    make_finding,
    make_risk_score,
    make_user,
    make_workspace,
)
from tests.test_demo_story import _api, _app, _brand_with_scan, _ui

from brandwatch.db.enums import DiscoverySource
from brandwatch.db.models import CandidateSource
from brandwatch.demo.story import _layout, story

CHAPTERS = ("learn", "find", "visit", "score", "map", "takedown")


def test_the_story_runs_on_the_workspace_data(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c = _api(app)
        brand, _job = _brand_with_scan(
            app, c, ["https://shopnova-giftcard.com/", "https://shopn0va.com/"]
        )
        page = _ui(app).get("/ui/how-it-works").text
        for ch in CHAPTERS:
            assert f'id="ch-{ch}"' in page, ch
        assert "Play the story" in page and 'id="rail"' in page
        # the story follows the workspace's first brand (the suite's shared admin workspace may hold
        # brands from earlier tests); the "try it yourself" box is gone
        assert brand["id"] in {b["id"] for b in c.get("/api/brands").json()}
        assert 'id="try"' not in page and "Try it yourself" not in page and "lexical-check" not in page
        # the deep material is still here, folded
        for anchor in (
            'id="deeper"',
            'id="all-steps"',
            'id="demo"',
            'id="under-the-hood"',
            'id="glossary"',
            'id="step-13"',
        ):
            assert anchor in page, anchor


def test_the_story_reads_its_own_workspace(session):
    """Deterministic, on a fresh workspace: flagged look-alikes come first and carry the stream that
    found them; the scored finding drives the score chapter; unrelated hosts are left out."""
    ws = make_workspace(session, "story")
    user = make_user(session, ws, "story@example.com")
    brand = make_brand(session, ws)
    flagged = make_candidate(session, brand, "https://shopnova-login.com/")
    session.add(CandidateSource(candidate_id=flagged.id, source=DiscoverySource.CT))
    watched = make_candidate(session, brand, "https://shopnovaa.com/")
    session.add(CandidateSource(candidate_id=watched.id, source=DiscoverySource.DNSTWIST))
    make_candidate(session, brand, "https://bakery-menu.example/")  # not a look-alike: never shown
    make_risk_score(session, make_finding(session, flagged))
    session.flush()

    s = story(session, user)
    rows = s["candidates"]["rows"]
    assert not s["candidates"]["illustrative"] and s["candidates"]["total"] == 3
    assert [r["host"] for r in rows] == ["shopnova-login.com", "shopnovaa.com"]
    assert (
        rows[0]["flag"] == "high"
        and rows[0]["streams"] == ["Certificate logs"]
        and rows[1]["flag"] is None
    )
    f = s["finding"]
    assert (
        f["host"] == "shopnova-login.com" and f["score"] == 80 and f["signals"][0]["points"] == 22
    )
    assert s["brand"]["illustrative"]  # no fingerprint yet → the learn chapter says so


def test_an_empty_workspace_gets_a_labelled_illustration(session):
    """A fresh workspace (the suite's shared admin workspace always has brands) still gets every
    chapter, each marked as an illustration, and a laid-out example graph."""
    user = make_user(session, make_workspace(session, "empty"), "empty@example.com")
    s = story(session, user)
    assert (
        s["brand"]["illustrative"]
        and s["candidates"]["illustrative"]
        and s["graph"]["illustrative"]
    )
    assert s["finding"] is None and s["takedown"] is None and s["candidates"]["rows"]
    assert (
        s["graph"]["nodes"][0]["seed"] and len(s["graph"]["edges"]) == len(s["graph"]["nodes"]) - 1
    )
    assert len(s["portals"]) >= 20 and s["example"]["signals"]


def test_graph_layout_stays_inside_the_picture():
    chain = ["a", "b", "c", "d", "e"]
    star = ["s"] + [f"n{i}" for i in range(12)]
    for ids, links in (
        (chain, list(zip(chain, chain[1:], strict=False))),
        (star, [("s", n) for n in star[1:]]),
    ):
        pos = _layout(ids, ids[0], links)
        assert pos[ids[0]] == (260.0, 170.0)
        assert all(20 <= x <= 500 and 10 <= y <= 330 for x, y in pos.values())
        assert len({(round(x), round(y)) for x, y in pos.values()}) == len(
            ids
        )  # no two nodes on one spot
