"""Where a finding came from at a glance (one tile per source: Google, ChatGPT, Facebook …), a watchlist that fits a laptop
screen (first / last / next / scans in one Seen column, the brand under the domain), and map tabs that read as buttons."""

from __future__ import annotations

from fastapi.testclient import TestClient
from tests.test_demo_story import _api, _app, _ui
from tests.test_findings_bulk import _brand

from brandwatch.api import labels


def test_one_tile_per_kind_of_source():
    got = labels.source_badges(["serpapi", "serper", "ct", "crtsh", "ai_answer"])
    assert [b["g"] for b in got] == ["google", "cert", "ai"]  # four APIs are one source to a reader; at most three tiles
    assert got[0]["label"] == "Google" and got[0]["glyph"] == "G" and "Google search" in got[0]["title"]
    assert labels.source_badges([{"stream": "manual", "pattern": "pivot: shares cert"}])[0]["g"] == "pivot"
    assert labels.source_badges([{"stream": "manual", "pattern": None}])[0]["label"] == "Analyst scan"
    assert labels.source_badges([{"stream": "social"}, {"stream": "meta_ads"}], limit=5)[1]["g"] == "meta_ads"
    assert labels.source_badges([]) == []


def test_the_lists_show_where_each_site_was_found_and_the_watchlist_fits(engine, tmp_path):
    app = _app(engine, tmp_path)
    with TestClient(app):
        c, ui = _api(app), _ui(app)
        _brand(c, app)
        findings = ui.get("/ui/findings").text
        assert 'class="srcic s-' in findings and 'class="hrow"' in findings
        assert "· found by " not in findings  # the tiles and a short name replaced the sentence
        watch = ui.get("/ui/candidates").text
        head = watch.split('id="ctable"')[1].split("</thead>")[0]
        assert "<th>Seen</th>" in head and "First seen" not in head and "Last seen" not in head and "<th>Brand</th>" not in head
        assert 'class="seen ts-short"' in watch and "<span>scans</span>" in watch and 'class="srcic s-' in watch
        dash = ui.get("/ui/dashboard").text
        tabs = dash.split('class="geotabs"')[1].split("</div>")[0]
        assert tabs.count('class="ic"><svg') == 2 and "where the fakes are hosted" in tabs and 'id="infra-n"' in tabs
        base = ui.get("/ui/brands").text
        assert "fmtShort" in base  # a narrow date column leaves this year's year out
