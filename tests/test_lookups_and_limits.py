"""DNS / WHOIS method choice with fallback, the look-alike names limit, short write transactions."""

import asyncio
import uuid

import pytest

from brandwatch import tenancy
from brandwatch.detection import dnslookup, sources


def test_policy_fallback_goes_to_the_other_method(monkeypatch):
    calls: list[str] = []
    monkeypatch.setitem(dnslookup._REGISTERED, "python", lambda n: calls.append("python") or None)
    monkeypatch.setitem(dnslookup._REGISTERED, "service", lambda n: calls.append("service") or True)
    dnslookup.set_policy("python", True)
    assert dnslookup.registered("x.example") is True and calls == ["python", "service"]
    calls.clear()
    dnslookup.set_policy("python", False)  # no fallback: "no answer" stays unknown
    assert dnslookup.registered("x.example") is None and calls == ["python"]
    calls.clear()
    dnslookup.set_policy("service", True)
    assert dnslookup.registered("x.example") is True and calls == ["service"]
    dnslookup.set_policy("bogus", True)
    assert dnslookup.current_policy().mode == "python"


def test_whois_route_follows_mode_and_fallback():
    lk = {
        "dns": {"mode": "python", "fallback": True},
        "whois": {"mode": "python", "fallback": True},
    }
    assert tenancy.whois_route(lk) == ["rdap", "local_whois", "whoisxml"]
    lk["whois"] = {"mode": "service", "fallback": True}
    assert tenancy.whois_route(lk) == ["whoisxml", "rdap", "local_whois"]
    lk["whois"] = {"mode": "service", "fallback": False}
    assert tenancy.whois_route(lk) == ["whoisxml"]
    lk["whois"] = {"mode": "python", "fallback": False}
    assert tenancy.whois_route(lk) == ["rdap", "local_whois"]


def test_workspace_lookups_round_trip(session):
    from brandwatch.db.models import Workspace

    ws = Workspace(name=f"lk-{uuid.uuid4().hex[:6]}")
    session.add(ws)
    session.flush()
    assert tenancy.workspace_lookups(session, ws.id)["dns"] == {"mode": "python", "fallback": True}
    tenancy.set_workspace_lookups(session, ws.id, {"dns": {"mode": "service", "fallback": False}})
    got = tenancy.workspace_lookups(session, ws.id)
    assert got["dns"] == {"mode": "service", "fallback": False}
    assert got["whois"] == {"mode": "python", "fallback": True}  # untouched


def test_names_limit_bounds_the_dns_checks():
    calls: list[str] = []

    def resolver(name: str):
        calls.append(name)
        return False

    r = asyncio.run(
        sources.stream_dnstwist(
            ["cryptohopper.com"], tlds="common", max_hits=None, resolver=resolver, max_checks=100
        )
    )
    assert len(calls) == 100 == r.checked and r.generated > 100
    assert "(limit 100)" in (r.note or "")


def test_scan_request_carries_the_names_limit():
    from brandwatch.api.brands import ScanRequest

    assert ScanRequest(max_candidates=100, max_names=100).max_names == 100
    with pytest.raises(ValueError):
        ScanRequest(max_names=0)


def test_checkpoint_commits_pending_work_before_a_provider_call(session):
    from brandwatch.db.base import checkpoint, set_checkpoint

    committed: list[bool] = []
    real_commit = session.commit
    session.commit = lambda: committed.append(True) or real_commit()  # type: ignore[method-assign]
    try:
        from brandwatch.db.models import Workspace

        session.add(Workspace(name=f"cp-{uuid.uuid4().hex[:6]}"))
        set_checkpoint(session)
        checkpoint()
        assert committed == [True]
        set_checkpoint(None)
        checkpoint()  # no scan session registered: nothing happens
        assert committed == [True]
    finally:
        session.commit = real_commit  # type: ignore[method-assign]
