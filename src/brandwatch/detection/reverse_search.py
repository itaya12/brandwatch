"""Search backwards from a link: who else uses the same traffic-distribution campaign, or sends data to the same place?

A group of confirmed sites is tied by something an operator reuses: the number of a traffic-distribution link
(``qemow.com/go/3115960``), the host a stolen password is posted to. The same thing is on the operator's OTHER sites, and
urlscan.io has scanned many of them (``?subid1=<domain>`` in the link names the site that sent the visitor). The analyst presses
"search for more" on a link; the answer is cached for 24 h (``intel_lookups``) and listed under the link. A campaign number in an
affiliate network can be shared by many unrelated advertisers, so the list is a lead, not proof; domains that carry the brand's name
are marked, and those can be scanned with one button.
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from sqlalchemy.orm import Session

from brandwatch.detection import intel as intel_mod
from brandwatch.detection.sources import _looks_related

SEARCHABLE = ("tds_campaign", "data_sink", "affiliate_id", "redirector")
_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)
MAX_HITS = 100


def query_for(kind: str, value: str) -> str | None:
    """The urlscan.io query for a link, or None when the kind cannot be searched backwards (a DNS token or a Cloudflare account
    has no public index)."""
    value = value.strip()
    if kind == "tds_campaign" and "/" in value:
        host, _, path = value.partition("/")
        return f'page.domain:{host} AND page.url:"{path}"'
    if kind == "data_sink" and _DOMAIN.match(value):
        return f"domain:{value}"
    if kind == "affiliate_id" and re.fullmatch(r"[A-Za-z0-9_]{1,24}=[A-Za-z0-9._-]{3,64}", value):
        return f'page.url:"{value}"'  # the pages whose address carries the id: ?atid=70321
    if kind == "redirector" and _DOMAIN.match(value):
        return f"page.domain:{value}"
    return None


def extract_domains(hits: list[dict[str, Any]], kind: str, own: set[str]) -> list[dict[str, Any]]:
    """The other sites in the answer: for a traffic link, the domains named in its query string (``subid1=…``: the site the visitor
    came from); for a data sink, the page that talked to it."""
    seen: dict[str, dict[str, Any]] = {}
    for h in hits:
        url = str(h.get("url") or "")
        cands: list[str] = []
        if kind == "tds_campaign":
            cands = [v.lower() for _k, v in parse_qsl(urlsplit(url).query) if _DOMAIN.match(v)]
        elif kind in ("affiliate_id", "redirector") and (h.get("task_domain") or h.get("domain")):
            cands = [str(h.get("task_domain") or h["domain"]).lower()]  # the site that was scanned, which led to the link
        elif h.get("domain"):
            cands = [str(h["domain"]).lower()]
        for d in cands:
            if d and d not in own and d not in seen:
                seen[d] = {"domain": d, "time": str(h.get("time") or "")[:10], "url": url, "result": f"https://urlscan.io/result/{h['task_id']}/" if h.get("task_id") else None}
    return list(seen.values())


async def search(providers: Any, kind: str, value: str, *, own: set[str], brand_key: str = "") -> dict[str, Any]:
    q = query_for(kind, value)
    if q is None:
        return {"query": None, "total": 0, "sites": [], "note": "this kind of link has no public index to search"}
    res = await providers.urlscan().search(q, limit=MAX_HITS)
    if not res.ok and res.error:
        return {"query": q, "total": 0, "sites": [], "note": f"urlscan.io: {res.error}"}
    data = res.data or {}
    sites = extract_domains(list(data.get("results") or []), kind, own)
    for s in sites:
        s["brand_related"] = bool(brand_key) and _looks_related(s["domain"], brand_key)
    sites.sort(key=lambda s: (not s["brand_related"], s["domain"]))
    return {"query": q, "total": data.get("total") or len(sites), "sites": sites, "note": None}


def cached(session: Session, workspace_id: uuid.UUID, kind: str, value: str) -> dict[str, Any] | None:
    row = intel_mod._get_row(session, workspace_id, "campaign_link", f"{kind}:{value}", "urlscan", "reverse")
    return {**(row.payload or {}), "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None} if row is not None and row.status == "ok" else None


def store(session: Session, workspace_id: uuid.UUID, kind: str, value: str, result: dict[str, Any]) -> None:
    intel_mod.put_row(session, workspace_id, "campaign_link", f"{kind}:{value}", "urlscan", "reverse", result)
