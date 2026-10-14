"""One map of every confirmed phishing site: which of them are connected, by what, and how sure we are.

The infrastructure map of a campaign starts from ONE confirmed site and pivots outwards. With dozens of confirmed sites the
question is the other way round: *do these sites belong together?* This module answers it from what is already known about
each site (the evidence of its finding, the campaign its map produced, and the investigation of the site and its network).

Every kind of link has a **weight**: how likely it is that two sites sharing it are one operation. An affiliate id in a redirect, a
registrant, an analytics ID are close to proof; a server on a small hoster is strong; a server of a big cloud, or a redirector host,
is only a hint; a CDN address, a registrar or a favicon says (almost) nothing. For a pair of sites the kinds they share are combined
(``1 - Π(1 - w)``): several hints add up, but the same kind twice does not count twice. Sites whose pair confidence reaches
``JOIN`` (0.75) are one *operation* (union-find); the confidence of an operation is the weakest tie that holds its members.
The result feeds the graph of the page, the operation cards and the sentences above them (``operations.py``).
"""

from __future__ import annotations

import itertools
import re
import uuid
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.db.enums import EvidenceType, NodeType
from brandwatch.db.models import (
    Brand,
    Campaign,
    CampaignNode,
    Candidate,
    Evidence,
    Finding,
    HtmlSnapshot,
    Screenshot,
    WhoisObservation,
)
from brandwatch.detection import hosting
from brandwatch.detection import intel as intel_mod
from brandwatch.detection import investigation as inv
from brandwatch.detection import operations as ops_mod
from brandwatch.detection import pattern as pattern_mod
from brandwatch.detection import redirects as redirects_mod
from brandwatch.detection import reverse_search as reverse_mod
from brandwatch.detection.baseline import whitelist_domains
from brandwatch.detection.whois_history import is_private

# how likely two sites that share this are one operation (see the module docstring); "ip" depends on the network, see ``weight``
WEIGHT = {"affiliate_id": 0.95, "registrant": 0.9, "tracking_id": 0.9, "data_sink": 0.9, "dns_token": 0.9, "cf_ns_pair": 0.85, "certificate": 0.8,
          "ip": 0.8, "tds_campaign": 0.8, "redirector": 0.6, "kit": 0.6, "past_ip": 0.5, "batch": 0.3, "kit_look": 0.3,
          "registrar": 0.1, "nameserver": 0.1, "favicon": 0.1, "shared_ip": 0.1, "shared_tds": 0.1}  # fmt: skip
JOIN = 0.75  # a pair of sites at or above this is one operation (two hints, a redirect host and a purchase day, do not reach it; a hint and an old server do)
POSSIBLE = 0.3  # below JOIN, at or above this: a real hint, drawn dashed; below this: "common, not proof"
STRONG = ("affiliate_id", "registrant", "tracking_id", "data_sink", "dns_token", "cf_ns_pair", "certificate", "ip", "tds_campaign")  # alone, they join sites
MEDIUM = ("redirector", "kit", "past_ip", "batch", "kit_look")  # hints: they add up
WEAK = ("favicon", "registrar", "nameserver", "shared_ip", "shared_tds")
ORDER = (*STRONG, *MEDIUM, *WEAK)
LABEL = {"ip": "the same server", "certificate": "the same TLS certificate", "tracking_id": "the same analytics / pixel ID",
         "registrant": "the same registrant", "favicon": "the same favicon", "registrar": "the same registrar",
         "nameserver": "the same name server", "shared_ip": "a server shared by many other sites", "shared_tds": "a traffic campaign used by hundreds of unrelated sites",
         "cf_ns_pair": "the same Cloudflare account (its two name servers are assigned to one account)",
         "dns_token": "the same domain-verification token in DNS (a token belongs to one account)",
         "tds_campaign": "the same traffic-distribution campaign (the id in the redirect link)",
         "data_sink": "the same place the stolen data is sent",
         "affiliate_id": "the same affiliate id on the brand's own site",
         "redirector": "the same redirect host", "past_ip": "a server both once used", "kit": "the same page code",
         "kit_look": "a page that looks the same", "batch": "registered together at one registrar"}  # fmt: skip
SHORT = {"ip": "server", "certificate": "certificate", "tracking_id": "analytics id", "registrant": "registrant", "favicon": "favicon", "registrar": "registrar",
         "nameserver": "name server", "shared_ip": "shared server", "cf_ns_pair": "Cloudflare account", "dns_token": "DNS token", "tds_campaign": "traffic campaign",
         "data_sink": "data goes to", "shared_tds": "traffic campaign (shared)", "affiliate_id": "affiliate", "redirector": "redirects via",
         "past_ip": "old server", "kit": "page code", "kit_look": "page look", "batch": "registered together"}  # fmt: skip
NODE_TYPE = {"ip": "ip", "certificate": "certificate", "tracking_id": "tracking_id", "registrant": "registrant",
             "favicon": "hostname", "registrar": "hostname", "nameserver": "hostname", "shared_ip": "ip", "shared_tds": "tracking_id", "cf_ns_pair": "registrant",
             "dns_token": "registrant", "tds_campaign": "tracking_id", "data_sink": "tracking_id", "affiliate_id": "tracking_id", "redirector": "hostname",
             "past_ip": "ip", "kit": "hostname", "kit_look": "hostname", "batch": "hostname"}  # fmt: skip
EDGE_TYPE = {"ip": "passive_dns", "certificate": "cert", "tracking_id": "tracking_id", "registrant": "reverse_whois",
             "favicon": "favicon", "registrar": "reverse_ns", "nameserver": "reverse_ns", "shared_ip": "passive_dns", "shared_tds": "favicon",
             "cf_ns_pair": "reverse_ns", "dns_token": "reverse_whois", "tds_campaign": "favicon", "data_sink": "tracking_id", "affiliate_id": "tracking_id",
             "redirector": "favicon", "past_ip": "passive_dns", "kit": "cert", "kit_look": "cert", "batch": "reverse_ns"}  # fmt: skip
_CAMPAIGN_KIND = {NodeType.IP: "ip", NodeType.CERTIFICATE: "certificate", NodeType.TRACKING_ID: "tracking_id", NodeType.REGISTRANT: "registrant"}


SHARED_TDS_SCANS = 200  # a campaign number that urlscan.io has seen on this many pages belongs to an affiliate network, not to one operator
SHARED_IP_SITES = 50  # a server with more sites than this is shared hosting: sitting on it says little
BATCH_DAYS = 3  # domains of one registrar registered within this many days of each other came out of one purchase
PHASH_BITS = 6  # screenshots whose perceptual hashes differ in at most this many bits look the same
_TOKEN = re.compile(r"^(google-site-verification|facebook-domain-verification|apple-domain-verification|MS|ms|atlassian-domain-verification|"
                    r"stripe-verification|docusign|zoho-verification|yandex-verification)[=:]\s*(\S{8,})", re.I)
_TDS_ID = re.compile(r"^/([A-Za-z0-9_-]{1,12})/(\d{5,})")  # /go/3115960: the campaign number of a traffic-distribution link
_SINK = re.compile(r"posts to another host: (\S+)")
_AFFILIATE = redirects_mod.AFFILIATE
# hosts that are not a redirector of one operator: public short-link services and the big sites a typo domain sometimes bounces to
PUBLIC_REDIRECT = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly", "buff.ly", "is.gd", "rebrand.ly", "cutt.ly", "lnkd.in", "google.com", "facebook.com",
                   "youtube.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "wikipedia.org", "microsoft.com", "apple.com", "amazon.com"}  # fmt: skip
PARKING = {"godaddy.com", "dan.com", "sedo.com", "afternic.com", "bodis.com", "parkingcrew.net", "hugedomains.com", "undeveloped.com",
           "sav.com", "namebright.com", "above.com", "domainmarket.com", "squadhelp.com", "atom.com"}  # fmt: skip


def _tds_campaign(url: str, own: str) -> str | None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    m = _TDS_ID.match(parts.path or "")
    return f"{host}{m.group(0)}" if m and host and host != own else None


_on = redirects_mod.on
_registrable = redirects_mod.registrable
_affiliate_ids = redirects_mod.affiliate_ids


def _hamming(a: str, b: str) -> int:
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return 64


def map_excludes(session: Session, workspace_id: uuid.UUID) -> dict[str, Any]:
    """What the analyst decided is no evidence of a link: whole kinds (every Cloudflare account, every registrar …) and single things (one
    registrar, one name server). Kept per workspace; the sites are not touched, only the lines between them."""
    from brandwatch.db.models import Workspace

    ws = session.get(Workspace, workspace_id)
    stored = ((ws.settings or {}).get("map_excludes") or {}) if ws else {}
    return {"kinds": [k for k in stored.get("kinds", []) if k in LABEL],
            "items": [{"kind": i["kind"], "value": str(i["value"])} for i in stored.get("items", []) if i.get("kind") in LABEL and i.get("value")]}  # fmt: skip


def set_map_exclude(session: Session, workspace_id: uuid.UUID, kind: str, value: str | None, exclude: bool) -> dict[str, Any]:
    """Exclude (or bring back) a whole kind of link, or one value of a kind."""
    from brandwatch.db.models import Workspace

    if kind not in LABEL:
        raise ValueError("unknown kind of link")
    cur = map_excludes(session, workspace_id)
    if value is None:
        kinds = [k for k in cur["kinds"] if k != kind] + ([kind] if exclude else [])
        cur["kinds"] = sorted(set(kinds))
    else:
        items = [i for i in cur["items"] if not (i["kind"] == kind and i["value"].lower() == value.lower())]
        cur["items"] = items + ([{"kind": kind, "value": value}] if exclude else [])
    ws = session.get(Workspace, workspace_id)
    ws.settings = {**(ws.settings or {}), "map_excludes": cur}
    session.flush()
    return cur


class _Assets:
    def __init__(self) -> None:
        self.by_key: dict[tuple[str, str], dict[str, Any]] = {}

    def add(self, kind: str, value: str | None, host: str, how: str = "evidence", cls: str | None = None, org: str | None = None) -> None:
        value = (value or "").strip()
        if not value:
            return
        key = (kind, value.lower() if kind in ("registrant", "registrar", "nameserver", "redirector", "affiliate_id") else value)
        row = self.by_key.setdefault(key, {"kind": kind, "value": value, "sites": [], "how": set(), "cls": cls, "org": org})
        if host not in row["sites"]:
            row["sites"].append(host)
        row["how"].add(how)


def _find(parent: dict[str, str], x: str) -> str:
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


def weight(a: dict[str, Any]) -> float:
    """How likely two sites that share this asset are one operation. A server counts for less on a big cloud, a redirect host for less
    once it is known to be everywhere."""
    if a["kind"] == "ip":
        return WEIGHT["ip"] if a.get("cls") == "hoster" else 0.5  # a big cloud, or a network nobody has looked up, says less than a small hoster
    if a["kind"] == "redirector" and a.get("common"):
        return WEIGHT["registrar"]
    return WEIGHT[a["kind"]]


def level(w: float) -> str:
    return "solid" if w >= JOIN else "possible" if w >= POSSIBLE else "weak"


def pair_confidence(kinds: dict[str, float]) -> float:
    """Independent kinds of evidence add up: 1 - Π(1 - w). The same kind twice is one kind."""
    p = 1.0
    for w in kinds.values():
        p *= 1.0 - w
    return 1.0 - p


def _clusters(items: dict[str, str], near: Any) -> list[list[str]]:
    """Single-linkage clusters of hosts whose value is ``near`` the other's (the perceptual hash of a screenshot)."""
    parent = {h: h for h in items}
    for a, b in itertools.combinations(sorted(items), 2):
        if near(items[a], items[b]):
            parent[_find(parent, a)] = _find(parent, b)
    out: dict[str, list[str]] = {}
    for h in items:
        out.setdefault(_find(parent, h), []).append(h)
    return [sorted(v) for v in out.values() if len(v) > 1]


def _day(v: Any):
    from datetime import date

    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def _views(sites: dict[str, dict[str, Any]], linked: list[dict[str, Any]], shared: list[dict[str, Any]], pair_conf: dict[tuple[str, str], float],
           pair: dict[tuple[str, str], dict[str, float]], gidx: dict[str, int]) -> dict[str, Any]:
    """What the alternative views need (matrix, arcs, flow, pivot): every site in order of operation, every pair of sites with its confidence, every shared thing
    with its sites, and one row per site for the flow (registrar -> hosting -> redirect host -> operation)."""
    order = sorted(sites, key=lambda h: (gidx.get(h, 0) == 0, gidx.get(h, 0), h))
    names = {g["index"]: g["name"] for g in linked}
    pairs = [{"a": x, "b": y, "conf": round(c, 2), "kinds": sorted(pair.get((x, y), {}), key=ORDER.index)} for (x, y), c in sorted(pair_conf.items()) if c >= POSSIBLE]
    pivot: dict[str, Any] = {}
    for kind in ORDER:
        rows = sorted(({"value": a["value"], "sites": sorted(a["sites"]), "weight": a["weight"], "level": a["level"], "network": a.get("org") if kind in ("ip", "past_ip", "shared_ip") else None,
                        "class": a.get("cls")} for a in shared if a["kind"] == kind), key=lambda r: (-len(r["sites"]), r["value"]))  # fmt: skip
        if rows:
            pivot[kind] = {"label": LABEL[kind], "short": SHORT[kind], "rows": rows}
    flow = []
    for h in order:
        s = sites[h]
        real = [x for x in s["hosting"] if x["cls"] != "cdn"]
        host = (real[0]["org"] or "unknown network") if real else ("behind a CDN" if s["behind_cloudflare"] or s["hosting"] else "no server seen")
        flow.append({"host": h, "vals": [s["registrar"] or "unknown registrar", host, s["redirectors"][0] if s["redirectors"] else "no redirect host",
                                         names.get(gidx.get(h, 0)) or "No strong link"], "op": gidx.get(h, 0)})  # fmt: skip
    return {"order": order, "names": {str(k): v for k, v in names.items()}, "pairs": pairs, "pivot": pivot, "flow": {"columns": ["Registrar", "Hosting", "Redirect via", "Operation"], "rows": flow},
            "sites": [{"host": h, "op": gidx.get(h, 0), "severity": sites[h]["severity"], "id": sites[h]["id"]} for h in order]}


def _swimlane(linked: list[dict[str, Any]], alone: list[str], sites: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """When each operation's domains were registered, on one time axis: a row per operation, a dot per domain, a ring around the dots
    bought within a few days of another (a wave)."""
    rows: list[dict[str, Any]] = []
    for label, index, hosts in [*((g["name"], g["index"], g["sites"]) for g in linked), ("No strong link", 0, alone)]:
        dots = sorted(({"date": d.isoformat(), "host": h} for h in hosts if (d := _day(sites[h]["registered"])) and d.year >= 1995), key=lambda x: x["date"])
        days = [_day(x["date"]) for x in dots]
        for i, x in enumerate(dots):
            x["wave"] = any(j != i and abs((days[j] - days[i]).days) <= BATCH_DAYS for j in range(len(dots)))
        if dots:
            rows.append({"label": label, "index": index, "dots": dots})
    every = [_day(x["date"]) for r in rows for x in r["dots"]]
    if not every:
        return {"rows": [], "ticks": []}
    lo, hi = min(every), max(every)
    span = max((hi - lo).days, 1)
    for r in rows:
        for x in r["dots"]:
            x["x"] = round(((_day(x["date"]) - lo).days / span) * 100, 2)
    years = range(lo.year + (1 if (lo.month, lo.day) != (1, 1) else 0), hi.year + 1)
    from datetime import date

    ticks = [{"label": str(y), "x": round(((date(y, 1, 1) - lo).days / span) * 100, 2)} for y in years]
    step = max(1, len(ticks) // 8)
    return {"rows": rows, "ticks": ticks[::step], "from": lo.isoformat(), "to": hi.isoformat()}


def build_all_map(session: Session, workspace_id: uuid.UUID, findings: list[Finding]) -> dict[str, Any]:
    assets = _Assets()
    sites: dict[str, dict[str, Any]] = {}
    social: list[dict[str, Any]] = []  # a Facebook page or a profile is not infrastructure: it has its own lane
    pending: list[str] = []
    ip_load: dict[str, int] = {}  # how many other sites each IP carries (VirusTotal), when an investigation knows
    org_cache: dict[str, str | None] = {}
    own_cache: dict[uuid.UUID, set[str]] = {}
    kit_html: dict[str, str] = {}
    kit_look: dict[str, str] = {}
    for f in findings:
        cand = session.get(Candidate, f.candidate_id)
        brand = session.get(Brand, f.brand_id)
        host = cand.hostname
        if "/" in host:  # a social profile is stored as facebook.com/<id>
            social.append({"id": str(f.id), "host": host, "severity": f.severity.value, "brand": brand.name if brand else None})
            continue
        if f.brand_id not in own_cache:  # the brand's own domains (and its family's, partners', CDNs'): a link to them is not a link between suspects
            own_cache[f.brand_id] = {d.lower() for d in whitelist_domains(session, f.brand_id)}
        own = own_cache[f.brand_id]
        sig = (f.current_score.signals if f.current_score else None) or {}
        sites[host] = {"id": str(f.id), "host": host, "severity": f.severity.value, "brand": brand.name if brand else None,
                       "mapped": bool(f.campaign_id), "investigated": False, "registered": None,
                       "signals": sorted(k for k in sig if not k.startswith("_")),
                       "tld": host.rsplit(".", 1)[-1], "country": None,
                       "behind_cloudflare": False, "brand_key": None, "registrar": None, "nameservers": [], "hosting": [], "issuer": None,
                       "affiliate": [], "redirectors": [], "forwards_to_brand": False, "parked": False, "sink": None, "final": None}  # fmt: skip
        S = sites[host]
        facts = inv._seed_facts(session, f)
        who = session.get(WhoisObservation, facts["evidence"]["whois"]) if facts["evidence"].get("whois") else None
        S["registered"] = who.registered_at.isoformat() if who and who.registered_at else None
        S["behind_cloudflare"] = hosting.ip_class(session, workspace_id, facts["ips"][0], org_cache)[0] == "cdn" if facts["ips"] else False
        # the redirect chain: a campaign number (qemow.com/go/3115960), an affiliate id on the brand's own site, a host that only forwards
        chain: list[str] = []
        for ev in session.scalars(sa.select(Evidence).where(Evidence.candidate_id == cand.id, Evidence.type == EvidenceType.HTTP,
                                                            Evidence.source_type == "http")).all():
            meta = ev.response_meta or {}
            for hop in [*(meta.get("redirect_chain") or []), meta.get("final_url") or ""]:
                if hop and str(hop) not in chain:
                    chain.append(str(hop))
        site_reg = _registrable(host)
        S["final"] = next(((urlsplit(h).hostname or "").lower() for h in reversed(chain) if h and urlsplit(h).hostname), None)  # where the visitor ends up
        for hop in chain:
            tds = _tds_campaign(hop, host)
            if tds:
                assets.add("tds_campaign", tds, host)
            hh = (urlsplit(hop).hostname or "").lower()
            if not hh or _registrable(hh) == site_reg:
                continue
            reg = _registrable(hh)
            if _on(hh, own):
                S["forwards_to_brand"] = True
            elif ops_mod.PARKING.search(hh):
                S["parked"] = True
            elif reg not in PUBLIC_REDIRECT and reg not in S["redirectors"]:
                S["redirectors"].append(reg)
                assets.add("redirector", reg, host)
        S["affiliate"] = _affiliate_ids(chain, own, host)
        for aff in S["affiliate"]:
            assets.add("affiliate_id", aff, host)
        # where a credential / payment form sends what the victim types
        cur = f.current_score
        sink = _SINK.search(str(((cur.signals or {}).get("_details") or {}).get("external_form_action") or "")) if cur else None
        if sink:
            sink_host = (urlsplit(sink.group(1)).hostname or sink.group(1)).lower()
            if sink_host and sink_host != host:
                assets.add("data_sink", sink_host, host)
                S["sink"] = sink_host
        for ip in facts["ips"]:
            cls, org = hosting.ip_class(session, workspace_id, ip, org_cache)
            S["hosting"].append({"ip": ip, "cls": cls, "org": org})
            if cls != "cdn":  # a CDN address carries thousands of unrelated sites
                assets.add("ip", ip, host, cls=cls, org=org)
        assets.add("certificate", facts["cert_fp"], host)
        for tid in facts["tracking_ids"]:
            assets.add("tracking_id", tid, host)
        for who in (facts["registrant_email"], facts["registrant_org"]):
            if who and not is_private(who):
                assets.add("registrant", str(who), host)
        if facts["favicon_mmh3"] is not None:
            assets.add("favicon", str(facts["favicon_mmh3"]), host)
        if not (sig.get("_challenge") or sig.get("_no_picture")):  # a challenge page or a blank page is the same for everybody: no kit to compare
            snap = session.get(HtmlSnapshot, facts["evidence"]["html"]) if facts["evidence"].get("html") else None
            if snap is not None and snap.dom_hash:
                kit_html[host] = snap.dom_hash
            shot = session.scalars(sa.select(Screenshot).join(Evidence, Evidence.id == Screenshot.evidence_id)
                                   .where(Evidence.candidate_id == cand.id).order_by(Evidence.observed_at.desc())).first()  # fmt: skip
            if shot is not None and shot.phash:
                kit_look[host] = shot.phash
        # what the map of this site found (its pivot: servers, certificates, registrants, tracking IDs it shares with others)
        if f.campaign_id:
            camp = session.get(Campaign, f.campaign_id)
            for n in (session.scalars(sa.select(CampaignNode).where(CampaignNode.campaign_id == camp.id, CampaignNode.included.is_(True))).all() if camp else []):
                kind = _CAMPAIGN_KIND.get(n.type)
                if kind == "ip":
                    cls, org = hosting.ip_class(session, workspace_id, n.value, org_cache)
                    if cls != "cdn":
                        assets.add("ip", n.value, host, how="map", cls=cls, org=org)
                elif kind and not (kind == "registrant" and is_private(n.value)):
                    assets.add(kind, n.value, host, how="map")
        # what the investigation of the site and its network found
        v = intel_mod.intel_view(session, workspace_id, host)
        if v.get("fetched_at") is not None:
            S["investigated"] = True
            S["registered"] = S["registered"] or (str(v.get("creation_date"))[:10] if v.get("creation_date") else None)
            S["country"] = next((i.get("country_name") for i in v.get("ips") or [] if i.get("country_name") and not i.get("shared")), None)
            S["behind_cloudflare"] = S["behind_cloudflare"] or any(i.get("shared") for i in v.get("ips") or [])
            current = {h["ip"] for h in S["hosting"]}
            for ip in v.get("ips") or []:
                if ip.get("ip") and not ip.get("shared"):
                    cls, org = hosting.ip_class(session, workspace_id, ip["ip"], org_cache)
                    if cls != "cdn":
                        assets.add("ip", ip["ip"], host, how="investigation", cls=cls, org=org)
                        if ip["ip"] not in current:
                            S["hosting"].append({"ip": ip["ip"], "cls": cls, "org": org})
                    if ip.get("hosted_count"):
                        ip_load[ip["ip"]] = int(ip["hosted_count"])
            for r in (v.get("relations") or {}).get("resolutions") or []:  # where the name pointed before: a server both once used
                ip = r.get("ip")
                if ip and ip not in current:
                    cls, org = hosting.ip_class(session, workspace_id, ip, org_cache)
                    if cls != "cdn":
                        assets.add("past_ip", ip, host, how="investigation", cls=cls, org=org)
            S["registrar"] = v.get("registrar")
            assets.add("registrar", v.get("registrar"), host, how="investigation")
            S["issuer"] = ((v.get("certificate") or {}).get("issuer")) or None
            ns = sorted({str(r.get("value") or "").lower().rstrip(".") for r in (v.get("dns") or {}).get("records") or [] if r.get("type") == "NS"})
            cf = [n for n in ns if n.endswith(".ns.cloudflare.com")]
            S["nameservers"] = ns
            if cf:  # Cloudflare gives each account its own pair of name servers: the pair names the account
                assets.add("cf_ns_pair", " + ".join(cf), host, how="investigation")
            for n in ns:
                if n not in cf:
                    assets.add("nameserver", n, host, how="investigation")
            for rec in (v.get("dns") or {}).get("records") or []:
                tok = _TOKEN.match(str(rec.get("value") or "").strip().strip('"')) if rec.get("type") == "TXT" else None
                if tok:
                    assets.add("dns_token", f"{tok.group(1).lower()}={tok.group(2)}", host, how="investigation")
        else:
            pending.append(host)

    # the same page code, a page that looks the same, domains bought together
    by_hash: dict[str, list[str]] = {}
    for h, d in kit_html.items():
        by_hash.setdefault(d, []).append(h)
    for d, hs in by_hash.items():
        for h in hs if len(hs) > 1 else []:
            assets.add("kit", f"page {d[:10]}", h)
    for cluster in _clusters(kit_look, lambda a, b: _hamming(a, b) <= PHASH_BITS):
        for h in cluster:
            assets.add("kit_look", f"screenshot {min(kit_look[x] for x in cluster)[:10]}", h)
    by_reg: dict[str, list[tuple[Any, str]]] = {}
    for h, s in sites.items():
        d = _day(s["registered"])
        if s["registrar"] and d:
            by_reg.setdefault(str(s["registrar"]).lower(), []).append((d, h))
    for rows in by_reg.values():
        rows.sort()
        run = [rows[0]]
        for item in [*rows[1:], None]:
            if item is not None and (item[0] - run[-1][0]).days <= BATCH_DAYS:
                run.append(item)
                continue
            if len(run) > 1:
                label = f"{sites[run[0][1]]['registrar']} · {run[0][0].isoformat()}" + (f" → {run[-1][0].isoformat()}" if run[-1][0] != run[0][0] else "")
                for _d, h in run:
                    assets.add("batch", label, h)
            run = [item] if item is not None else []

    for key in [k for k, a in assets.by_key.items() if a["kind"] == "past_ip" and ip_load.get(a["value"], 0) > SHARED_IP_SITES]:
        del assets.by_key[key]  # an old address that carries hundreds of sites is shared hosting
    for a in assets.by_key.values():  # an IP that carries a lot of other sites is shared hosting: sitting on it proves little
        if a["kind"] == "ip" and ip_load.get(a["value"], 0) > SHARED_IP_SITES:
            a["kind"] = "shared_ip"
            a["value"] = f"{a['value']} ({ip_load[a['value']]} sites)"
        if a["kind"] == "tds_campaign":  # once "search for more" has shown how many unrelated sites use the number, it stops being evidence
            seen = reverse_mod.cached(session, workspace_id, "tds_campaign", a["value"])
            if seen and int(seen.get("total") or 0) > SHARED_TDS_SCANS:
                a["kind"] = "shared_tds"
        if a["kind"] == "redirector":  # the same for a host that forwards: when it is everywhere it ties nobody
            seen = reverse_mod.cached(session, workspace_id, "redirector", a["value"])
            a["common"] = bool(seen and int(seen.get("total") or 0) > SHARED_TDS_SCANS)
    shared = [a for a in assets.by_key.values() if len(a["sites"]) > 1]
    for a in shared:
        a["weight"] = weight(a)
        a["level"] = level(a["weight"])
    ex = map_excludes(session, workspace_id)
    present = Counter(a["kind"] for a in shared)  # every kind that ties two sites, whether it is excluded or not: the filter chips
    skip = {(i["kind"], i["value"].lower()) for i in ex["items"]}
    gone = [a for a in shared if a["kind"] in ex["kinds"] or (a["kind"], a["value"].lower()) in skip]
    shared = [a for a in shared if a not in gone]
    strong = [a for a in shared if a["level"] == "solid"]
    possible = [a for a in shared if a["level"] == "possible"]
    weak = [a for a in shared if a["level"] == "weak"]

    # which sites belong together: the kinds a pair shares add up, and a pair at JOIN or above is one operation
    pair: dict[tuple[str, str], dict[str, float]] = {}
    for a in shared:
        if a["kind"] in WEAK:
            continue  # a registrar, a name server or a favicon never ties two sites, however many of them there are
        for x, y in itertools.combinations(sorted(a["sites"]), 2):
            d = pair.setdefault((x, y), {})
            d[a["kind"]] = max(d.get(a["kind"], 0.0), a["weight"])
    pair_conf = {k: pair_confidence(d) for k, d in pair.items()}
    # two sites are one operation on what is at least a hint by itself (0.5 and up): purchase days and look-alike pictures only support it, they never decide
    joined = {k for k, d in pair.items() if pair_confidence({kd: w for kd, w in d.items() if w >= 0.5}) >= JOIN}
    parent = {h: h for h in sites}
    for x, y in joined:
        parent[_find(parent, x)] = _find(parent, y)
    comps: dict[str, list[str]] = {}
    for h in sites:
        comps.setdefault(_find(parent, h), []).append(h)
    groups = []
    for members in comps.values():
        ms = set(members)
        ties = [a for a in shared if a["kind"] not in WEAK and len(set(a["sites"]) & ms) > 1]
        also = [a for a in shared if a["kind"] in WEAK and len(set(a["sites"]) & ms) > 1]
        best = [max([c for (x, y), c in pair_conf.items() if (x, y) in joined and h in (x, y) and x in ms and y in ms] or [0.0]) for h in members]
        confidence = round(min(best), 2) if len(members) > 1 else 0.0
        pat = pattern_mod.describe([sites[h] for h in members], [{"kind": a["kind"]} for a in ties if a["level"] == "solid"], None)

        def row(a: dict[str, Any], ms: set[str] = ms) -> dict[str, Any]:
            return {"kind": a["kind"], "label": LABEL[a["kind"]], "short": SHORT[a["kind"]], "value": a["value"], "sites": sorted(set(a["sites"]) & ms), "weight": a["weight"],
                    "level": a["level"], "network": (a.get("org") or None) if a["kind"] in ("ip", "past_ip", "shared_ip") else None, "class": a.get("cls")}  # fmt: skip

        # who is with whom: sites that share exactly the same things form a cluster (many links with the same sites are ONE line to read)
        by_set: dict[tuple[str, ...], list[dict[str, Any]]] = {}
        for a in ties:
            by_set.setdefault(tuple(sorted(set(a["sites"]) & ms)), []).append(a)
        clusters = []
        for key, items in by_set.items():
            kinds: dict[str, list[dict[str, Any]]] = {}
            for a in sorted(items, key=lambda x: (-x["weight"], x["value"])):
                kinds.setdefault(a["kind"], []).append(row(a))
            by_kind = sorted(({"kind": k, "label": SHORT[k], "weight": v[0]["weight"], "level": v[0]["level"], "vals": [x["value"] for x in v],
                               "network": next((x["network"] for x in v if x.get("network")), None)} for k, v in kinds.items()), key=lambda x: (-x["weight"], ORDER.index(x["kind"])))  # fmt: skip
            clusters.append({"sites": list(key), "strength": max(a["weight"] for a in items), "by_kind": by_kind})
        clusters.sort(key=lambda c: (-len(c["sites"]), -c["strength"], c["sites"][0]))
        hs = sorted(members)  # who against whom: for every pair of sites, how sure we are that they are one operation, and by what
        grid = {"hosts": hs, "cells": [[None if x == y else {"conf": round(pair_conf.get(tuple(sorted((x, y))), 0.0), 2),
                                                             "kinds": sorted(pair.get(tuple(sorted((x, y))), {}), key=ORDER.index)} for y in hs] for x in hs]}  # fmt: skip
        groups.append({"sites": sorted(members), "size": len(members), "pattern": pat, "confidence": confidence, "clusters": clusters, "grid": grid,
                       "links": sorted((row(a) for a in ties), key=lambda x: (-x["weight"], ORDER.index(x["kind"]), x["value"])),
                       "also": sorted((row(a) for a in also), key=lambda x: (ORDER.index(x["kind"]), x["value"]))})  # fmt: skip
    for g in groups:  # a link that can be searched backwards (a traffic campaign, a data sink, an affiliate id): what an earlier search found
        for lk in g["links"]:
            if lk["kind"] in reverse_mod.SEARCHABLE:
                lk["searchable"] = True
                lk["found"] = reverse_mod.cached(session, workspace_id, lk["kind"], lk["value"])
    linked = sorted((g for g in groups if g["size"] > 1), key=lambda g: (-g["size"], g["sites"][0]))
    alone = sorted(g["sites"][0] for g in groups if g["size"] == 1)
    for i, g in enumerate(linked, 1):  # what each one does, how to stop it, where to hunt for more
        g["index"] = i
        ops_mod.enrich(g, sites)
    alone_info = {h: ops_mod.behaviour([sites[h]], []) for h in alone}

    # the graph: every site, and the things that connect more than one of them (solid = proof, dashed = a hint, faint = common)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    site_id = {h: f"site:{h}" for h in sites}
    gidx = {h: g["index"] for g in linked for h in g["sites"]}  # the number of the operation a site is in; 0 = none
    gname = {g["index"]: g["name"] for g in linked}
    for h, s in sites.items():
        does = next((g["behaviour"] for g in linked if h in g["sites"]), None) or alone_info.get(h) or {}
        nodes.append({"id": site_id[h], "type": "domain", "kind": "site", "value": h, "label": h, "included": True, "groups": [gidx.get(h, 0)], "level": "solid",
                      "triage_reason": f"confirmed phishing · {s['brand'] or ''}",
                      "detail": {"does": does.get("label"), "operation": gname.get(gidx.get(h, 0)), "registered": s["registered"], "registrar": s["registrar"],
                                 "hosting": sorted({f"{x['org']} ({x['cls']})" if x["org"] else "unknown network" for x in s["hosting"] if x["cls"] != "cdn"})[:3],
                                 "forwards_to_brand": s["forwards_to_brand"], "affiliate": s["affiliate"], "redirectors": s["redirectors"]},
                      "attrs": {}, "finding": {"id": s["id"], "severity": s["severity"], "state": "confirmed"}})  # fmt: skip
    for a in strong + possible + weak:
        aid = f"{a['kind']}:{a['value']}"
        note = {"solid": "", "possible": " (a hint: not enough alone)", "weak": " (common, not proof of a link)"}[a["level"]]
        nodes.append({"id": aid, "type": NODE_TYPE[a["kind"]], "kind": a["kind"], "value": a["value"], "label": f"{SHORT[a['kind']]}: {a['value']}",
                      "included": a["level"] == "solid", "level": a["level"], "weight": a["weight"],
                      "groups": sorted({gidx.get(h, 0) for h in a["sites"]}),
                      "triage_reason": f"{LABEL[a['kind']]}: {len(a['sites'])} confirmed sites{note}",
                      "attrs": {}, "finding": None})  # fmt: skip
        for h in a["sites"]:
            edges.append({"id": f"{aid}|{h}", "source": site_id[h], "target": aid, "type": EDGE_TYPE[a["kind"]], "kind": a["kind"], "weight": a["weight"],
                          "level": a["level"], "source_value": h, "target_value": a["value"], "evidence_id": None})  # fmt: skip

    in_groups = sum(g["size"] for g in linked)
    if not sites:
        headline = "No confirmed phishing sites yet."
    elif not linked:
        headline = (f"{len(sites)} confirmed site{'s' if len(sites) != 1 else ''}, and nothing strong ties any two of them together: no shared server, "
                    "certificate, analytics ID or registrant" + (f" (only {len(weak) + len(possible)} weaker thing(s) in common)" if weak or possible else "") + ".")
    else:
        big = linked[0]
        what = ", ".join(sorted({x["label"] for x in big["links"] if x["level"] == "solid"} or {x["label"] for x in big["links"]}))
        headline = (f"{in_groups} of {len(sites)} confirmed sites are tied together in {len(linked)} group{'s' if len(linked) != 1 else ''}. "
                    f"The largest has {big['size']} sites that share {what}: {', '.join(big['sites'][:6])}{' …' if big['size'] > 6 else ''}."
                    + (f" It spans {len(big['brands'])} brands ({', '.join(b['name'] for b in big['brands'])}): the same attackers, not one brand's problem." if len(big.get("brands") or []) > 1 else "")
                    + (f" {len(alone)} site{'s have' if len(alone) != 1 else ' has'} no strong link to the others." if alone else ""))
    for h, s in sites.items():
        s["op"] = gidx.get(h, 0)
    return {
        "views": _views(sites, linked, shared, pair_conf, pair, gidx),
        "swimlane": _swimlane(linked, alone, sites),
        "headline": headline, "sites": list(sites.values()), "groups": linked, "operations": linked, "alone": alone, "alone_info": alone_info, "social": social,
        "overall": pattern_mod.describe(list(sites.values()), [{"kind": x["kind"]} for g in linked for x in g["links"] if x["level"] == "solid"]) if len(sites) > 1 else None,
        "stats": {"sites": len(sites), "linked_sites": in_groups, "groups": len(linked), "operations": len(linked), "alone": len(alone), "social": len(social),
                  "strong_links": len(strong), "weak_links": len(weak) + len(possible), "not_investigated": len(pending),
                  "not_mapped": sum(1 for s in sites.values() if not s["mapped"]),
                  "brands": len({s["brand"] for s in sites.values() if s["brand"]}), "cross_brand_groups": sum(1 for g in linked if len(g.get("brands") or []) > 1),
                  "ends_on_brand": sum(1 for s in sites.values() if s["forwards_to_brand"]),
                  "ends_on_brand_unrated": sum(1 for s in sites.values() if s["forwards_to_brand"] and not any(x in s["signals"] for x in ("affiliate_redirect", "redirect_via_third_party")))},
        "nodes": nodes, "edges": edges, "pending": pending,
        "kinds": [{"kind": k, "label": LABEL[k], "count": present[k], "strong": k in STRONG, "strength": "strong" if k in STRONG else "hint" if k in MEDIUM else "weak",
                   "excluded": k in ex["kinds"]}
                  for k in ORDER if present.get(k) or k in ex["kinds"]],
        "excluded": [{"kind": a["kind"], "label": LABEL[a["kind"]], "value": a["value"], "sites": sorted(a["sites"]), "by": "kind" if a["kind"] in ex["kinds"] else "item"}
                     for a in sorted(gone, key=lambda x: (x["kind"], x["value"]))],
    }  # fmt: skip
