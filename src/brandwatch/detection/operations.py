"""An operation: a group of confirmed sites that belong to one attacker, with what they do and how to stop them.

``all_map`` says WHICH sites are tied together and how sure it is. This turns each group into an *operation card*: what the attacker is
doing (steals the brand's affiliate commission, harvests passwords, forwards visitors through a scam funnel, sells parked domains,
or only copies the brand), the identifier that names the operation (an affiliate id, a redirect host), the tools the attacker uses
(registrar, hosting), when the domains were bought, and the shortest way to stop the whole operation: usually one report to one party
that covers every domain. Everything is a rule over facts BrandWatch already stored, and every conclusion says why.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

# a host that only sells or parks a domain
PARKING = re.compile(r"(^|\.)(forsale\.godaddy\.com|dan\.com|sedo\.com|afternic\.com|bodis\.com|parkingcrew\.net|hugedomains\.com|undeveloped\.com|"
                     r"sav\.com|namebright\.com|domainmarket\.com|squadhelp\.com|atom\.com)$", re.I)

KINDS = {
    "malware_lure": ("Malware lure", "☠", "makes the visitor run a command"),
    "credential_phishing": ("Phishing kit", "⚿", "collects passwords or card details"),
    "affiliate_fraud": ("Affiliate fraud", "$", "sends visitors to the real site with an affiliate id, to collect the commission"),
    "traffic_funnel": ("Traffic funnel", "↪", "forwards visitors through another host"),
    "parked": ("Parked domains", "P", "is parked or for sale"),
    "clone": ("Brand clone", "◐", "copies the brand's look"),
    "lookalike": ("Look-alike domains", "Aa", "has a name that imitates the brand"),
}
FORMS = ("credential_form", "payment_form", "seed_phrase_field", "external_form_action")


def _n(c: int, word: str) -> str:
    return f"{c} {word}{'' if c == 1 else 's'}"


def behaviour(members: list[dict[str, Any]], links: list[dict[str, Any]]) -> dict[str, Any]:
    """What this site (or group of sites) does, by the first rule that fits, with the facts it rests on."""
    n = len(members)

    def share(pred: Any) -> int:
        return sum(1 for s in members if pred(s))

    sig = lambda name: share(lambda s: name in (s.get("signals") or ()))  # noqa: E731
    kinds = {x["kind"] for x in links}
    # a page that ends on the brand's own site shows the brand's own login form: that is not a kit asking for a password
    kit_forms = share(lambda s: not s.get("forwards_to_brand") and any(x in (s.get("signals") or ()) for x in FORMS))
    why: list[str] = []
    if sig("clickfix_lure"):
        key = "malware_lure"
        why.append(f"{sig('clickfix_lure')}/{n} ask the visitor to run a command")
    elif kit_forms >= max(1, n // 2) or ("data_sink" in kinds and share(lambda s: not s.get("forwards_to_brand")) >= max(1, n // 3)):
        key = "credential_phishing"
        forms = [f"{c}/{n} {x.replace('_', ' ')}" for x in FORMS if (c := share(lambda s, x=x: not s.get("forwards_to_brand") and x in (s.get("signals") or ())))]
        why += forms or ["the stolen data is sent to the same place"]
    elif share(lambda s: s.get("affiliate") and s.get("forwards_to_brand")) >= max(1, (n + 1) // 2):
        key = "affiliate_fraud"
        ids = Counter(a for s in members for a in s.get("affiliate") or [])
        why.append(f"{share(lambda s: s.get('affiliate'))}/{n} forward to the brand's own site with " + ", ".join(f"?{a}" for a, _ in ids.most_common(2)))
        why.append("not phishing: nothing is stolen from the visitor, who ends on the real site; the abuse is the commission, and the redirect host that could send visitors elsewhere")
    elif share(lambda s: s.get("redirectors")) >= max(1, (n + 1) // 2) or "tds_campaign" in kinds:
        key = "traffic_funnel"
        reds = Counter(r for s in members for r in s.get("redirectors") or [])
        why.append(f"{share(lambda s: s.get('redirectors'))}/{n} are forwarded through " + (", ".join(r for r, _ in reds.most_common(2)) or "a traffic-distribution link"))
    elif share(lambda s: s.get("parked")) >= max(1, (n + 1) // 2):
        key = "parked"
        why.append(f"{share(lambda s: s.get('parked'))}/{n} end on a page that sells the domain")
    elif sig("looks_like_brand_ge_85") or sig("screenshot_similarity_ge_90") >= max(1, n // 2):
        key = "clone"
        why.append(f"{max(sig('looks_like_brand_ge_85'), sig('screenshot_similarity_ge_90'))}/{n} look like the brand")
    else:
        key = "lookalike"
        why.append("no form, redirect or copied page was recorded for them")
    label, icon, does = KINDS[key]
    return {"key": key, "label": label, "icon": icon, "does": does, "why": why}


def _name(key: str, members: list[dict[str, Any]], links: list[dict[str, Any]]) -> str:
    first = lambda kind: next((x["value"] for x in links if x["kind"] == kind), None)  # noqa: E731
    reds = Counter(r for s in members for r in s.get("redirectors") or [])
    if key == "affiliate_fraud":
        aff = first("affiliate_id") or Counter(a for s in members for a in s.get("affiliate") or []).most_common(1)[0][0]
        return f"Affiliate {aff}" + (f" · via {reds.most_common(1)[0][0]}" if reds else "")
    if key == "credential_phishing":
        sink = first("data_sink")
        return f"Phishing kit · sends data to {sink}" if sink else f"Phishing kit · {_n(len(members), 'site')}"
    if key == "malware_lure":
        return f"Malware lure · {_n(len(members), 'site')}"
    if key == "traffic_funnel":
        return f"Traffic funnel · {first('tds_campaign') or (reds.most_common(1)[0][0] if reds else _n(len(members), 'site'))}"
    if key == "parked":
        return f"Parked domains · {_n(len(members), 'site')}"
    regs = Counter(s["registrar"] for s in members if s.get("registrar"))
    where = f" · {regs.most_common(1)[0][0]}" if regs else ""
    return ("Brand clones" if key == "clone" else "Look-alike domains") + where


def _count(values: list[str | None]) -> list[dict[str, Any]]:
    return [{"name": k, "count": c} for k, c in Counter(v for v in values if v).most_common()]


def enrich(group: dict[str, Any], sites: dict[str, dict[str, Any]]) -> None:
    """Add to a group of ``all_map``: what the operation is, its toolkit, its waves, how to stop it, and the evidence per site."""
    members = [sites[h] for h in group["sites"]]
    links = [x for x in group["links"]]
    b = behaviour(members, links)
    n = len(members)
    conf = group.get("confidence") or 0.0
    group["behaviour"] = b
    brands = Counter(s.get("brand") for s in members if s.get("brand"))
    group["brands"] = [{"name": k, "count": c} for k, c in brands.most_common()]  # one group of attackers can target several brands
    group["name"] = _name(b["key"], members, links)
    per_site = Counter(behaviour([s], [])["key"] for s in members)  # one group can do two things: forward visitors for a commission AND run phishing kits
    mix = [k for k, c in per_site.most_common() if c >= 2]
    group["mix"] = [{"key": k, "label": KINDS[k][0], "count": per_site[k]} for k in mix] if len(mix) >= 2 else []
    if group["mix"]:
        group["name"] = " + ".join(x["label"] for x in group["mix"][:2]) + (f" · {len(brands)} brands" if len(brands) > 1 else f" · {group['name'].split(' · ', 1)[-1]}")
    group["level"] = "certain" if conf >= 0.9 else "likely"
    group["toolkit"] = {
        "registrars": _count([s.get("registrar") for s in members]),
        "hosting": _count([o for s in members for o in {f"{h['org']} ({h['cls']})" if h["org"] else "unknown network" for h in s.get("hosting") or [] if h["cls"] != "cdn"}]),
        "nameservers": _count([ns for s in members for ns in s.get("nameservers") or []]),
        "redirectors": _count([r for s in members for r in s.get("redirectors") or []]),
        "issuers": _count([s.get("issuer") for s in members]),
    }
    fact = group["pattern"]["facts"][0] if group["pattern"]["facts"] else ""
    who = f"Each of the {n} domains" if n > 1 else "This domain"
    across = (f"One group of attackers, {len(brands)} brands: " + ", ".join(f"{k} ×{c}" for k, c in brands.most_common()) + ". ") if len(brands) > 1 else ""
    mixed = ("It does more than one thing: " + ", ".join(f"{x['count']} × {x['label'].lower()}" for x in group["mix"]) + ". ") if group["mix"] else ""
    group["story"] = across + mixed + (f"{who} {b['does']}. " if not group["mix"] else "") + (fact[0].upper() + fact[1:] + ". " if fact else "") + f"{b['why'][0][0].upper()}{b['why'][0][1:]}."
    group["stop"] = _stop(group, members, links, b)
    group["matrix"] = {"kinds": [x for x in dict.fromkeys(x["kind"] for x in links)],
                       "rows": [{"host": s["host"], "cells": {k: [x["value"] for x in links if x["kind"] == k and s["host"] in x["sites"]] for k in dict.fromkeys(x["kind"] for x in links)}}
                                for s in members]}  # fmt: skip
    seen: dict[str, dict[str, Any]] = {}
    for x in sorted(links, key=lambda x: (-x["weight"], -len(x["sites"]))):  # the strongest tie of each kind: why we say these sites belong together
        seen.setdefault(x["kind"], {"kind": x["kind"], "label": x["label"], "short": x.get("short") or x["label"], "value": x["value"], "weight": x["weight"], "level": x["level"],
                                    "n": sum(1 for y in links if y["kind"] == x["kind"])})  # fmt: skip
    group["basis"] = list(seen.values())[:4]
    group["detail"] = _detail(group, members)
    group["report_md"] = _report(group, members)


# the order and the names of the "who shares what" sections: the servers come first
SECTIONS = (("ip", "Same server (address)"), ("past_ip", "Servers they once used"), ("certificate", "TLS certificates"), ("tracking_id", "Analytics / pixel IDs"),
            ("registrant", "Registrants"), ("affiliate_id", "Affiliate ids"), ("redirector", "Redirect hosts"), ("tds_campaign", "Traffic campaigns"),
            ("data_sink", "Where the stolen data goes"), ("cf_ns_pair", "Cloudflare accounts"), ("dns_token", "DNS verification tokens"), ("nameserver", "Name servers"),
            ("registrar", "Registrars"), ("batch", "Bought together"), ("kit", "Same page code"), ("kit_look", "Pages that look the same"), ("favicon", "Favicons"),
            ("shared_ip", "Servers shared with many unrelated sites"), ("shared_tds", "Traffic campaigns shared with many unrelated sites"))  # fmt: skip
_SHOW = {"credential_form", "payment_form", "seed_phrase_field", "external_form_action", "favicon_exact", "screenshot_similarity_ge_90", "looks_like_brand_ge_85",
         "cloaking_ua_based", "cloaking_ip_based", "device_gating", "bot_blocking", "clickfix_lure", "known_phishing", "vt_flagged", "redirect_from_suspect"}  # fmt: skip


def _detail(group: dict[str, Any], members: list[dict[str, Any]]) -> dict[str, Any]:
    """The full report of an operation: for every kind of thing the sites share, which sites share which one, and a line per site."""
    every = [*group["links"], *group["also"]]
    sections = []
    for kind, title in SECTIONS:
        rows = sorted((x for x in every if x["kind"] == kind), key=lambda x: (-len(x["sites"]), x["value"]))
        if rows:
            sections.append({"kind": kind, "title": title, "rows": [{"value": x["value"], "sites": x["sites"], "network": x.get("network"), "class": x.get("class"),
                                                                    "weight": x["weight"], "level": x["level"]} for x in rows]})  # fmt: skip
    per_site = []
    for s in members:
        hosting = s.get("hosting") or []
        per_site.append({"host": s["host"], "severity": s["severity"], "registered": s.get("registered"), "registrar": s.get("registrar"), "country": s.get("country"),
                         "ips": [h["ip"] for h in hosting if h["cls"] != "cdn"],
                         "hosting": sorted({f"{h['org']} ({h['cls']})" if h["org"] else "unknown network" for h in hosting if h["cls"] != "cdn"}),
                         "behind_cdn": any(h["cls"] == "cdn" for h in hosting) or bool(s.get("behind_cloudflare")), "nameservers": s.get("nameservers") or [],
                         "issuer": s.get("issuer"), "affiliate": s.get("affiliate") or [], "redirectors": s.get("redirectors") or [], "ends_on": s.get("final"),
                         "signals": [x for x in (s.get("signals") or []) if x in _SHOW][:6]})  # fmt: skip
    servers = next((sec for sec in sections if sec["kind"] == "ip"), None)
    on_one = max((len(r["sites"]) for r in servers["rows"]), default=0) if servers else 0
    summary = f"{on_one} of the {len(members)} sites are on one server" if on_one > 1 else "no two of these sites were seen on the same server"
    return {"sections": sections, "sites": per_site, "summary": summary}


def _stop(group: dict[str, Any], members: list[dict[str, Any]], links: list[dict[str, Any]], b: dict[str, Any]) -> list[dict[str, Any]]:
    """The shortest way to stop the whole operation: the party that one report reaches all of it through."""
    steps: list[dict[str, Any]] = []
    hosts = [s["host"] for s in members]
    brand = next((s["brand"] for s in members if s.get("brand")), "the brand")
    aff = [x for x in links if x["kind"] == "affiliate_id"]
    if aff:
        sites = sorted({h for x in aff for h in x["sites"]})
        steps.append({"title": f"Ask {brand}'s affiliate team to ban {aff[0]['value']}", "targets": sites,
                      "text": f"{_n(len(sites), 'domain')} send their visitors to the real site with {aff[0]['value']}. Banning that id and withholding its commission ends the reward for all of them at once."})
    sink = [x for x in links if x["kind"] == "data_sink"]
    if sink:
        steps.append({"title": f"Report {sink[0]['value']}, where the stolen data goes", "targets": sink[0]["sites"],
                      "text": "A single takedown of the collecting host stops every kit that posts to it."})
    reds = Counter(r for s in members for r in s.get("redirectors") or [])
    for r, c in reds.most_common(2):
        if c > 1:
            steps.append({"title": f"Report the redirect host {r}", "targets": [s["host"] for s in members if r in (s.get("redirectors") or [])],
                          "text": f"{_n(c, 'site')} forward visitors through {r}. Its abuse contact can close every short link."})
    for reg, c in Counter(s["registrar"] for s in members if s.get("registrar")).most_common(3):
        if c > 1:
            steps.append({"title": f"One bulk abuse report to {reg}", "targets": [s["host"] for s in members if s.get("registrar") == reg],
                          "text": f"{_n(c, 'domain')} are registered there. List them all in one report, with the screenshots from the evidence packages."})
    orgs = Counter(h["org"] for s in members for h in s.get("hosting") or [] if h["cls"] in ("hoster", "cloud") and h["org"])
    for org, c in orgs.most_common(2):
        if c > 1:
            steps.append({"title": f"Report the hosting provider {org}", "targets": [s["host"] for s in members if any(h["org"] == org for h in s.get("hosting") or [])],
                          "text": "The provider can disable the servers that host these pages."})
    if not steps:
        steps.append({"title": "Report each domain on its own", "targets": hosts, "text": "Nothing yet ties these sites to one party that a single report would reach."})
    return steps


def _report(group: dict[str, Any], members: list[dict[str, Any]]) -> str:
    """The operation as markdown, for a colleague or a takedown e-mail."""
    lines = [f"## {group['name']}", "", f"{group['behaviour']['label']} · {_n(len(members), 'site')} · {group['level']} ({round((group.get('confidence') or 0) * 100)}%)", "",
             group["story"], "", "**Domains**"]
    lines += [f"- {s['host']} ({s['severity']}" + (f", registered {s['registered']}" if s.get("registered") else "") + ")" for s in members]
    lines += ["", "**What ties them together**"]
    lines += [f"- {x['label']}: `{x['value']}` ({round(x['weight'] * 100)}%)" for x in group["links"] if x["kind"] not in ("ip", "past_ip")] or ["- (nothing strong)"]
    if any(x["kind"] in ("ip", "past_ip") for x in group["links"]):
        lines.append("- shared servers: listed below, address by address")
    lines += ["", "**How to stop it**"]
    for st in group["stop"]:
        lines.append(f"- {st['title']}: {st['text']}")
    det = group.get("detail") or {}
    lines += ["", f"### Who shares what ({det.get('summary', '')})"]
    for sec in det.get("sections", []):
        lines += ["", f"**{sec['title']}**"]
        for r in sec["rows"]:
            net = f" · {r['network']}" if r.get("network") else ""
            lines.append(f"- `{r['value']}`{net} · {_n(len(r['sites']), 'site')}: {', '.join(r['sites'])}")
    lines += ["", "### Site by site"]
    for s in det.get("sites", []):
        bits = [s["severity"]] + ([f"registered {s['registered']}"] if s.get("registered") else []) + ([f"registrar {s['registrar']}"] if s.get("registrar") else [])
        bits += [f"server {', '.join(s['ips'])}"] if s["ips"] else []
        bits += [f"hosting {', '.join(s['hosting'])}"] if s["hosting"] else []
        bits += ["behind a CDN"] if s["behind_cdn"] else []
        bits += [f"name servers {', '.join(s['nameservers'])}"] if s["nameservers"] else []
        bits += [f"affiliate {', '.join(s['affiliate'])}"] if s["affiliate"] else []
        bits += [f"via {', '.join(s['redirectors'])}"] if s["redirectors"] else []
        bits += [f"ends on {s['ends_on']}"] if s.get("ends_on") else []
        lines.append(f"- **{s['host']}**: " + "; ".join(bits))
    return "\n".join(lines)
