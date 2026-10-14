"""The pattern of an attack: what a group of confirmed sites have in common, in a few plain sentences and a timeline.

``all_map`` says WHICH sites are connected. This says WHAT the operation looks like: when the domains were registered (all at
once, or over months), how they are named (typos, another ending, the brand plus a word), where they are hosted, and how the kit
behaves (copies the favicon, hides from scanners, asks for a card or a seed phrase, runs a command). Everything comes from what
BrandWatch already stores; nothing is fetched here.
"""

from __future__ import annotations

from collections import Counter
from datetime import date, timedelta
from typing import Any

# how a name imitates the brand, from the signals the scoring already fired
NAMING = (("brand_tld_swap", "the brand name on another ending"), ("homoglyph_idn", "look-alike characters"),
          ("levenshtein_le_2", "a typo of the brand"), ("combosquat", "the brand plus extra words"), ("brand_in_subdomain", "the brand in a subdomain"))  # fmt: skip
# how the kit behaves
KIT = (("favicon_exact", "copies the brand's favicon"), ("screenshot_similarity_ge_90", "copies the brand's homepage"),
       ("looks_like_brand_ge_85", "looks 85%+ like the brand"), ("credential_form", "asks for a password"), ("payment_form", "asks for card details"),
       ("seed_phrase_field", "asks for a wallet seed phrase"), ("external_form_action", "sends what is typed to another server"),
       ("cloaking_ua_based", "shows scanners a harmless page"), ("cloaking_ip_based", "hides from data-centre addresses"),
       ("device_gating", "shows the lure only to phones"), ("bot_blocking", "refuses or challenges automated visitors"),
       ("clickfix_lure", "makes the visitor run a command"), ("known_phishing", "is already flagged by a security service"))  # fmt: skip


def _day(v: Any) -> date | None:
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def burst(days: list[date], window: int = 7) -> tuple[int, date, date] | None:
    """The largest number of registrations inside any ``window``-day span, and that span's first and last day."""
    days = sorted(days)
    best: tuple[int, date, date] | None = None
    j = 0
    for i, d in enumerate(days):
        while days[j] < d - timedelta(days=window - 1):
            j += 1
        n = i - j + 1
        if best is None or n > best[0]:
            best = (n, days[j], d)
    return best


def describe(sites: list[dict[str, Any]], links: list[dict[str, Any]], brand: str | None = None) -> dict[str, Any]:
    """``sites``: {host, registered, signals, tld, country, behind_cloudflare, severity}; ``links``: the strong links tying them."""
    n = len(sites)
    facts: list[str] = []
    days = [d for d in (_day(s.get("registered")) for s in sites) if d]
    timeline = sorted(({"date": d.isoformat(), "host": s["host"]} for s in sites if (d := _day(s.get("registered")))), key=lambda x: (x["date"], x["host"]))
    when = None
    if len(days) >= 2:
        b = burst(days)
        span = (max(days) - min(days)).days
        when = {"first": min(days).isoformat(), "last": max(days).isoformat(), "span_days": span}
        if b and b[0] >= max(2, round(len(days) * 0.6)):
            facts.append(f"{b[0]} of {len(days)} domains were registered within {(b[2] - b[1]).days + 1} day(s) ({b[1].isoformat()} → {b[2].isoformat()}): a batch, not a coincidence")
        else:
            facts.append(f"registered over {span} days ({min(days).isoformat()} → {max(days).isoformat()})")
        when["batch"] = bool(b and b[0] >= max(2, round(len(days) * 0.6)))
    naming = Counter()
    for s in sites:
        for sig, label in NAMING:
            if sig in (s.get("signals") or ()):
                naming[label] += 1
                break
        else:
            naming["another way"] += 1
    named = [f"{c} × {label}" for label, c in naming.most_common() if label != "another way"]
    if named:
        facts.append("names: " + ", ".join(named[:4]) + (f" of {brand}" if brand else ""))
    tlds = Counter(s.get("tld") for s in sites if s.get("tld"))
    if tlds and tlds.most_common(1)[0][1] > 1:
        facts.append("endings: " + ", ".join(f".{t} ({c})" for t, c in tlds.most_common(3)))
    cf = sum(1 for s in sites if s.get("behind_cloudflare"))
    if cf:
        facts.append(f"{cf} of {n} sit behind Cloudflare")
    countries = Counter(s.get("country") for s in sites if s.get("country"))
    if countries:
        facts.append("hosted in " + ", ".join(f"{c} ({k})" if k > 1 else c for c, k in countries.most_common(3)))
    kit = [f"{label} ({sum(1 for s in sites if sig in (s.get('signals') or ()))}/{n})" for sig, label in KIT
           if sum(1 for s in sites if sig in (s.get("signals") or ())) >= max(1, round(n * 0.5))]  # fmt: skip
    if kit:
        facts.append("the kit " + "; ".join(kit[:5]))
    kinds = sorted({link["kind"] for link in links})
    if len(kinds) >= 3:
        verdict = f"{len(kinds)} independent kinds of link: very likely one operation"
    elif len(kinds) == 2:
        verdict = "2 independent kinds of link: probably one operation"
    elif kinds:
        verdict = "one kind of link: likely related, worth confirming"
    else:
        verdict = "no strong link"
    sev = Counter(s.get("severity") for s in sites)
    summary = (f"{_plural(n, 'site')}" + (f" ({', '.join(f'{c} {k}' for k, c in sev.most_common())})" if sev else "") + ". " + "; ".join(facts[:4]) + "." if facts
               else f"{_plural(n, 'site')}.")  # fmt: skip
    return {"summary": summary, "facts": facts, "timeline": timeline, "when": when, "verdict": verdict, "link_kinds": kinds}
