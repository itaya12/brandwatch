"""WHOIS history → a readable ownership timeline.

Input: the records of WhoisXML's WHOIS History API (one record per WHOIS snapshot the vendor has
collected; demo mode returns the same shape from recorded stories). Output: snapshots sorted by
the date they were seen, the events between consecutive snapshots (registration, re-registration
after expiry, registrar transfer, owner change, privacy switched on / off, nameserver change) and a
summary an analyst can act on — above all the owner details that were visible *before* privacy was
switched on, which phishers often leave in the first hours of a registration.

Pure functions, no I/O: tests feed records in directly.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

# What privacy / proxy / GDPR-redacted WHOIS contacts look like across registrars.
PRIVACY_RE = re.compile(
    r"redact|privacy|private|proxy|withheld|whoisguard|protected|gdpr|masked|not disclosed|"
    r"data protect|contact privacy|domains by proxy|identity protect|on behalf of|statutory masking|"
    r"please query the rdds|anonymi[sz]ed|hidden|cloudflareregistrar|withheldforprivacy|whois ?privacy|domaincontact",
    re.I,
)
CONTACT_FIELDS = (
    "name",
    "organization",
    "email",
    "telephone",
    "country",
    "state",
    "city",
    "street",
)
IDENTITY_FIELDS = ("name", "organization", "email", "telephone")
MAX_RECORDS = 200


def _day(value: Any) -> str | None:
    """'2026-10-06T00:00:00Z' / '2026-10-06 00:00:00 UTC' / '2026-10-06' → '2026-10-06'."""
    text = str(value or "").strip()[:10]
    try:
        return date.fromisoformat(text).isoformat()
    except ValueError:
        return None


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split())


def is_private(value: Any) -> bool:
    return bool(value) and bool(PRIVACY_RE.search(str(value)))


def contact_view(c: dict | None) -> dict[str, Any]:
    """A registrant contact with privacy placeholders recognised: ``hidden`` is True when nothing
    that identifies a person or company is published."""
    c = c or {}
    out = {f: _clean(c.get(f)) for f in CONTACT_FIELDS}
    visible = {f: out[f] for f in IDENTITY_FIELDS if out[f] and not is_private(out[f])}
    out["visible"] = visible
    out["hidden"] = not visible
    out["privacy_service"] = next(
        (out[f] for f in ("organization", "name") if is_private(out[f])), ""
    )
    return out


def _identity(c: dict) -> tuple:
    v = c.get("visible") or {}
    return tuple((v.get(f) or "").lower() for f in IDENTITY_FIELDS)


def _label(c: dict) -> str:
    v = c.get("visible") or {}
    if not v:
        return c.get("privacy_service") or "privacy-protected"
    who = v.get("name") or v.get("organization") or v.get("email") or v.get("telephone") or "owner visible"
    extra = [
        x
        for x in (
            v.get("organization") if v.get("name") else None,
            v.get("email") if who != v.get("email") else None,
        )
        if x
    ]
    return who + (f" ({', '.join(extra)})" if extra else "")


def snapshots(records: list[dict]) -> list[dict[str, Any]]:
    """One normalised snapshot per record, oldest first (by the date the vendor saw it)."""
    out = []
    for r in (records or [])[:MAX_RECORDS]:
        audit = r.get("audit") or {}
        seen = (
            _day(audit.get("updatedDate") or audit.get("createdDate"))
            or _day(r.get("updatedDateISO8601"))
            or _day(r.get("createdDateISO8601"))
        )
        out.append({
            "seen": seen,
            "created": _day(r.get("createdDateISO8601") or r.get("createdDateRaw")),
            "updated": _day(r.get("updatedDateISO8601") or r.get("updatedDateRaw")),
            "expires": _day(r.get("expiresDateISO8601") or r.get("expiresDateRaw")),
            "registrar": _clean(r.get("registrarName")),
            "nameservers": sorted({str(n).lower().rstrip(".") for n in (r.get("nameServers") or []) if n}),
            "status": [str(s).split(" ")[0] for s in (r.get("status") or [])][:6] if isinstance(r.get("status"), list) else [],
            "registrant": contact_view(r.get("registrantContact")),
            "raw_text": str(r.get("rawText") or r.get("cleanText") or "")[:4000],
        })  # fmt: skip
    out.sort(key=lambda s: (s["seen"] or "", s["updated"] or ""))
    return out


def _event(
    kind: str, when: str | None, title: str, detail: str = "", key: bool = False
) -> dict[str, Any]:
    return {"kind": kind, "date": when, "title": title, "detail": detail, "key": key}


def events(snaps: list[dict]) -> list[dict[str, Any]]:
    """What changed between consecutive snapshots, oldest first."""
    if not snaps:
        return []
    first = snaps[0]
    fr = first["registrant"]
    out = [_event("registered", first["created"] or first["seen"],
                  "Registered with privacy on" if fr["hidden"] else f"Registered by {_label(fr)}",
                  (f"registrant shown as '{fr['privacy_service']}' · " if fr["hidden"] and fr["privacy_service"] else "")
                  + f"via {first['registrar'] or 'unknown registrar'}" + (f" · first WHOIS snapshot {first['seen']}" if first["seen"] else ""),
                  key=not fr["hidden"])]  # fmt: skip
    for prev, cur in zip(snaps, snaps[1:], strict=False):
        when = cur["seen"]
        if cur["created"] and prev["created"] and cur["created"] > prev["created"]:
            gap = (
                f"the previous registration expired {prev['expires']}"
                if prev["expires"]
                else "the previous registration lapsed"
            )
            out.append(_event("re_registered", cur["created"], "Re-registered after expiry",
                              f"{gap}; new owner {_label(cur['registrant'])} via {cur['registrar'] or 'unknown registrar'} "
                              f"(previous owner {_label(prev['registrant'])}). Aged domains are bought to look trustworthy.", key=True))  # fmt: skip
            continue
        if (
            cur["registrar"]
            and prev["registrar"]
            and cur["registrar"].lower() != prev["registrar"].lower()
        ):
            out.append(
                _event(
                    "transfer",
                    when,
                    f"Transferred to {cur['registrar']}",
                    f"from {prev['registrar']}",
                )
            )
        pr, cr = prev["registrant"], cur["registrant"]
        if not pr["hidden"] and cr["hidden"]:
            lost = ", ".join(f"{k}: {v}" for k, v in pr["visible"].items())
            out.append(_event("privacy_on", when, "Privacy switched on — owner details hidden",
                              f"until then WHOIS showed {lost}" + (f"; now '{cr['privacy_service']}'" if cr["privacy_service"] else ""), key=True))  # fmt: skip
        elif pr["hidden"] and not cr["hidden"]:
            out.append(
                _event("privacy_off", when, "Owner details became visible", _label(cr), key=True)
            )
        elif not pr["hidden"] and not cr["hidden"] and _identity(pr) != _identity(cr):
            out.append(
                _event(
                    "owner_change", when, "Owner changed", f"{_label(pr)} → {_label(cr)}", key=True
                )
            )
        if cur["nameservers"] and prev["nameservers"] and cur["nameservers"] != prev["nameservers"]:
            out.append(
                _event(
                    "nameservers",
                    when,
                    "Nameservers changed",
                    f"{', '.join(prev['nameservers'])} → {', '.join(cur['nameservers'])}",
                )
            )
        if (
            cur["expires"]
            and prev["expires"]
            and cur["expires"] > prev["expires"]
            and cur["created"] == prev["created"]
        ):
            out.append(_event("renewed", when, "Renewed", f"now expires {cur['expires']}"))
    return out


def exposed_owners(snaps: list[dict]) -> list[dict[str, Any]]:
    """Every distinct owner identity WHOIS ever showed, with the dates it was visible."""
    seen: dict[tuple, dict[str, Any]] = {}
    for s in snaps:
        c = s["registrant"]
        if c["hidden"]:
            continue
        k = _identity(c)
        row = seen.setdefault(
            k,
            {
                **{f: c[f] for f in CONTACT_FIELDS},
                "visible": c["visible"],
                "first_seen": s["seen"],
                "last_seen": s["seen"],
            },
        )
        row["last_seen"] = s["seen"]
    return list(seen.values())


def analyze(records: list[dict]) -> dict[str, Any]:
    snaps = snapshots(records)
    evs = events(snaps)
    owners = exposed_owners(snaps)
    latest = snaps[-1] if snaps else None
    hidden_now = bool(latest and latest["registrant"]["hidden"])
    privacy_on = [e for e in evs if e["kind"] == "privacy_on"]
    created = sorted(d for d in (s["created"] for s in snaps) if d)
    registrars = list(dict.fromkeys(s["registrar"] for s in snaps if s["registrar"]))
    # the lead only counts within the current registration: after an expiry and re-registration,
    # the previous (often legitimate) owner says nothing about who runs the site today
    life = [s for s in snaps if not created or s["created"] in (None, created[-1])]
    current_owners = exposed_owners(life)
    for i, s in enumerate(snaps):  # what changed vs the previous snapshot, for the table
        p = snaps[i - 1] if i else None
        s["changed"] = [] if p is None else [f for f, a, b in (
            ("registrar", p["registrar"], s["registrar"]), ("registrant", _identity(p["registrant"]), _identity(s["registrant"])),
            ("privacy", p["registrant"]["hidden"], s["registrant"]["hidden"]), ("created", p["created"], s["created"]),
            ("expires", p["expires"], s["expires"]), ("nameservers", p["nameservers"], s["nameservers"])) if a != b]  # fmt: skip
    return {
        "snapshots": snaps,
        "events": evs,
        "owners": owners,
        "summary": {
            "records": len(snaps),
            "first_registered": created[0] if created else None,
            "latest_registration": created[-1] if created else None,
            "registrars": registrars,
            "transfers": sum(1 for e in evs if e["kind"] == "transfer"),
            "owner_changes": sum(1 for e in evs if e["kind"] in ("owner_change", "re_registered")),
            "re_registrations": sum(1 for e in evs if e["kind"] == "re_registered"),
            "hidden_now": hidden_now,
            "hidden_since": privacy_on[-1]["date"] if hidden_now and privacy_on else None,
            # the lead: owner details that were public before privacy was switched on
            "leaked_owner": current_owners[-1] if hidden_now and current_owners else None,
        },
    }
