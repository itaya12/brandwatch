"""Evidence package reports and takedown drafts (spec §14 "Reports & Takedowns", Phase 2).

* ``build_evidence_package`` renders one Finding into a self-contained HTML report (screenshots
  embedded as data URIs, every evidence row with its SHA-256 and provenance) plus a JSON twin,
  stores both in the evidence store and records ``reports`` rows.
* ``create_takedown_draft`` fills the takedown template: recipient resolved in order
  WHOIS abuse e-mail → registrar abuse → hosting abuse (whatever the evidence recorded), subject,
  brand, impersonating URL, an evidence block and the request. It is **a draft**: fully editable,
  never sent by the system. ``transition_takedown`` enforces the case-management state machine
  (draft → review → approved → sent → acknowledged → in_progress → resolved, plus rejected /
  reopened) and audits every step.
"""

from __future__ import annotations

import base64
import html as html_mod
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch import __version__
from brandwatch.db.enums import TakedownState
from brandwatch.db.models import (
    AuditEvent,
    Brand,
    Candidate,
    Evidence,
    Finding,
    FindingEvidence,
    Report,
    TakedownDraft,
    User,
    WhoisObservation,
)
from brandwatch.db.types import utcnow
from brandwatch.evidence.store import EvidenceStore

# ------------------------------------------------------------------------------------------
# Evidence package
# ------------------------------------------------------------------------------------------


def _portal_keys() -> set[str]:
    from brandwatch.detection.takedown_channels import REPORT_PORTALS

    return {p["key"] for p in REPORT_PORTALS}


def _data_uri(store: EvidenceStore, location: str | None, mime: str = "image/png") -> str | None:
    if not location or not store.exists(location):
        return None
    return f"data:{mime};base64," + base64.b64encode(store.get(location)).decode("ascii")


def _investigation_html(inv: dict[str, Any] | None) -> str:
    """The investigation of the site and its network (``intel.investigation_summary``), when one was made."""
    if not inv:
        return ""
    e = html_mod.escape
    det = inv.get("detections") or {}
    cert = inv.get("certificate") or {}
    servers = "".join(
        f"<tr><td><code>{e(str(s.get('ip') or ''))}</code></td><td>{e(str(s.get('country') or ''))}</td>"
        f"<td>{e(('AS' + str(s['asn']) + ' ') if s.get('asn') else '')}{e(str(s.get('owner') or ''))}</td>"
        f"<td>{e(str(s.get('detections') or '-'))}</td><td>{e(str(s.get('abuse_score') if s.get('abuse_score') is not None else '-'))}</td>"
        f"<td>{'a Cloudflare address shared by many unrelated sites' if s.get('shared_cloudflare_address') else e(', '.join(s.get('other_sites_on_it') or []) or 'none recorded')}</td></tr>"
        for s in inv.get("servers") or []
    )
    urlscan = inv.get("urlscan") or {}
    return (
        "<h2>Investigation: the site and its network</h2>"
        f"<p>VirusTotal: {e(str(det.get('positives') if det.get('positives') is not None else '-'))} / {e(str(det.get('total') or '-'))} engines flag the domain · "
        f"registrar {e(str(inv.get('registrar') or '-'))} · registered {e(str(inv.get('created') or '-'))} · "
        f"nameservers {e(', '.join(inv.get('nameservers') or []) or '-')} · {inv.get('certificates_in_ct', 0)} certificate(s) in the CT logs"
        + (f" · certificate {e(str(cert.get('subject') or ''))} issued by {e(str(cert.get('issuer') or ''))}" if cert else "")
        + f" · urlscan.io: {urlscan.get('same_server', 0)} other site(s) on the same server, {urlscan.get('same_page', 0)} with the same page.</p>"
        "<table><tr><th>Server</th><th>Country</th><th>Network</th><th>Engines</th><th>Abuse</th><th>Other sites on it</th></tr>" + servers + "</table>"
    )


def render_report_html(
    detail: dict[str, Any], store: EvidenceStore, baseline_shot: str | None
) -> str:
    """Standalone HTML (no external assets) from the Explain-Finding payload."""
    e = html_mod.escape
    f, c, s = detail["finding"], detail["candidate"], detail["score"] or {}
    suspect_shot = None
    for ev in detail["evidence"]:
        if ev["type"] == "screenshot":
            suspect_shot = ev
    suspect_uri = _data_uri(store, suspect_shot["artifact_location"]) if suspect_shot else None
    baseline_uri = _data_uri(store, baseline_shot)
    rows = "".join(
        f"<tr><td>{e(ev['observed_at'] or '')}</td><td>{e(ev['type'])}</td><td>{e(ev['role'])}</td>"
        f"<td>{e(ev['source'])}</td><td>{e(ev['collector'])}</td><td><code>{e(ev['sha256'] or '-')}</code></td></tr>"
        for ev in detail["evidence"]
    )
    signals = "".join(
        f"<tr><td><code>{e(x['name'])}</code></td><td>{e(x['group'])}</td><td style='text-align:right'>+{int(x['points'])}</td><td>{e(x['detail'])}</td></tr>"
        for x in s.get("signals", [])
    )
    timeline = "".join(
        f"<li>{e(o['observed_at'] or '')} · HTTP {o['http_status']} · {e(o['state_at_time'])}"
        f"{' · content changed' if o['changed'] else ''}</li>"
        for o in detail["observations"]
    )
    rules = (
        ", ".join(f"{r['rule']} → ≥ {r['min_severity']}" for r in s.get("rules_fired", []))
        or "none"
    )
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    investigation = _investigation_html(detail.get("investigation"))
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>BrandWatch evidence package — {e(c["hostname"])}</title>
<style>body{{font-family:system-ui,sans-serif;margin:32px;color:#111}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:4px 6px;font-size:13px;text-align:left}}
img{{max-width:100%;border:1px solid #999}}.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}code{{font-size:12px}}.sev{{font-weight:700;text-transform:uppercase}}</style></head><body>
<h1>Evidence package — <code>{e(c["hostname"])}</code></h1>
<p>Brand: <b>{e(detail["brand"]["name"])}</b> · Finding <code>{e(f["id"])}</code> · state {e(f["state"])} ·
severity <span class="sev">{e(f["severity"])}</span> · risk score {s.get("score", "-")} / 100 · confidence {round(f["confidence"] or 0)} % ·
scoring version {e(str(s.get("scoring_version", "-")))} · generated {generated} by BrandWatch {__version__}</p>
<p>Impersonating URL: <code>{e(c["canonical_url"])}</code> · first seen {e(c["first_seen"] or "")} · discovered by {e(", ".join(x["source"] for x in c["sources"]))}</p>
<h2>Why this is flagged</h2><table><tr><th>Signal</th><th>Group</th><th>Points</th><th>Evidence</th></tr>{signals}</table>
<p>Combination rules: {e(rules)}. Unavailable evidence: {e(", ".join(s.get("unavailable", [])) or "none")}.{(" Not evaluated: " + e(", ".join(s.get("not_evaluated_groups", []))) + ".") if s.get("not_evaluated_groups") else ""}</p>
<h2>Suspect vs. official</h2><div class="grid">
<div><p>{e(c["hostname"])}</p>{'<img src="' + suspect_uri + '">' if suspect_uri else "<p><i>no screenshot captured (unavailable)</i></p>"}</div>
<div><p>official — {e(detail["brand"]["name"])}</p>{'<img src="' + baseline_uri + '">' if baseline_uri else "<p><i>no baseline screenshot</i></p>"}</div></div>
{investigation}<h2>Observation timeline</h2><ul>{timeline}</ul>
<h2>Evidence (immutable; chain of custody)</h2><table><tr><th>Observed</th><th>Type</th><th>Role</th><th>Source</th><th>Collector</th><th>SHA-256</th></tr>{rows}</table>
<p style="color:#555;font-size:12px">Every row above exists as an append-only database record; artifacts are content-addressed by SHA-256. This document was generated for human review; BrandWatch never sends takedown requests automatically.</p>
</body></html>"""


def build_evidence_package(
    session: Session,
    finding: Finding,
    detail: dict[str, Any],
    store: EvidenceStore,
    *,
    actor: User | None,
) -> dict[str, Report]:
    """Store HTML + JSON reports for a finding and return ``{"html": Report, "json": Report}``."""
    brand = session.get(Brand, finding.brand_id)
    from brandwatch.db.models import BrandFingerprint

    fp = session.scalars(
        sa.select(BrandFingerprint)
        .where(BrandFingerprint.brand_id == brand.id)
        .order_by(BrandFingerprint.version.desc())
    ).first()
    baseline_shot = ((fp.screenshots or {}).get("home") or {}).get("artifact") if fp else None

    # evidence detail rows need the artifact *location* for embedding (the API payload has URLs)
    for ev in detail["evidence"]:
        row = session.get(Evidence, uuid.UUID(ev["id"]))
        ev["artifact_location"] = row.artifact_location if row else None

    html_doc = render_report_html(detail, store, baseline_shot)
    json_doc = json.dumps(
        {"generated_at": utcnow().isoformat(), "generator": f"brandwatch {__version__}", **detail},
        indent=2, default=str,
    )  # fmt: skip
    out: dict[str, Report] = {}
    for kind, fmt, content, ctype in (
        ("evidence_package", "html", html_doc.encode("utf-8"), "text/html"),
        ("evidence_package", "json", json_doc.encode("utf-8"), "application/json"),
    ):
        art = store.put(content, content_type=ctype, suffix=f".{fmt}")
        report = Report(brand_id=brand.id, kind=kind, format=fmt, path=art.location)
        session.add(report)
        session.flush()
        out[fmt] = report
    session.add(
        AuditEvent(
            workspace_id=brand.workspace_id,
            actor_type="analyst" if actor else "system",
            actor_id=actor.id if actor else None,
            action="report.generated",
            object_type="finding",
            object_id=finding.id,
            new_value={"reports": {k: str(v.id) for k, v in out.items()}},
        )  # fmt: skip
    )
    session.flush()
    return out


# ------------------------------------------------------------------------------------------
# Takedown drafts
# ------------------------------------------------------------------------------------------
_TRANSITIONS: dict[TakedownState, tuple[TakedownState, ...]] = {
    TakedownState.DRAFT: (TakedownState.REVIEW, TakedownState.REJECTED),
    TakedownState.REVIEW: (TakedownState.APPROVED, TakedownState.DRAFT, TakedownState.REJECTED),
    TakedownState.APPROVED: (TakedownState.SENT, TakedownState.REVIEW, TakedownState.REJECTED),
    TakedownState.SENT: (
        TakedownState.ACKNOWLEDGED,
        TakedownState.IN_PROGRESS,
        TakedownState.RESOLVED,
    ),
    TakedownState.ACKNOWLEDGED: (TakedownState.IN_PROGRESS, TakedownState.RESOLVED),
    TakedownState.IN_PROGRESS: (TakedownState.RESOLVED, TakedownState.REOPENED),
    TakedownState.RESOLVED: (TakedownState.REOPENED,),
    TakedownState.REJECTED: (TakedownState.REOPENED,),
    TakedownState.REOPENED: (TakedownState.REVIEW, TakedownState.DRAFT),
}


def allowed_transitions(state: TakedownState) -> tuple[TakedownState, ...]:
    return _TRANSITIONS.get(state, ())


def resolve_abuse_contact(
    session: Session, finding: Finding
) -> tuple[str | None, str | None, str | None]:
    """(abuse_contact, registrar, host) from recorded WHOIS evidence; None when unknown."""
    who = session.execute(
        sa.select(WhoisObservation, Evidence)
        .join(Evidence, Evidence.id == WhoisObservation.evidence_id)
        .join(FindingEvidence, FindingEvidence.evidence_id == Evidence.id)
        .where(FindingEvidence.finding_id == finding.id)
        .order_by(Evidence.observed_at.desc())
    ).first()
    if who is None:
        return None, None, None
    obs: WhoisObservation = who[0]
    raw = obs.raw or {}
    registrant = obs.registrant or {}
    abuse = (
        raw.get("abuse_email")
        or raw.get("registrar_abuse_contact_email")
        or raw.get("emails")
        or registrant.get("abuse_email")
    )
    if isinstance(abuse, list):
        abuse = abuse[0] if abuse else None
    if isinstance(abuse, str) and "@" not in abuse:
        abuse = None
    return abuse, obs.registrar, raw.get("hosting") or raw.get("org")


def takedown_body(
    detail: dict[str, Any], *, abuse_contact: str | None, registrar: str | None
) -> str:
    f, c, s, b = detail["finding"], detail["candidate"], detail["score"] or {}, detail["brand"]
    signals = "\n".join(f"  - {x['name']}: {x['detail']}" for x in s.get("signals", [])[:8])
    shots = detail.get("screenshots", {})
    whois_age = next(
        (x["detail"] for x in s.get("signals", []) if x["name"] in ("age_lt_7d", "age_lt_30d")),
        "see evidence package",
    )
    if f.get("kind") == "shop":
        return shop_takedown_body(detail, abuse_contact=abuse_contact, registrar=registrar)
    if f.get("kind") == "social":
        return social_takedown_body(detail)
    return f"""To: {abuse_contact or "<abuse contact — resolve via WHOIS / abuse.net / hosting provider>"}
Subject: Phishing site impersonating {b["name"]} — request for takedown: {c["hostname"]}

Hello{f" {registrar} abuse team" if registrar else ""},

We are reporting a website that impersonates {b["name"]} and appears designed to harvest user credentials.

  Impersonating URL : {c["canonical_url"]}
  Hostname          : {c["hostname"]}
  First observed    : {c["first_seen"]}
  Risk assessment   : {f["severity"].upper()} (score {s.get("score", "-")} / 100, confidence {round(f["confidence"] or 0)} %)

Evidence (full package with hashes and screenshots attached / available on request):
{signals}
  - domain age: {whois_age}
  - screenshot similarity to the official site: {shots.get("similarity_pct", "n/a")} %
  - every observation is stored immutably with timestamp, collector version and SHA-256.

We respectfully request that you suspend the domain / hosting for the content above and confirm
when done. Please reference this case id in replies: {f["id"]}.

Thank you,
{b["name"]} brand protection
"""


def shop_takedown_body(
    detail: dict[str, Any], *, abuse_contact: str | None, registrar: str | None
) -> str:
    """The letter for a suspicious shop, worded to its conclusion (detection/shop_levels.py): a
    suspicious shop is reported for review, a likely counterfeit seller as likely, and only a
    confirmed one as selling counterfeits. The reassuring facts are listed too."""
    from brandwatch.detection import merchant, shop_levels

    f, c, s, b = detail["finding"], detail["candidate"], detail["score"] or {}, detail["brand"]
    shop = s.get("shop") or {}
    lv = f.get("shop_level") or {}
    level = lv.get("level") or shop_levels.effective_level(None, shop)
    w = shop_levels.wording(level, b["name"], lv.get("conclusion"))
    why = shop.get("why") or {}
    reasons = "\n".join(f"  - {v}" for k, v in why.items() if k not in merchant.SHOP_PENALTIES)
    favour = "\n".join(f"  - {v}" for k, v in why.items() if k in merchant.SHOP_PENALTIES)
    ads = shop.get("ads") or []
    ad_lines = "\n".join(
        f"  - {a.get('library_url')} (page “{a.get('page_name')}”, since {a.get('start_date') or '?'})"
        for a in ads[:5]
    )
    return f"""To: {abuse_contact or "<abuse contact — resolve via WHOIS / abuse.net / hosting provider>"}
Subject: {w["subject"]}: {c["hostname"]}

Hello{f" {registrar} abuse team" if registrar else ""},

We are reporting a web shop that {w["claim"]} It is not an authorised {b["name"]} retailer.

  Shop URL          : {c["canonical_url"]}
  Hostname          : {c["hostname"]}
  First observed    : {c["first_seen"]}
  Our conclusion    : {shop_levels.LEVELS[level]["label"]} — {shop_levels.LEVELS[level]["help"]}
  Risk assessment   : {f["severity"].upper()} (shop score {s.get("score", "-")} / 100, confidence {round(f["confidence"] or 0)} %)

What we found:
{reasons}
{("Also noted (in the shop's favour):" + chr(10) + favour) if favour else ""}
{("Ads that send buyers to this shop (Meta Ad Library):" + chr(10) + ad_lines) if ads else ""}

Every observation is stored immutably with timestamp, collector version and SHA-256; the full
evidence package is available on request.

{w["ask"]} Please reference this case id in replies: {f["id"]}.

Thank you,
{b["name"]} brand protection
"""


def social_takedown_body(detail: dict[str, Any]) -> str:
    """The report text for a fake Facebook page / Instagram profile. Meta takes impersonation reports
    through its own forms (linked on the takedown page), not by e-mail: this is what to paste there."""
    f, c, s, b = detail["finding"], detail["candidate"], detail["score"] or {}, detail["brand"]
    rec = s.get("social") or {}
    reasons = "\n".join(f"  - {why}" for why in (rec.get("why") or {}).values())
    ai = rec.get("ai") or {}
    kind = "Facebook page" if rec.get("platform") == "facebook" else "Instagram account"
    return f"""To: Meta — impersonation report (Facebook “Report an impostor account” / Instagram “Report impersonation” form)
Subject: {kind} impersonating {b["name"]}: {rec.get("name") or c["hostname"]}

Hello,

We represent {b["name"]}. The {kind} below pretends to be {b["name"]}; it is not one of our accounts.

  Account           : {rec.get("name") or "-"} ({c["canonical_url"]})
  First observed    : {c["first_seen"]}
  Assessment        : {f["severity"].upper()} (social score {s.get("score", "-")} / 100, confidence {round(f["confidence"] or 0)} %)
{("  Our reading       : " + ai["summary"]) if ai.get("summary") else ""}

What we found:
{reasons}

Every observation is stored immutably with timestamp, collector version and SHA-256; screenshots of
the account and the evidence package are available on request. Please remove the account and confirm.
Case id: {f["id"]}.

Thank you,
{b["name"]} brand protection
"""


def create_takedown_draft(
    session: Session, finding: Finding, detail: dict[str, Any], *, actor: User
) -> TakedownDraft:
    abuse, registrar, host = resolve_abuse_contact(session, finding)
    draft = TakedownDraft(
        finding_id=finding.id,
        state=TakedownState.DRAFT,
        abuse_contact=abuse,
        registrar=registrar,
        host=host,
        reference=f"BW-{str(finding.id)[:8].upper()}",
        body=takedown_body(detail, abuse_contact=abuse, registrar=registrar),
    )
    session.add(draft)
    session.flush()
    session.add(
        AuditEvent(
            workspace_id=actor.workspace_id,
            actor_type="analyst",
            actor_id=actor.id,
            action="takedown.drafted",
            object_type="takedown_draft",
            object_id=draft.id,
            new_value={"finding_id": str(finding.id), "abuse_contact": abuse, "state": "draft"},
        )  # fmt: skip
    )
    session.flush()
    return draft


def update_takedown_body(
    session: Session, draft: TakedownDraft, *, actor: User, body: str | None = None,
    abuse_contact: str | None = None,
) -> TakedownDraft:  # fmt: skip
    if draft.state not in (TakedownState.DRAFT, TakedownState.REVIEW, TakedownState.REOPENED):
        raise ValueError(f"cannot edit a takedown in state {draft.state.value}")
    old = {"abuse_contact": draft.abuse_contact, "body_sha": hash(draft.body or "")}
    if body is not None:
        draft.body = body
    if abuse_contact is not None:
        draft.abuse_contact = abuse_contact.strip() or None
    draft.updated_at = utcnow()
    session.add(
        AuditEvent(
            workspace_id=actor.workspace_id,
            actor_type="analyst",
            actor_id=actor.id,
            action="takedown.edited",
            object_type="takedown_draft",
            object_id=draft.id,
            old_value=old,
            new_value={"abuse_contact": draft.abuse_contact},
        )  # fmt: skip
    )
    session.flush()
    return draft


def transition_takedown(
    session: Session, draft: TakedownDraft, to: TakedownState, *, actor: User, reason: str = ""
) -> TakedownDraft:
    if to not in allowed_transitions(draft.state):
        raise ValueError(f"{draft.state.value} → {to.value} is not an allowed transition")
    if to is TakedownState.SENT and not draft.abuse_contact:
        raise ValueError("cannot mark as sent without an abuse contact")
    old = draft.state
    draft.state = to
    now = utcnow()
    if to is TakedownState.SENT:
        draft.sent_at = now  # recorded by the analyst after sending from their own mailbox
    elif to in (TakedownState.ACKNOWLEDGED, TakedownState.IN_PROGRESS):
        draft.response_at = draft.response_at or now
    elif to is TakedownState.RESOLVED:
        draft.resolved_at = now
    draft.updated_at = now
    session.add(
        AuditEvent(
            workspace_id=actor.workspace_id,
            actor_type="analyst",
            actor_id=actor.id,
            action=f"takedown.{to.value}",
            object_type="takedown_draft",
            object_id=draft.id,
            old_value={"state": old.value},
            new_value={"state": to.value},
            reason=reason or None,
        )  # fmt: skip
    )
    session.flush()
    return draft


def takedown_out(draft: TakedownDraft, session: Session) -> dict[str, Any]:
    cand = session.get(Candidate, session.get(Finding, draft.finding_id).candidate_id)
    iso = lambda d: d.isoformat() if d else None  # noqa: E731
    return {
        "id": str(draft.id),
        "finding_id": str(draft.finding_id),
        "hostname": cand.hostname if cand else None,
        "state": draft.state.value,
        "allowed_transitions": [t.value for t in allowed_transitions(draft.state)],
        "abuse_contact": draft.abuse_contact,
        "registrar": draft.registrar,
        "host": draft.host,
        "reference": draft.reference,
        "body": draft.body,
        "sent_at": iso(draft.sent_at),
        "response_at": iso(draft.response_at),
        "resolved_at": iso(draft.resolved_at),
        "created_at": iso(draft.created_at),
        "updated_at": iso(draft.updated_at),
        "channels": draft.channels or {},
        "reported_count": len(
            set((draft.channels or {}).get("reports") or {}) & _portal_keys()
        ),  # portals that still exist
        "channels_sent": sorted(((draft.channels or {}).get("sent") or {}).keys()),
    }
