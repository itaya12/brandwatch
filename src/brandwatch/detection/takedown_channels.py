"""Where a takedown request goes, beyond the registrar.

A phishing site can be pulled down by several parties, and the fastest one is often not the
registrar: the **hosting provider** (whoever owns the IP) can suspend the server, and a **CDN /
DNS provider** (Cloudflare & co.) can disable the proxy or the DNS zone even when the origin host
ignores abuse mail. On top of that, **report portals** (browser blocklists, anti-virus vendors,
phishing feeds) get the site flagged for users world-wide within hours — every vendor that flags
it also feeds VirusTotal, which search engines and mail filters consult.

This module resolves those channels from what the scan and the intel page already collected
(WHOIS/RDAP, DNS, IP ownership) and lists the portals. Nothing here sends anything: the analyst
opens a pre-filled mail or a form, reports, and ticks it off.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from sqlalchemy.orm import Session

from brandwatch.db.models import Brand, Candidate, Finding, TakedownDraft, User
from brandwatch.detection.discovery import split_host

# keyword (lower-case, matched against registrar / AS owner / org / nameserver) → abuse desk
KNOWN_ABUSE: dict[str, dict[str, Any]] = {
    "cloudflare": {"name": "Cloudflare", "email": "abuse@cloudflare.com", "form": "https://abuse.cloudflare.com/phishing", "cdn": True,
                   "note": "Cloudflare proxies the site: its abuse desk can disable the proxy/DNS even if the origin host ignores you"},
    "linode": {"name": "Linode / Akamai Connected Cloud", "email": "abuse@linode.com"},
    "akamai": {"name": "Akamai", "email": "abuse@akamai.com", "cdn": True},
    "fastly": {"name": "Fastly", "email": "abuse@fastly.com", "cdn": True},
    "amazon": {"name": "Amazon Web Services", "email": "abuse@amazonaws.com", "form": "https://support.aws.amazon.com/#/contacts/report-abuse"},
    "google": {"name": "Google Cloud", "form": "https://support.google.com/code/contact/cloud_platform_report"},
    "microsoft": {"name": "Microsoft Azure", "email": "abuse@microsoft.com", "form": "https://msrc.microsoft.com/report/abuse"},
    "digitalocean": {"name": "DigitalOcean", "email": "abuse@digitalocean.com", "form": "https://www.digitalocean.com/company/contact/abuse"},
    "ovh": {"name": "OVH", "email": "abuse@ovh.net", "form": "https://www.ovh.com/abuse/"},
    "hetzner": {"name": "Hetzner", "email": "abuse@hetzner.com", "form": "https://abuse.hetzner.com/"},
    "vultr": {"name": "Vultr", "email": "abuse@vultr.com"},
    "contabo": {"name": "Contabo", "email": "abuse@contabo.com"},
    "leaseweb": {"name": "Leaseweb", "email": "abuse@leaseweb.com"},
    "alibaba": {"name": "Alibaba Cloud", "email": "abuse@list.alibaba-inc.com"},
    "hostinger": {"name": "Hostinger", "email": "abuse@hostinger.com"},
    "namecheap": {"name": "Namecheap", "email": "abuse@namecheap.com"},
    "godaddy": {"name": "GoDaddy", "email": "abuse@godaddy.com", "form": "https://supportcenter.godaddy.com/AbuseReport"},
    "porkbun": {"name": "Porkbun", "email": "abuse@porkbun.com"},
    "tucows": {"name": "Tucows", "email": "abuse@tucows.com"},
    "publicdomainregistry": {"name": "PDR Ltd", "email": "abuse-contact@publicdomainregistry.com"},
    "nicenic": {"name": "NiceNIC", "email": "abuse@nicenic.net"},
    "dynadot": {"name": "Dynadot", "email": "abuse@dynadot.com"},
    "gname": {"name": "Gname", "email": "abuse@gname.com"},
    "hostwinds": {"name": "Hostwinds", "email": "abuse@hostwinds.com"},
}  # fmt: skip

# Public places to report a phishing site. {url} / {host} are filled in; "mailto:" entries open a
# pre-filled mail. Every anti-virus vendor that flags the site also feeds VirusTotal.
# Where to report a phishing site, each link going as close to the report form as the vendor allows.
# Links checked on 2026-10-10; {url} / {host} are filled in for the site being reported.
REPORT_PORTALS: list[dict[str, Any]] = [
    # browsers: the warning a victim actually sees
    {"key": "google_safebrowsing", "group": "browsers", "name": "Google Safe Browsing", "url": "https://safebrowsing.google.com/safebrowsing/report_phish/?url={url}",
     "note": "Chrome, Firefox, Safari and Android warn users; Google also demotes the site in search. Opens with the URL filled in"},
    {"key": "microsoft_smartscreen", "group": "browsers", "name": "Microsoft SmartScreen", "url": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest",
     "note": "Edge, Windows and Outlook block the site. Guest form, no sign-in"},
    # anti-virus engines (most of them are also VirusTotal engines)
    {"key": "kaspersky", "group": "antivirus", "name": "Kaspersky OpenTIP", "url": "https://opentip.kaspersky.com/{host}/", "note": "opens on the domain: check it and report"},
    {"key": "eset", "group": "antivirus", "name": "ESET", "url": "https://phishing.eset.com/report", "note": "phishing report form"},
    {"key": "bitdefender", "group": "antivirus", "name": "Bitdefender", "url": "https://www.bitdefender.com/consumer/support/answer/29358/", "note": "Bitdefender's official route for reporting a malicious site; detection is added within 72 hours"},
    {"key": "trendmicro", "group": "antivirus", "name": "Trend Micro Site Safety", "url": "https://global.sitesafety.trendmicro.com/", "note": "check the URL; an untested site is queued for review automatically"},
    {"key": "avast", "group": "antivirus", "name": "Avast / AVG", "url": "https://www.avast.com/report-false-negative", "note": "report a malicious site they do not block yet"},
    {"key": "sophos", "group": "antivirus", "name": "Sophos", "url": "https://support.sophos.com/support/s/filesubmission", "note": "URL / sample submission"},
    {"key": "avira", "group": "antivirus", "name": "Avira", "url": "https://www.avira.com/en/analysis/submit", "note": "URL / sample submission"},
    {"key": "drweb", "group": "antivirus", "name": "Dr.Web", "url": "https://vms.drweb.com/sendvirus/", "note": "URL / sample submission"},
    # corporate web filters: block the site on company networks, routers and DNS filters
    {"key": "fortiguard", "group": "filters", "name": "FortiGuard (Fortinet)", "url": "https://www.fortiguard.com/webfilter", "note": "look up the URL and submit it for rating; no account"},
    {"key": "symantec", "group": "filters", "name": "Symantec / Broadcom Site Review", "url": "https://sitereview.bluecoat.com/", "note": "Norton & Blue Coat categorisation"},
    {"key": "trellix", "group": "filters", "name": "Trellix / McAfee TrustedSource", "url": "https://www.trustedsource.org/", "note": "URL categorisation & dispute"},
    {"key": "zscaler", "group": "filters", "name": "Zscaler Site Review", "url": "https://sitereview.zscaler.com/", "note": "look up the URL and request reclassification; answer by e-mail"},
    {"key": "paloalto", "group": "filters", "name": "Palo Alto Networks Test A Site", "url": "https://urlfiltering.paloaltonetworks.com/", "note": "look up the URL, then 'Request change' under the result (may ask you to sign in)"},
    {"key": "brightcloud", "group": "filters", "name": "OpenText BrightCloud (Webroot)", "url": "https://support.threatintel.opentext.com/tools/change-request.php", "note": "change request: rate the URL 1-20; used by many routers and firewalls"},
    {"key": "cisco_talos", "group": "filters", "name": "Cisco Talos", "url": "https://talosintelligence.com/reputation_center/support", "note": "web reputation ticket; free Cisco account"},
    # phishing feeds and blocklists consumed by mail servers, resolvers and security vendors
    {"key": "netcraft", "group": "feeds", "name": "Netcraft", "url": "https://report.netcraft.com/report",
     "note": "runs its own takedown service and feeds browser blocklists"},
    {"key": "apwg", "group": "feeds", "name": "APWG (Anti-Phishing Working Group)", "url": "mailto:reportphishing@apwg.org?subject={subject}&body={body}",
     "note": "the industry phishing feed used by security vendors world-wide; opens a pre-written e-mail"},
    {"key": "spamhaus", "group": "feeds", "name": "Spamhaus", "url": "https://submit.spamhaus.org/",
     "note": "domain / URL blocklists used by mail servers and DNS resolvers; sign in with GitHub, Google or LinkedIn"},
    {"key": "phishtank", "group": "feeds", "name": "PhishTank", "url": "https://phishtank.org/add_web_phish.php",
     "note": "community feed run by Cisco Talos; free account needed"},
    {"key": "urlhaus", "group": "feeds", "name": "URLhaus (abuse.ch)", "url": "https://urlhaus.abuse.ch/api/#submit",
     "note": "malware URLs only: use it when the kit also pushes malware (APKs, droppers); free abuse.ch account"},
    # national reporting: pick the country of the victims
    {"key": "ic3", "group": "authorities", "name": "FBI IC3 (US)", "url": "https://complaint.ic3.gov/", "note": "complaint form, for US victims or US-hosted sites"},
    {"key": "ncsc_uk", "group": "authorities", "name": "NCSC Report a suspicious website (UK)", "url": "https://www.ncsc.gov.uk/section/about-this-website/report-scam-website", "note": "the form is on the page; the NCSC takes sites down"},
    {"key": "scamwatch_au", "group": "authorities", "name": "Scamwatch (Australia)", "url": "https://www.scamwatch.gov.au/report-a-scam", "note": "ACCC report form; works with providers to remove scam sites"},
    {"key": "cafc_ca", "group": "authorities", "name": "Canadian Anti-Fraud Centre", "url": "https://reportcyberandfraud.canada.ca/", "note": "the national cybercrime and fraud reporting system"},
]  # fmt: skip
PORTAL_GROUPS = {"browsers": "Browsers & search engines", "antivirus": "Anti-virus vendors (most are VirusTotal engines)",
                 "filters": "Corporate web filters (company networks, routers, DNS filters)",
                 "feeds": "Phishing feeds & blocklists", "authorities": "National reporting (pick the victims' country)"}  # fmt: skip

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_ABUSE_LINE = re.compile(
    r"(?im)^\s*(?:abuse-mailbox|OrgAbuseEmail|abuse-c|abuse|Registrar Abuse Contact Email)\s*:\s*(\S+@\S+)"
)


def known_desk(*names: str | None) -> dict[str, Any] | None:
    """The known abuse desk whose keyword appears in any of ``names`` (org, AS owner, nameserver, registrar)."""
    blob = " ".join(n for n in names if n).lower()
    for key, desk in KNOWN_ABUSE.items():
        if key in blob:
            return {"key": key, **desk}
    return None


def _abuse_from_whois(text: str | None) -> str | None:
    if not text:
        return None
    m = _ABUSE_LINE.search(text)
    if m and _EMAIL.search(m.group(1)):
        return _EMAIL.search(m.group(1)).group(0)
    for e in _EMAIL.findall(text):
        if "abuse" in e.lower():
            return e
    return None


def resolve_channels(session: Session, finding: Finding) -> dict[str, Any]:
    """Registrar / hosting / CDN contacts for a finding from recorded evidence and the intel cache."""
    from brandwatch.detection import intel as intel_mod
    from brandwatch.detection.investigation import _seed_facts
    from brandwatch.detection.reports import resolve_abuse_contact

    cand = session.get(Candidate, finding.candidate_id)
    brand = session.get(Brand, finding.brand_id)
    ws = brand.workspace_id
    host = cand.hostname
    reg = split_host(host).registrable or host
    abuse, registrar, _ = resolve_abuse_contact(session, finding)

    # --- registrar (WHOIS evidence → RDAP intel → known desk) -------------------------------
    rdap_row = intel_mod.rows_for(session, ws, "domain", reg).get("rdap/report")
    rdap = intel_mod._rdap_view(rdap_row.payload if rdap_row and rdap_row.status == "ok" else None)
    registrar = registrar or rdap.get("registrar")
    desk = known_desk(registrar)
    dom_rows_whois = intel_mod.rows_for(session, ws, "domain", host).get("virustotal/report")
    whois_text = (
        ((dom_rows_whois.payload or {}).get("attributes") or {}).get("whois")
        if dom_rows_whois and dom_rows_whois.status == "ok"
        else None
    )
    whois_abuse = _abuse_from_whois(whois_text)
    registrar_channel = {
        "name": registrar, "email": abuse or rdap.get("abuse_email") or whois_abuse or (desk or {}).get("email"),
        "phone": rdap.get("abuse_phone"), "form": (desk or {}).get("form"), "url": rdap.get("registrar_url"),
        "source": "WHOIS" if abuse else ("RDAP" if rdap.get("abuse_email") else ("WHOIS record" if whois_abuse else ("known desk" if desk else None))),
    }  # fmt: skip

    # --- hosting (every IP the site resolves to) ----------------------------------------------
    facts = _seed_facts(session, finding)
    ips = list(dict.fromkeys(facts.get("ips") or []))
    dom_rows = intel_mod.rows_for(session, ws, "domain", host)
    vt_dom = dom_rows.get("virustotal/report")
    attrs = (
        ((vt_dom.payload or {}).get("attributes") or {}) if vt_dom and vt_dom.status == "ok" else {}
    )
    for rec in attrs.get("last_dns_records") or []:
        if rec.get("type") == "A" and rec.get("value") and rec["value"] not in ips:
            ips.append(rec["value"])
    nameservers = [
        r["value"].lower()
        for r in attrs.get("last_dns_records") or []
        if r.get("type") == "NS" and r.get("value")
    ]
    nameservers += [n.lower() for n in rdap.get("nameservers") or [] if n]
    hosting: list[dict[str, Any]] = []
    cdn: dict[str, Any] | None = None
    for ip in ips[:4]:
        rows = intel_mod.rows_for(session, ws, "ip", ip)
        rep = rows.get("virustotal/report")
        a = ((rep.payload or {}).get("attributes") or {}) if rep and rep.status == "ok" else {}
        geo_row = rows.get("geo/report")
        geo = (geo_row.payload or {}) if geo_row and geo_row.status == "ok" else {}
        org = a.get("as_owner") or geo.get("org")  # IP ownership only — never the domain registrant
        email = _abuse_from_whois(a.get("whois"))
        d = known_desk(org)
        entry = {"ip": ip, "org": org, "country": (a.get("country") or geo.get("country") or "").upper() or None,
                 "email": email or (d or {}).get("email"), "form": (d or {}).get("form"), "desk": (d or {}).get("name"),
                 "source": "IP WHOIS" if email else ("known desk" if d else None)}  # fmt: skip
        if d and d.get("cdn"):
            cdn = cdn or {
                "name": d["name"],
                "email": d.get("email"),
                "form": d.get("form"),
                "note": d.get("note"),
                "via": f"IP {ip} belongs to {d['name']}",
            }
            entry["cdn"] = True
        hosting.append(entry)
    if cdn is None:
        d = known_desk(*nameservers)
        if d and d.get("cdn"):
            cdn = {
                "name": d["name"],
                "email": d.get("email"),
                "form": d.get("form"),
                "note": d.get("note"),
                "via": "nameservers " + ", ".join(sorted(set(nameservers))[:2]),
            }
    return {"registrar": registrar_channel, "hosting": hosting, "cdn": cdn, "nameservers": sorted(set(nameservers)),
            "resolved_at": datetime.now(UTC).isoformat()}  # fmt: skip


def ensure_channels(
    session: Session, draft: TakedownDraft, *, force: bool = False, persist: bool = True
) -> dict[str, Any]:
    """The draft's channel record. The contacts are resolved **fresh on every view** (so running
    intel later improves them) and the analyst's edits (``overrides``), ``sent`` and ``reports``
    are overlaid; only those three are stored. ``persist=False`` never writes (GET pages)."""
    stored = dict(draft.channels or {})
    finding = session.get(Finding, draft.finding_id)
    resolved = resolve_channels(session, finding)
    overrides = dict(stored.get("overrides") or {})
    for channel, email in overrides.items():
        if channel == "registrar":
            resolved["registrar"] = {
                **(resolved.get("registrar") or {}),
                "email": email,
                "source": "analyst",
            }
        elif channel == "cdn":
            resolved["cdn"] = {**(resolved.get("cdn") or {"name": "CDN / DNS provider", "via": "added by analyst"}), "email": email, "source": "analyst"}  # fmt: skip
        elif channel.startswith("hosting:"):
            ip = channel.split(":", 1)[1]
            hosting = resolved.get("hosting") or []
            if not any(h.get("ip") == ip for h in hosting):
                hosting.append({"ip": ip, "org": None, "country": None, "form": None, "desk": None})
            for h in hosting:
                if h.get("ip") == ip:
                    h["email"], h["source"] = email, "analyst"
            resolved["hosting"] = hosting
    ch = {"resolved": resolved, "overrides": overrides, "sent": dict(stored.get("sent") or {}),
          "reports": dict(stored.get("reports") or {})}  # fmt: skip
    if persist and (force or "overrides" not in stored):
        draft.channels = {"overrides": overrides, "sent": ch["sent"], "reports": ch["reports"]}
        session.flush()
    return ch


def record_channel(
    session: Session, draft: TakedownDraft, *, actor: User, channel: str, contact: str | None, sent: bool
) -> dict[str, Any]:  # fmt: skip
    """Analyst edited a channel's contact and/or reports having sent the request to it."""
    from brandwatch.db.enums import TakedownState
    from brandwatch.db.models import AuditEvent

    ch = ensure_channels(session, draft, persist=False)
    hosting_ips = {h.get("ip") for h in ch["resolved"].get("hosting") or []}
    if channel not in ("registrar", "cdn") and not (
        channel.startswith("hosting:") and channel.split(":", 1)[1] in hosting_ips
    ):
        raise ValueError(f"unknown channel {channel!r}")
    email = (contact or "").strip()
    if email and not _EMAIL.fullmatch(email):
        raise ValueError("the contact must be a plain e-mail address")
    overrides = dict(ch["overrides"])
    if contact is not None:
        if email:
            overrides[channel] = email
        else:
            overrides.pop(channel, None)
        if (
            channel == "registrar"
            and email
            and draft.state not in (TakedownState.RESOLVED, TakedownState.REJECTED)
        ):  # the registrar's address is the request's main contact (also after it was sent to another channel first)
            draft.abuse_contact = email
    sent_map = dict(ch["sent"])
    if sent:
        to = email or _channel_email(ch["resolved"], channel)
        sent_map[channel] = {"at": datetime.now(UTC).isoformat(), "to": to, "by": actor.email}
        draft.sent_at = draft.sent_at or datetime.now(UTC)  # the list / dashboard show it as sent
        if draft.state in (TakedownState.DRAFT, TakedownState.REVIEW, TakedownState.APPROVED, TakedownState.REOPENED):
            # the first channel that was mailed moves the request to "sent" (it used to stay a draft, and the list kept
            # saying "not sent yet"); the state machine's own transition is audited the same way
            old = draft.state
            draft.state = TakedownState.SENT
            if not draft.abuse_contact and to:
                draft.abuse_contact = to
            session.add(AuditEvent(workspace_id=actor.workspace_id, actor_type="analyst", actor_id=actor.id,
                                   action="takedown.sent", object_type="takedown_draft", object_id=draft.id,
                                   old_value={"state": old.value}, new_value={"state": "sent", "channel": channel}))  # fmt: skip
    draft.channels = {"overrides": overrides, "sent": sent_map, "reports": dict(ch["reports"])}
    draft.updated_at = datetime.now(UTC)
    session.add(AuditEvent(workspace_id=actor.workspace_id, actor_type="analyst", actor_id=actor.id,
                           action="takedown.channel_sent" if sent else "takedown.channel_edited", object_type="takedown_draft",
                           object_id=draft.id, new_value={"channel": channel, "to": email or None}))  # fmt: skip
    session.flush()
    return ensure_channels(session, draft, persist=False)


def _channel_email(resolved: dict[str, Any], channel: str) -> str | None:
    if channel in ("registrar", "cdn"):
        return (resolved.get(channel) or {}).get("email")
    ip = channel.split(":", 1)[1]
    return next((h.get("email") for h in resolved.get("hosting") or [] if h.get("ip") == ip), None)


def toggle_report(
    session: Session, draft: TakedownDraft, *, actor: User, portal: str
) -> dict[str, Any]:
    """Tick / untick "reported to <portal>"."""
    from brandwatch.db.models import AuditEvent

    if portal not in {p["key"] for p in REPORT_PORTALS}:
        # Report-to-Meta rows: only the ads / pages / forms of this finding's own shop
        finding = session.get(Finding, draft.finding_id)
        allowed = (meta_report_keys(shop_record_of(session, finding)) | social_report_keys(social_record_of(session, finding))
                   | meta_report_keys(ads_record_of(session, finding)) if finding else set())  # fmt: skip
        if portal not in allowed:
            raise ValueError(f"unknown report portal {portal!r}")
    ch = ensure_channels(session, draft, persist=False)
    reports = dict(ch.get("reports", {}))
    done = portal in reports
    if done:
        reports.pop(portal)
    else:
        reports[portal] = {"at": datetime.now(UTC).isoformat(), "by": actor.email}
    draft.channels = {
        "overrides": dict(ch["overrides"]),
        "sent": dict(ch["sent"]),
        "reports": reports,
    }
    draft.updated_at = datetime.now(UTC)
    session.add(AuditEvent(workspace_id=actor.workspace_id, actor_type="analyst", actor_id=actor.id,
                           action="takedown.report_unticked" if done else "takedown.reported", object_type="takedown_draft",
                           object_id=draft.id, new_value={"portal": portal}))  # fmt: skip
    session.flush()
    return ensure_channels(session, draft, persist=False)


def portal_links(url: str, host: str, subject: str, body: str) -> list[dict[str, Any]]:
    """The portal list with {url}/{host}/{subject}/{body} filled in (mail bodies kept short)."""
    short = (
        body
        if len(body) <= 1500
        else body[:1500] + "\n\n[... full request text pasted by the analyst ...]"
    )
    out = []
    for p in REPORT_PORTALS:
        link = p["url"].format(
            url=quote(url, safe=""),
            host=quote(host, safe=""),
            subject=quote(subject, safe=""),
            body=quote(short, safe=""),
        )
        out.append({**p, "link": link, "group_label": PORTAL_GROUPS[p["group"]]})
    return out


def mailto(email: str | None, subject: str, body: str, *, max_len: int = 1900) -> str | None:
    """A ``mailto:`` link the mail client can open: only for a plain address, and short enough
    for Windows/Outlook (the whole encoded link stays under ``max_len``)."""
    if not email or not _EMAIL.fullmatch(email.strip()):
        return None
    head = f"mailto:{email.strip()}?subject={quote(subject, safe='')}&body="
    tail = quote("\n\n[... paste the full request text from BrandWatch ...]", safe="")
    room = max_len - len(head) - len(tail)
    enc = quote(body, safe="")
    if len(enc) <= room:
        return head + enc
    cut = body
    while (
        cut and len(quote(cut, safe="")) > room
    ):  # shrink the raw text until the encoded form fits
        cut = cut[: int(len(cut) * 0.8)]
    return head + quote(cut, safe="") + tail


def body_for(body: str, email: str | None, org: str | None, reference: str | None) -> str:
    """The request text addressed to one channel: its own To: line, greeting and case id."""
    lines = body.splitlines()
    out = []
    for line in lines:
        if line.startswith("To:") and email:
            line = f"To: {email}"
        elif line.startswith("Hello") and line.rstrip().endswith(","):
            line = f"Hello{f' {org}' if org else ''} abuse team,"
        out.append(line)
    text = "\n".join(out)
    if reference:
        text = re.sub(
            r"reference this case id in replies: [^.\s]+",
            f"reference this case id in replies: {reference}",
            text,
        )
    return text


def subject_for(draft: TakedownDraft, session: Session) -> str:
    finding = session.get(Finding, draft.finding_id)
    cand = session.get(Candidate, finding.candidate_id)
    brand = session.get(Brand, finding.brand_id)
    if (finding.kind or "phishing") == "shop":
        from brandwatch.detection import shop_levels

        level, conclusion = shop_level_of(session, finding)
        return f"{shop_levels.wording(level, brand.name, conclusion)['subject']} {draft.reference}: {cand.hostname}"
    if (finding.kind or "phishing") == "social":
        return f"Account impersonating {brand.name} — report {draft.reference}: {cand.hostname}"
    return f"Phishing site impersonating {brand.name} — takedown request {draft.reference}: {cand.hostname}"


# --- Report to Meta: the ads and the advertiser pages that send buyers to a scam shop ----------------
# Opened in a real browser on 2026-10-11 before being listed. Meta's own in-product "Report ad" /
# "Report Page" flows need no special access; these forms are for the trademark owner.
META_FORMS: list[dict[str, str]] = [
    {"key": "meta_form:fb_trademark", "name": "Facebook — Trademark report form",
     "url": "https://www.facebook.com/help/contact/trademarkform",
     "note": "for the trademark owner; has a dedicated option for content offering counterfeit goods"},
    {"key": "meta_form:counterfeit", "name": "Instagram / Threads — Counterfeit report form",
     "url": "https://www.facebook.com/help/contact/counterfeitform",
     "note": "selling or promoting counterfeit goods on Instagram or Threads"},
    {"key": "meta_form:ig_trademark", "name": "Instagram — Trademark report form",
     "url": "https://help.instagram.com/contact/230197320740525",
     "note": "use of the brand name or logo on Instagram without permission"},
]  # fmt: skip


# fake social accounts: Meta's impersonation forms (both work without logging in) + the trademark forms
SOCIAL_FORMS: list[dict[str, str]] = [
    {"key": "meta_form:fb_imposter", "name": "Facebook — Report an impostor account",
     "url": "https://www.facebook.com/help/contact/295309487309948",
     "note": "a page or profile pretending to be the brand; works without a Facebook login"},
    {"key": "meta_form:ig_impersonation", "name": "Instagram — Report impersonation",
     "url": "https://help.instagram.com/contact/636276399721841",
     "note": "an Instagram or Threads account pretending to be the brand or someone you represent"},
    META_FORMS[0], META_FORMS[2],
]  # fmt: skip


def social_record_of(session: Session, finding: Finding) -> dict[str, Any]:
    cur = finding.current_score
    return dict(((cur.groups or {}).get("_breakdown") or {}).get("social") or {}) if cur else {}


def social_targets(rec: dict[str, Any]) -> list[dict[str, Any]]:
    """The account(s) to report: the Facebook page, and its linked Instagram profile."""
    out: list[dict[str, Any]] = []
    if not rec:
        return out
    ig = rec.get("ig") or {}
    if rec.get("platform") == "facebook":
        out.append({"page_id": f"facebook:{rec.get('handle')}", "page_name": rec.get("name") or rec.get("handle"),
                    "page_url": rec.get("url"), "ads": [], "platform": "facebook", "instagram": bool(ig)})  # fmt: skip
    if ig.get("username"):
        out.append({"page_id": f"instagram:{ig['username']}", "page_name": f"@{ig['username']}",
                    "page_url": ig.get("url") or f"https://www.instagram.com/{ig['username']}/", "ads": [], "platform": "instagram"})  # fmt: skip
    return out


def social_report_text(brand: str, rec: dict[str, Any], summary: str | None) -> str:
    lines = [f"This {'Facebook page' if rec.get('platform') == 'facebook' else 'Instagram account'} “{rec.get('name') or rec.get('handle')}” "
             f"({rec.get('url')}) is pretending to be {brand}. It is not an account of {brand}."]  # fmt: skip
    if summary:
        lines.append(summary)
    lines += [f"- {why}" for why in list((rec.get("why") or {}).values())[:6]]
    return "\n".join(lines)


def social_report_keys(rec: dict[str, Any]) -> set[str]:
    if not rec:
        return set()
    return {f["key"] for f in SOCIAL_FORMS} | {f"meta_page:{t['page_id']}" for t in social_targets(rec)}


def shop_record_of(session: Session, finding: Finding) -> dict[str, Any]:
    cur = finding.current_score
    return dict(((cur.groups or {}).get("_breakdown") or {}).get("shop") or {}) if cur else {}


def ads_record_of(session: Session, finding: Finding) -> dict[str, Any]:
    """The ads of an advertised phishing site, in the shape ``meta_pages`` reads (``{"ads": [...]}``)."""
    cur = finding.current_score
    ads = list(((cur.groups or {}).get("_breakdown") or {}).get("ads") or []) if cur else []
    return {"ads": ads} if ads else {}


# a phishing ad uses the brand's name: the trademark owner's forms fit; the counterfeit one does not
PHISHING_AD_FORMS: list[dict[str, str]] = [f for f in META_FORMS if f["key"] != "meta_form:counterfeit"]


def phishing_ad_report_text(brand: str, url: str, rec: dict[str, Any], summary: str | None) -> str:
    """Copy-ready text for Meta: an ad that impersonates the brand and sends people to a phishing site."""
    lines = [f"This ad uses the name of {brand} and sends people to {url}, a phishing site that is not {brand}'s. "
             f"It asks for {brand} customers' login details. Please remove the ad and the page behind it."]  # fmt: skip
    if summary:
        lines.append(summary)
    for a in (rec.get("ads") or [])[:5]:
        lines.append(f"Ad: {a.get('library_url')} — page “{a.get('page_name')}”")
    return "\n".join(lines)


def shop_level_of(session: Session, finding: Finding) -> tuple[str, dict[str, Any] | None]:
    """A shop finding's conclusion (the analyst's, else BrandWatch's reading) and the analyst's record."""
    from brandwatch.detection import shop_levels

    return shop_levels.effective_level(finding.conclusion, shop_record_of(session, finding)), finding.conclusion


def meta_pages(shop: dict[str, Any]) -> list[dict[str, Any]]:
    """The advertiser pages behind a shop, each with its ads — one "Report to Meta" row per page."""
    pages: dict[str, dict[str, Any]] = {}
    for a in shop.get("ads") or []:
        pid = str(a.get("page_id") or a.get("page_name") or "?")
        p = pages.setdefault(pid, {"page_id": pid, "page_name": a.get("page_name") or pid, "instagram": False, "ads": [],
                                   "page_url": f"https://www.facebook.com/{pid}" if pid.isdigit() else None})  # fmt: skip
        p["instagram"] = p["instagram"] or "instagram" in (a.get("platforms") or [])
        p["ads"].append(a)
    return list(pages.values())


def meta_report_text(
    brand: str, url: str, shop: dict[str, Any], summary: str | None, level: str = "suspicious_retailer",
    conclusion: dict[str, Any] | None = None,
) -> str:
    """Copy-ready text for Meta's report flows and forms — claiming only what the conclusion supports."""
    from brandwatch.detection import shop_levels

    w = shop_levels.wording(level, brand, conclusion)
    lines = [f"This ad / page sends buyers to {url}, {w['meta']}. It is not an authorised {brand} retailer."]
    if summary:
        lines.append(summary)
    for a in (shop.get("ads") or [])[:5]:
        lines.append(f"Ad: {a.get('library_url')} — page “{a.get('page_name')}”")
    return "\n".join(lines)


def meta_report_keys(shop: dict[str, Any]) -> set[str]:
    keys = {f["key"] for f in META_FORMS} if shop.get("ads") else set()
    for p in meta_pages(shop):
        keys.add(f"meta_page:{p['page_id']}")
        keys.update(f"meta_ad:{a.get('ad_id')}" for a in p["ads"] if a.get("ad_id"))
    return keys


def finding_url(session: Session, draft: TakedownDraft) -> tuple[str, str]:
    finding = session.get(Finding, draft.finding_id)
    cand = session.get(Candidate, finding.candidate_id)
    return cand.canonical_url, cand.hostname
