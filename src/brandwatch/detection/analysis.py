"""Analysis (spec §3 stage 6): turn collected evidence into fired signals (spec §5 catalogue).

Phase 1 evaluates the Identity, Visual, Behavior, Reputation and Freshness groups from evidence
the enrichment stage collected. Infrastructure and Evasion signals need pivoting / multi-probe
(Phases 4–5) and are reported as not evaluated. Every fired signal carries a plain-language
detail string — that is what "Explain Finding" shows.
"""

from __future__ import annotations

import re
from typing import Any

from rapidfuzz.distance import Levenshtein

from brandwatch.config.brand_config import ScoringConfig
from brandwatch.db.enums import ProviderStatus
from brandwatch.detection import dom, images
from brandwatch.detection import redirects as redirects_mod
from brandwatch.detection.baseline import BrandBaseline
from brandwatch.detection.discovery import SHORT_KEY, key_in, split_host
from brandwatch.detection.enrichment import CollectedEvidence
from brandwatch.detection.normalize import canonical_listing_url, is_app_store
from brandwatch.pipeline.stages import AnalysisResult

FAVICON_NEAR_MAX_DISTANCE = 6
SCREENSHOT_SIMILAR_THRESHOLD = 0.90
LOOKS_LIKE_BRAND_THRESHOLD = 0.85  # the "Looks like <brand> N%" of the finding page: above this the risk is very high
PALETTE_MATCH_THRESHOLD = 0.67
LOGIN_DOM_THRESHOLD = 0.80
REPUTATION_SIGNALS = {
    "virustotal": "vt_flagged",
    "urlhaus": "urlhaus_listed",
    "phishtank": "phishtank_listed",
    "safebrowsing": "safe_browsing",
}
NOT_EVALUATED_PHASE1: tuple[str, ...] = ()  # every group is evaluated from Phase 5 on


_AUTH_PATH = re.compile(
    r"(log-?in|sign-?in|sign-?up|register|verify|secure|my-?account|password|wallet)"
)


def _is_official_app(url: str, official: tuple[str, ...]) -> bool:
    clean = canonical_listing_url(url)
    return any(clean == canonical_listing_url(o) for o in official)


def analyze(ev: CollectedEvidence, baseline: BrandBaseline, cfg: ScoringConfig) -> AnalysisResult:
    fired: dict[str, float] = {}
    details: dict[str, str] = {}
    fp_flags: list[str] = []

    def fire(signal: str, why: str) -> None:
        points = cfg.weights.get(signal)
        if points is None or points <= 0:
            return
        fired[signal] = float(points)
        details[signal] = why

    key = baseline.brand_key
    parts = split_host(ev.host)
    sld = parts.sld
    subdomain = parts.subdomain
    path = ev.url.split("/", 3)[3].lower() if ev.url.count("/") >= 3 else ""

    # --- Identity -----------------------------------------------------------------------------
    if key and key_in(key, sld):
        if sld == key:
            fire(
                "brand_exact_in_domain", f"registrable label '{sld}' is exactly the brand ('{key}')"
            )
        else:
            fire("brand_exact_in_domain", f"brand '{key}' appears inside the domain label '{sld}'")
            fire("combosquat", f"'{sld}' combines the brand with extra words")
    elif key and len(key) >= SHORT_KEY:  # a 2-letter key is 1-2 edits from half the dictionary
        dist = Levenshtein.distance(sld, key)
        if 0 < dist <= 2:
            fire("levenshtein_le_2", f"'{sld}' is {dist} edit(s) from '{key}'")
    if ev.host.startswith("xn--") or any(label.startswith("xn--") for label in ev.host.split(".")):
        try:
            unicode_host = ev.host.encode("ascii").decode("idna")
        except Exception:  # noqa: BLE001
            unicode_host = ev.host
        fire("homoglyph_idn", f"IDN hostname {ev.host} renders as '{unicode_host}'")
    official_regs = {split_host(d).registrable for d in baseline.official_domains}
    final_host = (
        (ev.final_url or ev.url).split("/")[2].lower() if "://" in (ev.final_url or ev.url) else ""
    )
    redirects_home = bool(final_host) and split_host(final_host).registrable in official_regs
    if redirects_home and split_host(ev.host).registrable not in official_regs:
        rf = redirects_mod.facts(ev.host, list(ev.redirect_chain), ev.final_url or ev.url, {d.lower() for d in baseline.official_domains})
        if rf.affiliate:
            fire("affiliate_redirect", f"the visit ends on the brand's own site after a link with {', '.join(rf.affiliate)}: the commission goes to the owner of that id")
        if rf.via:
            fire("redirect_via_third_party", f"the visit goes through {', '.join(rf.via)} on its way to the brand's own site: the destination can be changed at any time")
        fp_flags.append("redirects_to_official")  # the page captured is the real site's: whatever it looks like says nothing about the look-alike
        details["redirects_to_official"] = (
            f"ends on the brand's own site ({final_host}), so the page is the real one and its look is not counted"
            + (" — an affiliate id or a third-party redirect host in the chain is still rated" if rf.affiliate or rf.via else " — likely the brand's own registration")
        )
    if key and sld == key and parts.registrable not in official_regs and not redirects_home:
        fire(
            "brand_tld_swap",
            f"the domain is exactly the brand name on another TLD (.{parts.suffix})",
        )
    if key and not redirects_home and ev.features is not None and not is_app_store(ev.host):
        title_l = (ev.features.title or "").lower()
        title_n = re.sub(r"[^a-z0-9]", "", title_l)
        if len(key) < SHORT_KEY:
            claims = title_n == key or bool(
                re.match(r"\W*" + re.escape(key) + r"(?![a-z])", title_l)
                or re.search(r"(?<![a-z])" + re.escape(key) + r"\W*$", title_l)
            )
        else:
            claims = title_n == key or title_n.startswith(key) or title_n.endswith(key)
        if title_n and claims:
            fire(
                "title_claims_brand",
                f"the page calls itself the brand: <title>{(ev.features.title or '')[:60]}</title>",
            )
    if key and subdomain and key_in(key, subdomain):
        fire("brand_in_subdomain", f"brand '{key}' appears in subdomain '{subdomain}'")
    if key and path and key_in(key, path):
        fire("brand_in_path", f"brand '{key}' appears in the URL path")
    if path and _AUTH_PATH.search(path):
        fire("auth_path_in_url", f"URL path looks like a login / sign-up page: /{path[:40]}")

    # --- App-store / APK listings: the listing text is the identity, not the store's domain ---
    if is_app_store(ev.host):
        details["app_listing"] = f"{ev.host} is an app store / APK site; judged by the listing"
        page_url = ev.final_url or ev.url
        if _is_official_app(page_url, baseline.official_apps):
            fp_flags.append("official_app_listing")
            details["official_app_listing"] = "this listing is linked from the brand's own site"
        elif ev.features is not None and key:
            def named(t: str | None) -> bool:  # a short key must stand as a word in the listing
                if len(key) < SHORT_KEY:
                    return key_in(key, (t or "").lower())
                return key in (t or "").lower().replace(" ", "").replace("-", "")

            if named(ev.features.title):
                fire("app_listing_brand_title",
                     f"app listing title carries the brand: '{(ev.features.title or '')[:80]}'")  # fmt: skip
            if named(ev.features.meta_description):
                fire("app_listing_brand_description",
                     "the listing's meta description mentions the brand")  # fmt: skip

    # --- Visual --------------------------------------------------------------------------------
    if ev.favicon_mmh3 is not None and baseline.favicon_mmh3 is not None:
        if ev.favicon_mmh3 == baseline.favicon_mmh3:
            fire("favicon_exact", f"favicon mmh3 {ev.favicon_mmh3} equals the brand's favicon hash")
        elif ev.favicon_phash and baseline.favicon_phash:
            d = images.hamming(ev.favicon_phash, baseline.favicon_phash)
            if d <= FAVICON_NEAR_MAX_DISTANCE:
                fire("favicon_phash_near", f"favicon pHash within {d} bits of the brand's favicon")
    references = [
        (baseline.screenshot_phash, baseline.screenshot_dhash, "homepage"),
        (baseline.login_screenshot_phash, baseline.login_screenshot_dhash, "login page"),
    ]
    best: tuple[float, str] | None = None
    for ref_phash, ref_dhash, label in references:
        if not (ev.screenshot_phash and ref_phash):
            continue
        sim = images.similarity(ev.screenshot_phash, ref_phash)
        if ev.screenshot_dhash and ref_dhash:
            sim = (sim + images.similarity(ev.screenshot_dhash, ref_dhash)) / 2
        if best is None or sim > best[0]:
            best = (sim, label)
    shown = (  # the number the finding page shows: this picture against the brand's homepage (pHash)
        images.similarity(ev.screenshot_phash, baseline.screenshot_phash) if ev.screenshot_phash and baseline.screenshot_phash else None
    )
    if best is not None or shown is not None:
        looks = max(best[0] if best else 0.0, shown or 0.0)
        if looks >= LOOKS_LIKE_BRAND_THRESHOLD and not redirects_home:
            fire("looks_like_brand_ge_85", f"the page looks {looks:.0%} like {baseline.brand_key}'s real site: above 85% the risk is very high")
    if best is not None:
        sim, matched = best
        details["screenshot_similarity"] = f"{sim:.0%} (vs {matched})"
        if sim >= SCREENSHOT_SIMILAR_THRESHOLD:
            fire(
                "screenshot_similarity_ge_90",
                f"homepage screenshot is {sim:.0%} similar to the brand's (pHash)",
            )

    if ev.palette and baseline.palette and ev.screenshot_phash:
        psim = dom.palette_similarity(
            dom.palette_from_hex(ev.palette), dom.palette_from_hex(list(baseline.palette))
        )
        details["palette_similarity"] = f"{psim:.0%}"
        if psim >= PALETTE_MATCH_THRESHOLD:
            fire("palette_match", f"{psim:.0%} of the page's dominant colours match the brand's")
    if ev.login_signature and baseline.login_signature and "input:password" in ev.login_signature:
        dsim = dom.dom_similarity(ev.login_signature, list(baseline.login_signature))
        details["login_dom_similarity"] = f"{dsim:.0%}"
        if dsim >= LOGIN_DOM_THRESHOLD:
            fire(
                "login_dom_similarity", f"login form markup is {dsim:.0%} identical to the brand's"
            )

    # --- Behavior ------------------------------------------------------------------------------
    f = ev.features
    if f is not None:
        if f.credential_form:
            fire("credential_form", "page contains a password field")
        if f.payment_form:
            fire("payment_form", "page asks for card number / CVV / expiry")
        if f.seed_phrase_field:
            fire("seed_phrase_field", "page asks for a wallet seed / recovery phrase")
        if f.brand_keywords:
            fire(
                "brand_keywords_in_content",
                f"brand terms in content: {', '.join(f.brand_keywords[:5])}",
            )
        if f.lure_terms:
            fire("lure_language", f"lure phrases: {'; '.join(f.lure_terms[:3])}")
        if f.external_form_action:
            targets = sorted({x.action for x in f.forms if x.external_action and x.action})
            fire(
                "external_form_action",
                f"credential/payment form posts to another host: {targets[0] if targets else '?'}",
            )
        if f.password_prefill:
            fire("password_prefill", "login form arrives with the victim's e-mail pre-filled")

    # --- Infrastructure (links computed by the runner from campaigns / confirmed findings) ----
    for signal, why in ev.infra_links.items():
        fire(signal, why)
    if ev.redirected_from:  # a look-alike that is already rated High sends its visitors to this address
        src = ev.redirected_from
        fire("redirect_from_suspect", f"{src.get('host')} (rated {str(src.get('severity') or 'high').upper()}) redirects its visitors here: "
                                      "the same operator, so the same verdict")  # fmt: skip

    # --- Behaviour: the page asks the visitor to run a command (ClickFix) ------------------------
    if ev.clickfix:
        fire("clickfix_lure", f"{ev.clickfix['reason']}" + (f" ({'; '.join(ev.clickfix.get('indicators') or [])})" if ev.clickfix.get("indicators") else ""))

    # --- Evasion (Phase 5 cloaking multi-probe) ----------------------------------------------
    for signal, why in ev.cloaking_signals.items():
        fire(signal, why)
    if ev.scanner_block:  # HTTP 403 / a bot check: the site refuses automated visitors
        vendor = f" ({ev.scanner_block['vendor']})" if ev.scanner_block.get("vendor") else ""
        fire("bot_blocking", f"the site refuses automated visitors: HTTP {ev.scanner_block.get('status')}{vendor}")

    # --- Reputation (UNKNOWN never counts as clean) ---------------------------------------------
    positives = 0
    for provider, status in ev.reputation.items():
        signal = REPUTATION_SIGNALS.get(provider)
        if status is ProviderStatus.POSITIVE:
            positives += 1
            if signal:
                fire(signal, f"{provider} flags this host as malicious")
    if f is not None and f.cloudflare_phish_warning:
        positives += 1
        fire("cloudflare_phishing_warning",
             "Cloudflare, which serves this site, shows its own “Suspected Phishing” warning instead of the site")  # fmt: skip
    # a verdict somebody else already made: a security product's warning page, or a blocklist's phishing entry
    verdicts: list[str] = []
    if ev.security_warning:
        verdicts.append(f"{ev.security_warning.get('vendor')}: {ev.security_warning.get('reason')}")
    detail = ev.reputation_detail
    if "SOCIAL_ENGINEERING" in ((detail.get("safebrowsing") or {}).get("threats") or []):
        verdicts.append("Google Safe Browsing lists it as social engineering (phishing)")
    if ev.reputation.get("phishtank") is ProviderStatus.POSITIVE:
        verdicts.append("PhishTank lists it")
    engines = (detail.get("virustotal") or {}).get("phishing_engines") or []
    if len(engines) >= 3:
        verdicts.append(f"{len(engines)} VirusTotal engines call it phishing ({', '.join(engines[:4])})")
    if verdicts:
        if not ev.security_warning:
            positives += 1  # a warning page was already counted; a blocklist verdict is another independent voice
        fire("known_phishing", "already flagged as phishing — " + "; ".join(verdicts))

    # --- Freshness ------------------------------------------------------------------------------
    age = ev.whois_age_days
    if age is not None:
        if age < 7:
            fire("age_lt_7d", f"domain registered {age} day(s) ago")
        if age < 30:  # cumulative; the Freshness cap bounds the total
            fire("age_lt_30d", f"domain registered {age} days ago")
        elif age > 730 and positives:
            # an old domain reassures only while nobody flags it: a blocklisted one gets no discount
            details["age_gt_2y"] = (f"domain is {age // 365} years old — no false-positive discount, "
                                    "because a blocklist already flags it")  # fmt: skip
        elif age > 730:
            fp_flags.append("age_gt_2y")
            details["age_gt_2y"] = f"domain is {age // 365} years old (false-positive penalty)"

    if "woke_up" in ev.triggers:
        fire("woke_up_in_watch", "candidate was parked/dead on the watchlist and came alive")

    unavailable = tuple(sorted(set(ev.unavailable)))
    info: dict[str, Any] = {
        "signals": details,
        "not_evaluated_groups": list(NOT_EVALUATED_PHASE1),
        "screenshot_captured": ev.screenshot_phash is not None,
        "html_captured": bool(ev.html),
        "whois_age_days": age,
        "reputation_positives": positives,
        "reputation": {k: v.value for k, v in ev.reputation.items()},
        "provider_notes": dict(ev.provider_notes),
        "favicon_mmh3": ev.favicon_mmh3,
        "baseline_version": baseline.version,
        "triggers": list(ev.triggers),
        "cloaking": ev.cloaking_summary or None,
        "scanner_block": ev.scanner_block,
        "security_warning": ev.security_warning,  # the verdict page: its vendor and why; the page itself was not studied further
        "snapshot": ev.snapshot,  # screenshot / title are urlscan.io's, because the live site refused the scan
        "challenge": ev.challenge,  # who was shown a bot check, what it looked like, why that visitor
        "clickfix": ev.clickfix,  # the lure: kind, reason, what gave it away
        "no_picture": ev.no_picture,  # the page was blank and urlscan.io has no picture: where it leads instead
        "redirected_from": ev.redirected_from,  # the flagged look-alike that sends its visitors here: {host, severity, finding_id}
    }
    return AnalysisResult(
        signals=fired,
        evidence_refs=ev.evidence_refs,
        unavailable=unavailable,
        fp_flags=tuple(fp_flags),
        details=info,
    )
