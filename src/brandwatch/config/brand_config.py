"""Per-brand detection / economic / scoring configuration (spec §5, §13).

Phase 0 ships only what Phase 1 needs: ``scoring.{group_caps, weights, thresholds,
combination_rules, fp_penalties}``, ``economic_limits`` and a minimal ``detection`` block.
``extra="forbid"`` everywhere means a brand config can never smuggle in a security limit
(``MAX_RESPONSE_SIZE`` etc.) — those live in :mod:`brandwatch.security.limits` only.

Weights and caps below are the spec's illustrative values; they get calibrated against the
golden dataset (spec §18) in Phase 1.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from brandwatch.config.settings import EconomicLimits
from brandwatch.db.enums import Severity

SCORING_VERSION = "v7"  # v7 (2026-10-13): + affiliate_redirect and redirect_via_third_party (a look-alike that ends on the brand's own site is not a phishing page, but an affiliate id or a third-party redirect host in the chain is still abuse); v6 (2026-10-13): + looks_like_brand_ge_85 (looks at least 85% like the brand: Critical); v5 (2026-10-13): + clickfix_lure (a fake verification that makes the visitor run a command); v4: + redirect_from_suspect; v3: + known_phishing
# what each catalogue revision added — merged into a brand's saved scoring snapshot when it loads,
# so a signal added later is not silently weight 0 for brands created before it
CATALOGUE_ADDITIONS: dict[str, Any] = {
    "rev": "c7",
    "weights": {"cloudflare_phishing_warning": 15, "known_phishing": 15, "redirect_from_suspect": 20, "clickfix_lure": 30,
                "looks_like_brand_ge_85": 8, "device_gating": 14, "affiliate_redirect": 25, "redirect_via_third_party": 20},
    "rules": ["cloudflare_flagged_lookalike", "cloudflare_flagged_typo", "known_phishing_verdict", "redirect_from_flagged_site",
              "clickfix_lure_verdict", "looks_like_brand_verdict", "affiliate_redirect_verdict", "redirect_service_verdict"],
}
RAW_SCORE_MAX = 150  # Σ group caps; score = round(raw / RAW_SCORE_MAX * 100)

# signal -> group  (spec §5 signal catalogue)
SIGNAL_GROUPS: dict[str, str] = {
    # Identity — pretending by name
    "brand_exact_in_domain": "identity",
    "brand_tld_swap": "identity",
    "title_claims_brand": "behavior",
    "brand_in_subdomain": "identity",
    "brand_in_path": "identity",
    "app_listing_brand_title": "identity",
    "app_listing_brand_description": "identity",
    "homoglyph_idn": "identity",
    "combosquat": "identity",
    "levenshtein_le_2": "identity",
    # Visual — looks like the brand
    "favicon_exact": "visual",
    "favicon_phash_near": "visual",
    "logo_detected": "visual",
    "screenshot_similarity_ge_90": "visual",
    "looks_like_brand_ge_85": "visual",
    "login_dom_similarity": "visual",
    "palette_match": "visual",
    # Behavior — acts like phishing
    "credential_form": "behavior",
    "payment_form": "behavior",
    "seed_phrase_field": "behavior",
    "clickfix_lure": "behavior",
    "brand_keywords_in_content": "behavior",
    "auth_path_in_url": "behavior",
    "lure_language": "behavior",
    "external_form_action": "behavior",
    "password_prefill": "behavior",
    # Infrastructure — suspicious / linked hosting
    "bad_reputation_asn": "infrastructure",
    "cohosted_with_known_phish": "infrastructure",
    "cert_shared_with_phish": "infrastructure",
    "tracking_id_shared": "infrastructure",
    "linked_to_known_campaign": "infrastructure",
    "redirect_from_suspect": "infrastructure",
    "affiliate_redirect": "behavior",  # the visit ends on the brand's own site after a link with an affiliate id: the commission goes to a stranger
    "redirect_via_third_party": "infrastructure",  # ... through a host that can send the visitor anywhere tomorrow
    # Reputation — others flag it ("not listed" = unknown → 0, never negative)
    "vt_flagged": "reputation",
    "cloudflare_phishing_warning": "reputation",
    "known_phishing": "reputation",
    "urlhaus_listed": "reputation",
    "phishtank_listed": "reputation",
    "safe_browsing": "reputation",
    # Freshness — fresh throwaway
    "age_lt_7d": "freshness",
    "age_lt_30d": "freshness",
    "cert_age_lt_7d": "freshness",
    "woke_up_in_watch": "freshness",
    # Evasion — actively hiding (strongest tell)
    "cloaking_ip_based": "evasion",
    "cloaking_ua_based": "evasion",
    "parameter_gating": "evasion",
    "referer_gating": "evasion",
    "device_gating": "evasion",
    "bot_blocking": "evasion",
}

DEFAULT_GROUP_CAPS: dict[str, int] = {
    "identity": 20,
    "visual": 30,
    "behavior": 30,
    "infrastructure": 20,
    "reputation": 15,
    "freshness": 10,
    "evasion": 25,
}

DEFAULT_WEIGHTS: dict[str, int] = {
    "brand_exact_in_domain": 12,
    "brand_tld_swap": 20,  # the registrable label IS the brand, on a TLD the brand does not use
    "title_claims_brand": 10,  # the page's <title> presents itself as the brand
    "brand_in_subdomain": 10,
    "brand_in_path": 8,
    "app_listing_brand_title": 16,  # an app-store / APK listing named after the brand
    "app_listing_brand_description": 10,
    "homoglyph_idn": 10,
    "combosquat": 8,
    "levenshtein_le_2": 8,
    "favicon_exact": 22,
    "favicon_phash_near": 14,
    "logo_detected": 12,
    "screenshot_similarity_ge_90": 18,
    "looks_like_brand_ge_85": 8,  # the rule below floors the severity at Critical
    "login_dom_similarity": 12,
    "palette_match": 5,
    "credential_form": 14,
    "payment_form": 12,
    "seed_phrase_field": 25,
    "clickfix_lure": 30,  # asks the visitor to run a command; the rule below floors the severity at High
    "brand_keywords_in_content": 6,
    "auth_path_in_url": 4,  # /login, /signup, /verify … in the candidate URL
    "lure_language": 6,
    "external_form_action": 12,
    "password_prefill": 10,
    "bad_reputation_asn": 6,
    "cohosted_with_known_phish": 15,
    "cert_shared_with_phish": 12,
    "tracking_id_shared": 15,
    "linked_to_known_campaign": 15,
    "affiliate_redirect": 25,  # ends on the brand's own site with an affiliate id: not phishing, but the brand pays commission on its own traffic; floored at Medium
    "redirect_via_third_party": 20,  # ends on the brand's own site through a third-party redirect host: the destination can be swapped for a phishing page; floored at High
    "redirect_from_suspect": 20,  # a site BrandWatch already rated High sends its visitors here; the rule below floors this one at High
    "vt_flagged": 12,
    "cloudflare_phishing_warning": 15,
    "known_phishing": 15,  # a security service already says phishing; the rule below floors the severity at High
    "urlhaus_listed": 12,
    "phishtank_listed": 10,
    "safe_browsing": 10,
    "age_lt_7d": 10,
    "age_lt_30d": 6,
    "cert_age_lt_7d": 5,
    "woke_up_in_watch": 8,
    "cloaking_ip_based": 25,
    "cloaking_ua_based": 18,
    "parameter_gating": 12,
    "referer_gating": 8,
    "device_gating": 14,  # the lure is shown to a mobile phone only
    "bot_blocking": 8,
}

DEFAULT_FP_PENALTIES: dict[str, int] = {
    "age_gt_2y": 15,
    "redirects_to_official": 60,  # the brand's own defensive registration
    "ev_cert_matches_brand": 10,
    "hosted_on_brand_asn_or_cdn": 20,
    "whois_registrant_is_brand": 20,
}


# Decisive clusters: all signals fired together → +high_confidence_bonus (spec §5).
DEFAULT_HIGH_CONFIDENCE_CLUSTERS: tuple[tuple[str, ...], ...] = (
    ("favicon_exact", "credential_form", "brand_exact_in_domain"),
    ("favicon_exact", "credential_form", "levenshtein_le_2"),
    ("favicon_exact", "credential_form", "homoglyph_idn"),
    ("favicon_exact", "login_dom_similarity", "cloaking_ip_based"),
    ("screenshot_similarity_ge_90", "credential_form", "external_form_action"),
)


class Thresholds(BaseModel):
    """Severity bands on the normalized 0–100 score (spec §5)."""

    model_config = ConfigDict(extra="forbid")

    medium: int = Field(default=25, ge=1, le=100)
    high: int = Field(default=50, ge=1, le=100)
    critical: int = Field(default=75, ge=1, le=100)

    @model_validator(mode="after")
    def _monotonic(self) -> Thresholds:
        if not (self.medium < self.high < self.critical):
            raise ValueError("thresholds must satisfy medium < high < critical")
        return self

    def severity_for(self, score: int) -> Severity:
        if score >= self.critical:
            return Severity.CRITICAL
        if score >= self.high:
            return Severity.HIGH
        if score >= self.medium:
            return Severity.MEDIUM
        return Severity.LOW


class CombinationRule(BaseModel):
    """If every listed signal fired, severity is floored at ``min_severity``."""

    model_config = ConfigDict(extra="forbid")

    name: str
    signals_all: list[str] = Field(min_length=1)  # one signal is enough for a verdict somebody else already made
    min_severity: Severity


DEFAULT_COMBINATION_RULES: list[CombinationRule] = [
    CombinationRule(
        name="pixel_clone_login",
        signals_all=["favicon_exact", "screenshot_similarity_ge_90", "credential_form"],
        min_severity=Severity.CRITICAL,
    ),
    CombinationRule(
        name="cloaked_clone",
        signals_all=["favicon_exact", "cloaking_ip_based", "credential_form"],
        min_severity=Severity.CRITICAL,
    ),
    CombinationRule(
        name="fresh_lookalike_login",
        signals_all=["screenshot_similarity_ge_90", "credential_form", "age_lt_30d"],
        min_severity=Severity.HIGH,
    ),
    CombinationRule(
        name="crypto_seed_harvest",
        signals_all=["seed_phrase_field", "brand_exact_in_domain"],
        min_severity=Severity.CRITICAL,
    ),
    CombinationRule(
        name="exact_brand_impersonation",
        signals_all=["brand_tld_swap", "title_claims_brand"],
        min_severity=Severity.HIGH,
    ),
    CombinationRule(
        name="exact_brand_login",
        signals_all=["brand_tld_swap", "credential_form"],
        min_severity=Severity.CRITICAL,
    ),
    CombinationRule(
        name="brand_title_login",
        signals_all=["title_claims_brand", "credential_form"],
        min_severity=Severity.HIGH,
    ),
    CombinationRule(
        name="campaign_linked_login",
        signals_all=["linked_to_known_campaign", "credential_form"],
        min_severity=Severity.HIGH,
    ),
    # Cloudflare, an antivirus, a DNS filter or a blocklist already says phishing: nobody needs to open the page first
    CombinationRule(
        name="known_phishing_verdict",
        signals_all=["known_phishing"],
        min_severity=Severity.HIGH,
    ),
    # a page that looks (almost) exactly like the brand's own site: whatever else is known, the risk is very high
    CombinationRule(
        name="looks_like_brand_verdict",
        signals_all=["looks_like_brand_ge_85"],
        min_severity=Severity.CRITICAL,
    ),
    # the page itself tries to make the visitor run a command: malware delivery, whatever it is called
    CombinationRule(
        name="clickfix_lure_verdict",
        signals_all=["clickfix_lure"],
        min_severity=Severity.HIGH,
    ),
    # a look-alike that ends on the brand's own site, but with an affiliate id: not phishing, still worth a report
    CombinationRule(
        name="affiliate_redirect_verdict",
        signals_all=["affiliate_redirect"],
        min_severity=Severity.MEDIUM,
    ),
    # ... or through a third-party redirect host: it can send the visitor anywhere tomorrow
    CombinationRule(
        name="redirect_service_verdict",
        signals_all=["redirect_via_third_party"],
        min_severity=Severity.HIGH,
    ),
    # a look-alike that is already High redirects its visitors here, and this address carries the brand: the same operator
    CombinationRule(
        name="redirect_from_flagged_site",
        signals_all=["redirect_from_suspect"],
        min_severity=Severity.HIGH,
    ),
    # the CDN in front of the site already blocks it as phishing, and its name carries the brand
    CombinationRule(
        name="cloudflare_flagged_lookalike",
        signals_all=["brand_exact_in_domain", "cloudflare_phishing_warning"],
        min_severity=Severity.HIGH,
    ),
    CombinationRule(
        name="cloudflare_flagged_typo",
        signals_all=["levenshtein_le_2", "cloudflare_phishing_warning"],
        min_severity=Severity.HIGH,
    ),
]


class ScoringConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = SCORING_VERSION
    group_caps: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_GROUP_CAPS))
    weights: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    thresholds: Thresholds = Field(default_factory=Thresholds)
    combination_rules: list[CombinationRule] = Field(
        default_factory=lambda: list(DEFAULT_COMBINATION_RULES)
    )
    high_confidence_bonus: int = Field(default=15, ge=0)  # per decisive cluster
    high_confidence_bonus_cap: int = Field(default=15, ge=0)  # total cap
    high_confidence_clusters: list[list[str]] = Field(
        default_factory=lambda: [list(c) for c in DEFAULT_HIGH_CONFIDENCE_CLUSTERS]
    )
    fp_penalties: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_FP_PENALTIES))
    finding_min_severity: Severity = Severity.MEDIUM  # below this → watchlist, no Finding

    @model_validator(mode="before")
    @classmethod
    def _upgrade_saved(cls, data: Any) -> Any:
        """A brand's saved snapshot from an older catalogue. Untouched defaults ("v1") become today's
        defaults; a customised config keeps every value it set and gains what the catalogue added
        since (default weight, new rules), with the revision appended to its version."""
        if not isinstance(data, dict) or not data:
            return data
        version = str(data.get("version") or "")
        if version == "v1":
            return {}
        rev = CATALOGUE_ADDITIONS["rev"]
        if version == SCORING_VERSION or version.endswith(f"+{rev}") or "weights" not in data:
            return data
        out = dict(data)
        weights = dict(out.get("weights") or {})
        added = [k for k in CATALOGUE_ADDITIONS["weights"] if k not in weights]
        for k in added:
            weights[k] = CATALOGUE_ADDITIONS["weights"][k]
        out["weights"] = weights
        rules = list(out.get("combination_rules") or [])
        names = {(r.get("name") if isinstance(r, dict) else r.name) for r in rules}
        new_rules = [r for r in DEFAULT_COMBINATION_RULES if r.name in CATALOGUE_ADDITIONS["rules"] and r.name not in names]
        if "combination_rules" in out:
            out["combination_rules"] = rules + [r.model_dump(mode="json") for r in new_rules]
        if added or new_rules:
            out["version"] = f"{version or 'v1'}+{rev}"[:32]
        return out

    @model_validator(mode="after")
    def _consistent(self) -> ScoringConfig:
        for name, w in self.weights.items():
            if w < 0:
                raise ValueError(f"weight for '{name}' must be >= 0")
            if name not in SIGNAL_GROUPS:
                raise ValueError(f"unknown signal '{name}'")
        for group, cap in self.group_caps.items():
            if group not in DEFAULT_GROUP_CAPS:
                raise ValueError(f"unknown signal group '{group}'")
            if cap <= 0:
                raise ValueError(f"group cap for '{group}' must be > 0")
        missing = set(DEFAULT_GROUP_CAPS) - set(self.group_caps)
        if missing:
            raise ValueError(f"group_caps missing: {sorted(missing)}")
        for rule in self.combination_rules:
            unknown = [s for s in rule.signals_all if s not in SIGNAL_GROUPS]
            if unknown:
                raise ValueError(f"rule '{rule.name}' references unknown signals {unknown}")
        for cluster in self.high_confidence_clusters:
            unknown = [x for x in cluster if x not in SIGNAL_GROUPS]
            if len(cluster) < 2 or unknown:
                raise ValueError(f"invalid high-confidence cluster {cluster}: {unknown}")
        for name, p in self.fp_penalties.items():
            if p < 0:
                raise ValueError(f"fp penalty for '{name}' must be >= 0")
        return self

    @property
    def raw_max(self) -> int:
        return sum(self.group_caps.values())


class DetectionConfig(BaseModel):
    """Minimal Phase-0/1 detection knobs. Presets and the full settings UI come later."""

    model_config = ConfigDict(extra="forbid")

    streams: list[str] = Field(default_factory=lambda: ["dnstwist"])
    # Facebook pages / Instagram profiles under the brand's name (detection/social.py); on for every
    # track — it runs only when the SearchApi key is set (recorded accounts in demo mode)
    social_accounts: bool = True
    # phishing ads for a brand nobody else sells (a bank, a payment app): Facebook / Instagram ads that use the brand's
    # name and send people to a site that is not the brand's. Off until switched on per brand (paid: SearchApi); a
    # retail brand's ads are always searched, for scam shops
    phishing_ads: bool = False
    # what ChatGPT / Gemini / Google AI Mode tell users about the brand's contacts (detection/ai_answers.py): off
    # until switched on per brand; runs with approved prompts and the SearchApi key (recorded answers in demo mode)
    ai_answers: bool = False
    ai_engines: list[Literal["chatgpt", "gemini", "google_ai_mode"]] = Field(
        default_factory=lambda: ["chatgpt", "gemini", "google_ai_mode"], max_length=3
    )
    ai_prompts_max: int = Field(default=8, ge=1, le=20)  # approved prompts asked per run (x every engine)
    contacts_pages_max: int = Field(default=40, ge=1, le=150)  # official pages read for the brand's real contacts
    tlds: Literal["common", "popular", "all"] = "common"
    max_candidates: int = Field(default=500, ge=1)
    # look-alike names checked in DNS per scan (best first: keyword combinations, other TLDs,
    # typos; exotic international homoglyphs last)
    max_names_checked: int = Field(default=3000, ge=1, le=100_000)
    watch_window_days: int = Field(default=7, ge=1, le=90)
    watch_cadence_hours: int = Field(default=24, ge=1, le=24 * 7)
    scan_interval_hours: int = Field(default=24, ge=1, le=24 * 30)  # scheduled brand scans
    long_watch_multiplier: int = Field(default=3, ge=1, le=12)  # expire after N × watch window
    search_geo: str = "us"
    search_lang: str = "en"
    # [{"country": "us", "langs": ["en", "es"]}, …]: each country with the languages it is searched in. When set, it decides; search_geo
    # and search_lang are kept in step with it (the countries, the first language). See ``detection/markets.py``.
    search_markets: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("search_markets", mode="before")
    @classmethod
    def _clean_markets(cls, v: Any) -> Any:
        from brandwatch.detection.markets import normalize

        return normalize(v) if v else []
    cloaking_probes: bool = True  # Tier 3: bot / param / referer probes
    residential_probe: Literal["off", "gated", "always"] = "gated"  # Tier 4, budgeted
    # country the residential proxy should exit from ("" = auto from search country / language);
    # that is where the brand's users — and its phishing victims — are, so cloaking that targets
    # a region is caught
    residential_country: str = ""
    ai_second_opinion: bool = True  # advisory LLM verdict on Medium+ findings
    # when an analyst confirms a finding, map the attacker's infrastructure right away
    auto_map_on_confirm: bool = True
    # ... and investigate the site and its network (a quick lookup) and build the evidence package, so a confirmed site
    # is complete without opening it
    auto_investigate_on_confirm: bool = True
    # Google queries for the "search" stream. Empty = the AI-generated list from the baseline
    # (brand + login / sign up / support / app …, plus misspellings).
    search_queries: list[str] = Field(default_factory=list)
    search_queries_max: int = Field(default=10, ge=1, le=30)


# Three tracks. A track is a complete DetectionConfig profile; "custom" is any deviation from it.
PRESET_PROFILES: dict[str, dict[str, Any]] = {
    "basic": {
        "streams": ["dnstwist", "ct"], "tlds": "common", "max_candidates": 150, "max_names_checked": 1000,
        "watch_window_days": 7, "watch_cadence_hours": 24, "scan_interval_hours": 24,
        "cloaking_probes": True, "residential_probe": "gated", "ai_second_opinion": False,
    },
    "standard": {
        "streams": ["dnstwist", "ct", "urlscan"], "tlds": "popular", "max_candidates": 500, "max_names_checked": 3000,
        "watch_window_days": 14, "watch_cadence_hours": 12, "scan_interval_hours": 12,
        "cloaking_probes": True, "residential_probe": "gated", "ai_second_opinion": True,
    },
    "enterprise": {
        "streams": ["dnstwist", "ct", "nrd", "search", "urlscan"], "tlds": "all",
        "max_candidates": 1500, "max_names_checked": 20000, "watch_window_days": 30, "watch_cadence_hours": 6,
        "scan_interval_hours": 6, "cloaking_probes": True, "residential_probe": "always",
        "ai_second_opinion": True,
    },
}  # fmt: skip
PRESET_INFO: dict[str, dict[str, str]] = {
    "basic": {
        "label": "Light", "tagline": "fast · free",
        "blurb": "Look-alike domains and certificate logs only, common TLDs. Free cloaking "
                 "probes stay on; no paid search, no AI. A few minutes, about $0.",
    },
    "standard": {
        "label": "Standard", "tagline": "recommended",
        "blurb": "Adds the urlscan archive, cloaking probes and an AI second opinion on "
                 "Medium+ findings. Re-checks the watchlist twice a day.",
    },
    "enterprise": {
        "label": "Deep", "tagline": "maximum coverage",
        "blurb": "Every stream incl. Google search and new-domain feeds, all TLDs, residential "
                 "re-fetch for cloaked kits, 6-hour cadence. Uses paid API credits.",
    },
}  # fmt: skip


def detection_for_preset(preset: str) -> DetectionConfig:
    return DetectionConfig.model_validate(PRESET_PROFILES.get(preset, PRESET_PROFILES["basic"]))


# switches of the brand itself, not of its track: changing them is not "custom", changing the track keeps them
BRAND_SWITCHES = ("social_accounts", "phishing_ads", "ai_answers", "ai_engines", "ai_prompts_max", "contacts_pages_max")


def is_custom_detection(preset: str, detection: DetectionConfig) -> bool:
    """True when the brand deviates from its track (the UI then shows the full parameter set)."""
    return detection.model_dump(exclude=set(BRAND_SWITCHES)) != detection_for_preset(preset).model_dump(exclude=set(BRAND_SWITCHES))


class BrandConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preset: Literal["basic", "standard", "enterprise"] = "basic"
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    economic_limits: EconomicLimits = Field(default_factory=EconomicLimits)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)

    @classmethod
    def for_preset(cls, preset: str) -> BrandConfig:
        """A brand config whose detection profile is the track's (scoring stays the calibrated default)."""
        return cls(preset=preset, detection=detection_for_preset(preset))  # type: ignore[arg-type]
