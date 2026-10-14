"""Discovery, Phase 1: dnstwist permutations of the brand's official domains (spec §3 stage 1,
§8 "domain name" surface). CT / NRD / search / urlscan sources arrive in Phase 3.

Pure: no network. dnstwist is used as a permutation *library* only; resolution happens later in
the enrichment stage through the provider layer (so demo mode stays deterministic).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

import tldextract

from brandwatch.db.enums import DiscoverySource, Surface
from brandwatch.pipeline.stages import DiscoveryHit

# Lexicon for combosquats ("shopnova-login.com", "secure-shopnova.com"). Spec §9 vertical
# profiles will extend this per vertical; Phase 1 ships a generic set.
DEFAULT_DICTIONARY: tuple[str, ...] = (
    "login", "signin", "secure", "verify", "account", "accounts", "support", "help", "my",
    "online", "pay", "payment", "billing", "service", "center", "store", "shop", "outlet",
    "deals", "official", "update", "auth", "portal", "app", "mail", "signup", "register",
    "trading", "bot", "wallet", "exchange", "bonus", "promo", "download", "apk", "password",
    "reset", "web", "io", "pro", "plus", "team", "club", "vip",
)  # fmt: skip

TLD_SETS: dict[str, tuple[str, ...]] = {
    "common": ("com", "net", "org", "co", "io", "info", "shop", "online", "site", "xyz", "top", "store"),
    "popular": ("com", "net", "org", "co", "io", "info", "shop", "online", "site", "xyz", "top",
                "store", "biz", "us", "uk", "de", "fr", "es", "it", "nl", "ru", "cn", "in", "br",
                "app", "dev", "cloud", "live", "me", "tv", "cc", "ws", "club", "link", "vip"),
}  # fmt: skip

# tldextract without network: bundled public-suffix snapshot only.
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


def _snapshot_tlds() -> tuple[str, ...]:
    """Every single-label ASCII top-level domain in the bundled public-suffix snapshot (~1,300)."""
    return tuple(sorted(t for t in _extract.tlds if "." not in t and t.isascii() and t.isalpha()))


# "all": the popular set first, then every other TLD that exists — used by the Deep track.
TLD_SETS["all"] = TLD_SETS["popular"] + tuple(
    t for t in _snapshot_tlds() if t not in TLD_SETS["popular"]
)


def _snapshot_tlds() -> tuple[str, ...]:
    """Every single-label ASCII top-level domain in the bundled public-suffix snapshot (~1,300)."""
    return tuple(sorted(t for t in _extract.tlds if "." not in t and t.isascii() and t.isalpha()))


# "all": the popular set first, then every other TLD that exists — used by the Deep track.
TLD_SETS["all"] = TLD_SETS["popular"] + tuple(
    t for t in _snapshot_tlds() if t not in TLD_SETS["popular"]
)


@dataclass(frozen=True, slots=True)
class RegistrableParts:
    subdomain: str
    sld: str  # second-level label ("shopnova")
    suffix: str  # public suffix ("com", "co.uk")

    @property
    def registrable(self) -> str:
        return f"{self.sld}.{self.suffix}" if self.suffix else self.sld


SHORT_KEY = 4


def key_in(key: str, text: str) -> bool:
    """Is the brand key in ``text``? A key shorter than 4 characters must stand as its own word or
    label part ("on-cloud.com", "hp support"), never inside another word ("phone", "london")."""
    if not key or not text:
        return False
    if len(key) >= SHORT_KEY:
        return key in text
    return re.search(r"(?<![a-z])" + re.escape(key) + r"(?![a-z])", text) is not None


def split_host(host: str) -> RegistrableParts:
    ext = _extract(host.lower().rstrip("."))
    return RegistrableParts(subdomain=ext.subdomain, sld=ext.domain, suffix=ext.suffix)


def permutations(
    domain: str,
    *,
    dictionary: Iterable[str] = DEFAULT_DICTIONARY,
    tlds: str | Iterable[str] = "common",
    fuzzers: Iterable[str] | None = None,
) -> list[tuple[str, str]]:
    """``[(fuzzer, permuted_domain), ...]`` for one registrable domain. Excludes the original."""
    import dnstwist

    tld_list = list(TLD_SETS[tlds]) if isinstance(tlds, str) else list(tlds)
    fuzz = dnstwist.Fuzzer(domain, dictionary=list(dictionary), tld_dictionary=tld_list)
    fuzz.generate(fuzzers=list(fuzzers) if fuzzers else [])
    out: list[tuple[str, str]] = []
    for item in fuzz.domains:
        fuzzer = str(item.get("fuzzer", "")).lower()
        permuted = str(item.get("domain", "")).lower().rstrip(".")
        if not permuted or fuzzer in ("*original", "original") or permuted == domain.lower():
            continue
        out.append((fuzzer, permuted))
    # combosquats in lexicon order (login, signin, secure … first) so a candidate cap keeps
    # the words real kits actually use before the long tail
    words = list(dictionary)
    if words:
        rank = {w: i for i, w in enumerate(words)}

        def word_rank(permuted: str) -> int:
            label = permuted.split(".")[0]
            return min((i for w, i in rank.items() if w in label), default=len(rank))

        combos = sorted((x for x in out if x[0] == "dictionary"), key=lambda x: word_rank(x[1]))
        out = combos + [x for x in out if x[0] != "dictionary"]
    return out


# Cheap-and-likely first: combosquats and TLD swaps are what real kits register; the
# thousands of homoglyph variants come last so a candidate cap still samples every technique.
FUZZER_PRIORITY: tuple[str, ...] = (
    "dictionary", "tld-swap", "addition", "omission", "hyphenation", "transposition",
    "repetition", "replacement", "bitsquatting", "vowel-swap", "insertion", "subdomain",
    "plural", "various", "homoglyph",
)  # fmt: skip


def interleave_by_fuzzer(perms: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Round-robin across fuzzers (in FUZZER_PRIORITY order) so a cap keeps a fair sample."""
    buckets: dict[str, list[tuple[str, str]]] = {}
    for fuzzer, domain in perms:
        buckets.setdefault(fuzzer, []).append((fuzzer, domain))
    # ASCII homoglyphs (0/o, 1/l, rn/m) are what kits actually register; IDN variants come after.
    if "homoglyph" in buckets:
        buckets["homoglyph"].sort(key=lambda fd: ("xn--" in fd[1], fd[1]))
    order = [f for f in FUZZER_PRIORITY if f in buckets] + sorted(
        f for f in buckets if f not in FUZZER_PRIORITY
    )
    out: list[tuple[str, str]] = []
    while any(buckets.values()):
        for f in order:
            if buckets[f]:
                out.append(buckets[f].pop(0))
    return out


def discover_dnstwist(
    official_domains: Iterable[str],
    *,
    dictionary: Iterable[str] = DEFAULT_DICTIONARY,
    tlds: str = "common",
    max_hits: int | None = None,
) -> list[DiscoveryHit]:
    """DiscoveryHits for every permutation of every official domain (deduplicated, ordered)."""
    seen: set[str] = set()
    hits: list[DiscoveryHit] = []
    officials = {split_host(d).registrable for d in official_domains}
    for official in sorted(officials):
        for fuzzer, permuted in interleave_by_fuzzer(
            permutations(official, dictionary=dictionary, tlds=tlds)
        ):
            if permuted in seen or permuted in officials:
                continue
            seen.add(permuted)
            hits.append(
                DiscoveryHit(
                    source=DiscoverySource.DNSTWIST,
                    raw_value=permuted,
                    surface=Surface.NAME,
                    matched_pattern=f"{fuzzer}:{official}",
                )
            )
            if max_hits is not None and len(hits) >= max_hits:
                return hits
    return hits


def manual_hits(urls: Iterable[str]) -> list[DiscoveryHit]:
    """Analyst-supplied URLs / domains (spec §21 discovery_source.manual)."""
    out: list[DiscoveryHit] = []
    for raw in urls:
        raw = raw.strip()
        if not raw:
            continue
        surface = Surface.PATH if "/" in raw.split("://", 1)[-1].rstrip("/") else Surface.NAME
        out.append(
            DiscoveryHit(
                source=DiscoverySource.MANUAL, raw_value=raw, surface=surface, matched_pattern=None
            )
        )
    return out
