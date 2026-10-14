"""Discovery streams beyond dnstwist (spec §3 stage 1, §8 "four surfaces", Phase 3).

Each stream is a coroutine ``(ctx-like inputs) -> list[DiscoveryHit]`` that degrades on its own:
a provider outage yields an empty list plus a note, never an exception, so the other streams
still run. Streams are enabled per brand through ``detection.streams``.

    dnstwist  — name surface, permutations (Phase 1)
    ct        — subdomain/name surface: certificate transparency SANs containing the brand
    nrd       — name surface: newly-registered-domain feed (local newline-delimited file)
    search    — name/path surface: web search results mentioning the brand
    urlscan   — path surface: scanned pages whose URL contains the brand
    meta_ads  — shops advertised on Facebook / Instagram with the brand's product keywords
                (brands whose products other shops resell; runs on their own, see the runner)
"""

from __future__ import annotations

import asyncio
import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from rapidfuzz.distance import Levenshtein

from brandwatch import trace
from brandwatch.db.enums import DiscoverySource, Surface
from brandwatch.detection import relevance
from brandwatch.detection.discovery import (
    DEFAULT_DICTIONARY,
    SHORT_KEY,
    TLD_SETS,
    interleave_by_fuzzer,
    key_in,
    permutations,
    split_host,
)
from brandwatch.detection.normalize import (
    canonical_listing_url,
    is_app_store,
    is_known_platform,
    is_shared_hosting,
)
from brandwatch.pipeline.stages import DiscoveryHit
from brandwatch.providers.registry import ProviderRegistry

STREAMS: tuple[str, ...] = ("dnstwist", "ct", "nrd", "search", "urlscan", "meta_ads")
MAX_AD_QUERIES = 6  # default searches per scan (keywords × countries) — per brand: detection/ad_settings.py
MAX_AD_PAGES = 12  # a hard stop on paging through one search, whatever "ads per search" says


@dataclass(slots=True)
class StreamResult:
    stream: str
    hits: list[DiscoveryHit] = field(default_factory=list)
    degraded: bool = False
    note: str | None = None
    api_calls: int = 0
    # everything the stream looked at (incl. official / filtered results) for the live console
    seen: list[dict] = field(default_factory=list)
    generated: int = 0  # dnstwist: permutations generated (before the DNS check)
    checked: int = 0  # dnstwist: names actually checked in DNS
    unknown: int = 0  # dnstwist: names with no usable DNS answer (timeouts / SERVFAIL)
    dns_broken: bool = False  # most look-ups got no answer: the result cannot be trusted
    tlds: int = 0  # dnstwist: TLDs tried
    ads_by_host: dict[str, list[dict]] = field(default_factory=dict)  # meta_ads: every ad per shop
    not_about_brand: int = 0  # meta_ads: ads that only shared the words (cloud storage, "on cloud nine")
    ai_checked: int = 0  # meta_ads: unclear ads the AI read
    ad_totals: dict[str, Any] = field(default_factory=dict)  # meta_ads: "keyword|CC" → ads Meta has in total


def _host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        return (urlsplit(url_or_host).hostname or "").lower().rstrip(".")
    return url_or_host.lower().rstrip(".").lstrip("*.")


def _is_official(host: str, officials: set[str]) -> bool:
    return any(host == o or host.endswith("." + o) for o in officials)


def _looks_related(host: str, brand_key: str) -> bool:
    if not brand_key:
        return False
    sld = split_host(host).sld
    if len(brand_key) < SHORT_KEY:  # "on": only as a label part (on-sale.com), never inside "phone"
        return key_in(brand_key, host)
    return brand_key in host.replace("-", "") or (0 < Levenshtein.distance(sld, brand_key) <= 2)


# --------------------------------------------------------------------------------------------
PUBLIC_RESOLVERS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
_dns_lock = threading.Lock()
_dns_nameservers: list[str] | None = None
_dns_report: dict[str, Any] = {}


# International (xn--) homoglyph names are thousands per brand, almost never registered and slow
# to resolve (many resolvers time out on them). The first ones (closest to the brand) are kept.
MAX_IDN_PER_OFFICIAL = 250


def dns_nameservers() -> list[str]:
    from brandwatch.detection import dnslookup

    return dnslookup.service_nameservers()


def dns_registered(name: str) -> bool | None:
    """Is the name registered? Uses the workspace's DNS method (Python walk from the root, or a
    public resolver service) with its fallback — see ``detection.dnslookup``."""
    from brandwatch.detection import dnslookup

    return dnslookup.registered(name)


FUZZER_LABELS: dict[str, str] = {
    "dictionary": "combinations with keywords", "tld-swap": "the brand on other TLDs",
    "hyphenation": "hyphenated", "addition": "typos (added letter)", "omission": "typos (missing letter)",
    "transposition": "typos (swapped letters)", "replacement": "typos (wrong key)",
    "repetition": "typos (doubled letter)", "vowel-swap": "typos (vowel swap)",
    "insertion": "typos (inserted letter)", "bitsquatting": "bit-flips", "homoglyph": "look-alike characters",
    "subdomain": "dotted variants", "plural": "plural", "various": "other variants",
    "brand-name": "the brand name as a domain",
}  # fmt: skip


def short_label_aliases(officials: Iterable[str], brand_key: str) -> dict[str, str]:
    """``{"on.com": "oncloud.com"}``: an official domain whose label is too short to permute is
    replaced by the brand key on the same ending (the key is longer only when the brand's name
    starts with the label — see ``baseline.brand_key_for``)."""
    out: dict[str, str] = {}
    for d in officials:
        parts = split_host(d)
        if (parts.registrable and parts.suffix and len(parts.sld) < SHORT_KEY
                and len(brand_key) >= SHORT_KEY and brand_key != parts.sld):  # fmt: skip
            out[parts.registrable] = f"{brand_key}.{parts.suffix}"
    return out


async def stream_dnstwist(
    officials: Iterable[str],
    *,
    tlds: str,
    max_hits: int | None,
    dictionary: Iterable[str] | None = None,
    resolver: Callable[[str], bool | None] | None = None,
    concurrency: int = 40,
    on_generated: Callable[[int, dict[str, dict]], None] | None = None,
    on_progress: Callable[[int, int, list[str], int], None] | None = None,
    max_checks: int | None = None,
    should_stop: Callable[[], bool] | None = None,
    aliases: dict[str, str] | None = None,
) -> StreamResult:
    """Look-alike names of the official domains: typos, hyphenation (crypto-hopper), combosquats
    with the lexicon (cryptohopperlogin, cryptohopper-trading) and the brand on other TLDs.
    With a ``resolver`` (live mode) every name is checked in DNS concurrently and only registered
    names become candidates; without one (demo / tests) every permutation is a candidate.
    ``on_generated`` / ``on_progress`` let the caller narrate the work; ``should_stop`` is polled
    between DNS batches so an analyst can stop a scan.

    A label shorter than 4 letters ("on" of on.com) has no meaningful typos — every 2–3 letter
    .com is taken by someone unrelated. ``aliases`` maps such a domain to the brand name as a domain
    ("on.com" → "oncloud.com"), which is permuted instead and itself checked; a short label with no
    alias keeps only its keyword combinations ("on-login.com")."""
    regs = sorted({split_host(d).registrable for d in officials})
    aliases = aliases or {}
    bases = list(dict.fromkeys(aliases.get(r, r) for r in regs))
    words = list(dictionary) if dictionary else list(DEFAULT_DICTIONARY)
    names: list[tuple[str, str, str]] = []  # (fuzzer, permuted, official)
    idn_count: dict[str, int] = {}
    idn_skipped = 0
    seen: set[str] = set(regs) | set(bases)
    for official in bases:
        if official not in regs:  # the brand name as a domain (alias of a short official label)
            names.append(("brand-name", official, official))
        short = len(split_host(official).sld) < SHORT_KEY
        for fuzzer, permuted in interleave_by_fuzzer(
            permutations(official, dictionary=words, tlds=tlds)
        ):
            if permuted in seen or (short and fuzzer != "dictionary"):
                continue
            seen.add(permuted)
            if permuted.startswith("xn--") or ".xn--" in permuted:
                idn_seen = idn_count.get(official, 0)
                if idn_seen >= MAX_IDN_PER_OFFICIAL:
                    idn_skipped += 1
                    continue
                idn_count[official] = idn_seen + 1
            names.append((fuzzer, permuted, official))
    n_tlds = len(TLD_SETS[tlds]) if isinstance(tlds, str) else len(list(tlds))
    generated_total = len(names)
    if max_checks is not None and len(names) > max_checks:
        names = names[:max_checks]  # interleaved best-first, so every technique keeps a share
    breakdown: dict[str, dict] = {}
    for f, d, _o in names:
        b = breakdown.setdefault(f, {"count": 0, "examples": [], "label": FUZZER_LABELS.get(f, f)})
        b["count"] += 1
        if len(b["examples"]) < 5:
            b["examples"].append(d)
    if idn_skipped:
        breakdown.setdefault(
            "homoglyph", {"count": 0, "examples": [], "label": FUZZER_LABELS["homoglyph"]}
        )
        breakdown["homoglyph"]["skipped_idn"] = idn_skipped
    if on_generated is not None:
        on_generated(len(names), breakdown)
    trace.section("DNSTWIST · look-alike names")
    trace.log("dnstwist", "inputs", officials=regs, permuted=bases, tld_set=tlds if isinstance(tlds, str) else "custom",
              tlds=n_tlds, lexicon=words,
              how="dnstwist fuzzers on each official registrable domain; every name below is then "
                  "checked in DNS (A, then NS record) — no HTTP and no WHOIS at this stage; only "
                  "registered names become candidates and are visited later")  # fmt: skip
    trace.log(
        "dnstwist",
        "generated per technique",
        **{f: {"count": b["count"], "examples": b["examples"]} for f, b in breakdown.items()},
    )
    for i in range(0, len(names), 2000):
        trace.log(
            "dnstwist",
            f"all generated names, part {i // 2000 + 1}",
            names=[f"{d} [{f}]" for f, d, _o in names[i : i + 2000]],
        )
    sample = [{"label": d, "tag": FUZZER_LABELS.get(f, f)} for f, d, _o in names[:14]]

    def hit(f: str, d: str, o: str) -> DiscoveryHit:
        return DiscoveryHit(DiscoverySource.DNSTWIST, d, Surface.NAME, matched_pattern=f"{f}:{o}")

    if resolver is None:
        hits = [hit(f, d, o) for f, d, o in names]
        if max_hits is not None:
            hits = hits[:max_hits]
        return StreamResult(
            "dnstwist", hits, seen=sample, generated=generated_total, tlds=n_tlds,
            note=f"{generated_total} names generated across {n_tlds} TLDs (no DNS check in demo mode)",
        )  # fmt: skip

    sem = asyncio.Semaphore(concurrency)

    async def check(f: str, d: str, o: str) -> tuple[str, str, str, bool | None]:
        async with sem:
            ok = await asyncio.to_thread(resolver, d)
        return f, d, o, ok

    hits: list[DiscoveryHit] = []
    registered: list[str] = []
    unknown: list[str] = []
    checked = 0
    stopped = dns_broken = False
    batch = max(concurrency * 5, 100)
    from brandwatch.db.base import checkpoint

    for start in range(0, len(names), batch):
        if should_stop is not None and should_stop():
            stopped = True
            break
        checkpoint()  # release the write lock before minutes of DNS work (the cancel check read)
        chunk = names[start : start + batch]
        results = await asyncio.gather(*(check(f, d, o) for f, d, o in chunk))
        checked += len(results)
        for f, d, o, ok in results:
            if ok:
                hits.append(hit(f, d, o))
                registered.append(d)
            elif ok is None:
                unknown.append(d)
        trace.log("dnstwist",
                  f"DNS batch {start // batch + 1}: {sum(1 for r in results if r[3])} registered, "
                  f"{sum(1 for r in results if r[3] is None)} no answer, of {len(results)}",
                  registered=[d for _f, d, _o, ok in results if ok],
                  no_answer=[d for _f, d, _o, ok in results if ok is None],
                  not_registered=[d for _f, d, _o, ok in results if ok is False])  # fmt: skip
        if on_progress is not None:
            on_progress(min(start + batch, len(names)), len(names), list(registered), len(unknown))
        # the first batch tells us whether DNS works at all; do not grind through thousands of
        # time-outs and then report "0 registered"
        if start == 0 and len(results) >= 50 and len(unknown) > 0.8 * len(results):
            dns_broken = True
            break
    total_registered = len(hits)
    if max_hits is not None:
        hits = hits[:max_hits]
    live = set(registered)
    for item in sample:  # mark which of the shown examples actually exist
        if item["label"] in live:
            item["tag"] += " · registered"
    note = (f"{generated_total} names generated across {n_tlds} TLDs, {checked} checked in DNS"
            + (f" (limit {max_checks})" if max_checks and generated_total > max_checks else "")
            + f", {total_registered} registered")  # fmt: skip
    if unknown:
        note += f", {len(unknown)} without a DNS answer"
    if dns_broken:
        note = (f"DNS is not answering on this machine: {len(unknown)} of the first {checked} look-ups "
                "timed out, so the look-alike check was stopped (the result would be a false 0)")  # fmt: skip
    if stopped:
        note += " (stopped by the analyst before every name was checked)"
    return StreamResult(
        "dnstwist", hits, seen=sample, generated=generated_total, tlds=n_tlds, note=note,
        checked=checked, unknown=len(unknown), dns_broken=dns_broken, degraded=dns_broken,
    )  # fmt: skip


async def stream_ct(
    providers: ProviderRegistry, brand_key: str, officials: set[str]
) -> StreamResult:
    notes: list[str] = []
    if len(brand_key) >= SHORT_KEY:
        res = await providers.cert().ct_search(f"%{brand_key}%")
        api_calls = 1
    else:  # "%on%" is every certificate in the log: search the official domains only
        res, api_calls = None, 0
        notes.append(f"brand token “{brand_key}” too short for a substring search")
    certs: list[dict] = list((res.data or {}).get("certificates", [])) if res and res.ok else []
    if res is not None and not res.ok:
        notes.append(f"brand-substring CT search unavailable ({res.error})")
    # crt.sh down or nothing found: query each official domain through the cert chain. A plain
    # domain search works on crt.sh and on the keyless CertSpotter fallback, so CT evidence
    # (subdomains, related certs) keeps flowing during a crt.sh outage.
    if res is None or not res.ok or not certs:
        for official in sorted({split_host(o).registrable for o in officials if "." in o}):
            r2 = await providers.cert().ct_search(official)
            api_calls += 1
            if r2.ok:
                certs += list((r2.data or {}).get("certificates", []))
            else:
                notes.append(f"{official}: {r2.error}")
    if not certs and (res is None or not res.ok):
        return StreamResult(
            "ct", degraded=True, note="; ".join(notes)[:300] or (res.error if res else None),
            api_calls=api_calls,
        )  # fmt: skip
    hits: list[DiscoveryHit] = []
    seen: set[str] = set()
    for cert in certs:
        fp = cert.get("fingerprint_sha256", "")[:12]
        for san in cert.get("sans", []):
            host = _host_of(str(san))
            if not host or "." not in host or host in seen or _is_official(host, officials):
                continue
            if not _looks_related(host, brand_key):
                continue
            seen.add(host)
            reg = split_host(host).registrable
            hits.append(
                DiscoveryHit(
                    source=DiscoverySource.CT,
                    raw_value=host,
                    surface=Surface.SUBDOMAIN if reg != host else Surface.NAME,
                    matched_pattern=f"san:{fp}",
                )
            )
    return StreamResult("ct", hits, api_calls=api_calls, note="; ".join(notes)[:300] or None)


def whoisds_urls(days_back: tuple[int, ...] = (1, 2, 3)) -> list[str]:
    """Free daily Newly-Registered-Domains lists from whoisds.com (no key). A day's list is
    published the next day, so the most recent available is yesterday; older days are the
    fallback. Each URL returns a zip of ~70k domains registered that day."""

    return [u for _, u in whoisds_feeds(days_back)]


def whoisds_feeds(days_back: tuple[int, ...] = (1, 2, 3)) -> list[tuple[str, str]]:
    """``(date, url)`` of the free whoisds lists, most recent first."""
    import base64
    import datetime as _dt

    out = []
    for off in days_back:
        d = (_dt.date.today() - _dt.timedelta(days=off)).isoformat()
        tok = base64.b64encode(f"{d}.zip".encode()).decode()
        out.append(
            (d, f"https://www.whoisds.com/whois-database/newly-registered-domains/{tok}/nrd")
        )
    return out


async def _nrd_text(feed: str, cache_dir: str | Path | None) -> str:
    """The NRD feed as text. ``feed`` is a local path or an http(s) URL (a ``{date}`` placeholder
    is filled with today's date); .zip and .gz downloads are decompressed; a URL is cached once
    per day under ``cache_dir/_nrd`` so a 100k+-domain feed is fetched only once."""
    import datetime as _dt
    import gzip
    import hashlib
    import io
    import zipfile

    if "://" not in feed:
        return Path(feed).read_text(encoding="utf-8", errors="replace")
    url = feed.replace("{date}", _dt.date.today().isoformat())
    cache = None
    if cache_dir:
        cache = (
            Path(cache_dir)
            / "_nrd"
            / (
                hashlib.sha256(url.encode()).hexdigest()[:16]
                + f"-{_dt.date.today().isoformat()}.txt"
            )
        )
        if cache.exists():
            return cache.read_text(encoding="utf-8", errors="replace")
    import httpx

    transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")  # this network's IPv6 is broken
    async with httpx.AsyncClient(timeout=120, follow_redirects=True, transport=transport) as c:
        r = await c.get(url)
        r.raise_for_status()
        body = r.content
    if url.endswith(".zip") or body[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(body)) as z:
            body = z.read(z.namelist()[0])
    elif url.endswith(".gz") or body[:2] == bytes([0x1F, 0x8B]):
        body = gzip.decompress(body)
    text = body.decode("utf-8", errors="replace")
    if cache is not None:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(text, encoding="utf-8")
    return text


async def stream_nrd(
    feed_path: str | Path | None,
    brand_key: str,
    officials: set[str],
    *,
    max_hits: int = 500,
    cache_dir: str | Path | None = None,
) -> StreamResult:
    if not feed_path:
        return StreamResult("nrd", degraded=True, note="no NRD feed configured (NRD_FEED_PATH)")
    is_whoisds = str(feed_path).strip().lower() == "whoisds"
    feeds = whoisds_feeds() if is_whoisds else [(Path(str(feed_path)).name, str(feed_path))]
    if "://" not in feeds[0][1] and not Path(feeds[0][1]).exists():
        return StreamResult("nrd", degraded=True, note=f"NRD feed not found: {feeds[0][1]}")
    text = None
    last_err = ""
    label = feeds[0][0]
    for day, feed in feeds:  # whoisds: try yesterday, then older days
        try:
            text = await _nrd_text(feed, cache_dir)
            label = day
            break
        except Exception as exc:  # noqa: BLE001 - a bad feed must never kill discovery
            last_err = f"{type(exc).__name__}: {exc}"
    if text is None:
        return StreamResult("nrd", degraded=True, note=f"NRD feed error: {last_err}")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    total = len(lines)
    hits: list[DiscoveryHit] = []
    seen: set[str] = set()
    checked = 0
    for line in lines:
        checked += 1
        host = _host_of(line.strip())
        if not host or "." not in host or host in seen or _is_official(host, officials):
            continue
        if _looks_related(host, brand_key):
            seen.add(host)
            hits.append(
                DiscoveryHit(
                    DiscoverySource.NRD, host, Surface.NAME, matched_pattern="nrd:brand-match"
                )
            )
            if len(hits) >= max_hits:
                break
    if is_whoisds:  # the list for a day is published the next morning → it is yesterday's
        import datetime as _dt

        age = (_dt.date.today() - _dt.date.fromisoformat(label)).days
        when = "yesterday" if age == 1 else f"{age} days ago"
        source = f"domains registered {when} ({label}, whoisds)"
    else:
        source = f"feed {label}"
    return StreamResult(
        "nrd", hits, generated=total, checked=checked,
        note=f"{source}: {total:,} new domains, {checked:,} checked, {len(hits)} match(es)",
    )  # fmt: skip


_AUTH_TITLE = re.compile(
    r"\b(log ?in|sign ?in|sign ?up|register|account|verify|wallet|password|2fa)\b", re.I
)
_AUTH_PATH = re.compile(r"(login|signin|signup|register|verify|account|wallet|password)", re.I)


def triage_search_result(
    host: str,
    title: str | None,
    url: str,
    officials: set[str],
    brand_key: str | None,
    official_apps: tuple[str, ...] | list[str] = (),
) -> tuple[str, str, bool]:
    """What the scanner thinks of one Google result before visiting it:
    ``(short tag, plain-language verdict, will it be visited)``."""
    key = (brand_key or "").lower()
    if not host:
        return "invalid", "not a web address", False
    if _is_official(host, officials):
        return "official", "the brand's own site", False
    if is_known_platform(host):
        return (
            "skipped: platform",
            "well-known platform (video / social / wiki) — not a phishing host",
            False,
        )
    t = title or ""
    brandish = bool(key) and (key in host.replace("-", "") or key in t.lower().replace(" ", ""))
    authy = bool(_AUTH_TITLE.search(t)) or bool(_AUTH_PATH.search(urlsplit(url).path))
    if is_app_store(host):
        listing = canonical_listing_url(url)
        if any(listing == canonical_listing_url(o) for o in official_apps):
            return "official app", "the brand's own app listing (linked from its website)", False
        if not brandish:
            return (
                "skipped: other app",
                "app listing that does not carry the brand name — another product",
                False,
            )
        return (
            "app listing",
            "app-store / APK listing named after the brand — will be checked",
            True,
        )
    if is_shared_hosting(host):
        if brandish:
            return (
                "suspicious",
                "free-hosting page about the brand — a classic kit location, will be visited",
                True,
            )
        return "free hosting", "page on a free hosting platform — will be visited", True
    if brandish and authy:
        return (
            "suspicious",
            "login / sign-up page carrying the brand name — will be visited first",
            True,
        )
    if brandish:
        return "brand mention", "the brand appears in the domain or title — will be visited", True
    if authy:
        return (
            "login-style",
            "login-style page without the brand in its title — will be visited",
            True,
        )
    return "low priority", "unrelated-looking result — still visited, at low priority", True


async def stream_search(
    providers: ProviderRegistry,
    brand_name: str,
    officials: set[str],
    *,
    geo: str,
    lang: str,
    queries: list[str] | None = None,
    geos: list[str] | None = None,
    brand_key: str | None = None,
    on_query: Callable[[str, str, list[dict]], None] | None = None,
    official_apps: tuple[str, ...] | list[str] = (),
    markets: list[tuple[str, str]] | None = None,
) -> StreamResult:
    """One Google (SerpAPI) search per query and country (and, with ``markets``, per country and language) — the brand name alone, or the list of
    queries impersonators target ("<brand> login", "<brand> support", misspellings …).
    ``on_query`` receives every result of a query (site, title, verdict) as it comes in."""
    queries = [q for q in (queries or []) if q.strip()] or [brand_name]
    geos = [g.strip().lower() for g in (geos or []) if g.strip()] or [geo]
    hits: list[DiscoveryHit] = []
    seen: set[str] = set()
    looked: list[dict] = []
    looked_urls: set[str] = set()
    errors: list[str] = []
    pairs = [(g.strip().lower(), (lg or lang).strip().lower()) for g, lg in (markets or [])] or [(g, lang) for g in geos]
    several = len({lg for _g, lg in pairs}) > 1 or len(pairs) != len({g for g, _lg in pairs})  # a country in two languages: say which one
    runs = [(q, g, lg) for g, lg in pairs for q in queries]
    for query, country, qlang in runs:
        res = await providers.search().search(query, geo=country, lang=qlang)
        if not res.ok:
            errors.append(f"{query} ({country}): {res.error}")
            continue
        this_query: list[dict] = []
        for pos, item in enumerate((res.data or {}).get("hits", []), 1):
            url = item["url"] if isinstance(item, dict) else str(item)
            host = _host_of(url)
            meta = item if isinstance(item, dict) else {}
            title = meta.get("title") or host
            tag, verdict, visit = triage_search_result(
                host, meta.get("title"), url, officials, brand_key, official_apps
            )
            if meta.get("kind") == "ad":
                tag, verdict = "ad · " + tag, "paid ad — " + verdict
            entry = {
                "label": title, "url": url, "host": host, "query": query, "geo": country,
                "lang": qlang, "position": meta.get("position") or pos, "tag": f"#{meta.get('position') or pos} · {tag}",
                "note": verdict, "official": tag == "official", "visit": visit,
            }  # fmt: skip
            this_query.append(entry)
            if url not in looked_urls:
                looked_urls.add(url)
                looked.append(entry)
            if not visit or url in seen:
                continue
            seen.add(url)
            path = urlsplit(url).path
            surface = Surface.PATH if path not in ("", "/") else Surface.NAME
            hits.append(
                DiscoveryHit(
                    DiscoverySource.SERPAPI,
                    url,
                    surface,
                    matched_pattern=f"serp:{country}/{qlang}:{query}",
                )  # fmt: skip
            )
        label = f"{country}/{qlang}" if several else country
        if on_query is not None:
            on_query(query, label, this_query)
        via = str(getattr(res, "provider", "") or "")
        late = f" · answered by {via.split(':')[-1]}" if via and "serpapi" not in via else ""  # the fallback answered
        trace.log("search", f"Google {label} “{query}”: {len(this_query)} results{late}",
                  results=[{"pos": r["position"], "host": r["host"], "title": r["label"], "url": r["url"],
                            "verdict": r["note"], "visit": r["visit"]} for r in this_query])  # fmt: skip
    if errors and len(errors) == len(runs):
        return StreamResult(
            "search", degraded=True, note="; ".join(errors)[:300], api_calls=len(runs)
        )
    note = (
        f"{len(errors)} of {len(runs)} searches failed: " + "; ".join(errors)[:200]
        if errors
        else None
    )
    return StreamResult("search", hits, note=note, api_calls=len(runs), seen=looked)


async def stream_urlscan(
    providers: ProviderRegistry, brand_key: str, officials: set[str]
) -> StreamResult:
    if len(brand_key) < SHORT_KEY:
        return StreamResult("urlscan", degraded=True, note=(
            f"the brand token “{brand_key}” is too short to search the urlscan archive — it is inside "
            "millions of unrelated addresses; give the brand its full name (e.g. “On Cloud”)"))  # fmt: skip
    res = await providers.urlscan().search_pages(brand_key)
    if not res.ok:
        return StreamResult("urlscan", degraded=True, note=res.error, api_calls=1)
    hits: list[DiscoveryHit] = []
    seen: set[str] = set()
    for item in (res.data or {}).get("results", []):
        url = item.get("url") if isinstance(item, dict) else str(item)
        if not url:
            continue
        host = _host_of(url)
        if not host or _is_official(host, officials) or url in seen:
            continue
        seen.add(url)
        path = urlsplit(url).path
        surface = Surface.PATH if path not in ("", "/") else Surface.NAME
        hits.append(
            DiscoveryHit(
                DiscoverySource.URLSCAN,
                url,
                surface,
                matched_pattern=f"urlscan:{item.get('task_id', '')}"
                if isinstance(item, dict)
                else "urlscan",
            )
        )
    return StreamResult("urlscan", hits, api_calls=1)


_FB_REDIRECTORS = ("l.facebook.com", "lm.facebook.com", "l.instagram.com", "l.messenger.com")
_TRACKING = re.compile(
    r"^(utm_[a-z_]+|fbclid|gclid|dclid|igshid|mc_cid|mc_eid|_ga|ttclid|msclkid)$", re.I
)
_NOT_A_SHOP = ("wa.me", "api.whatsapp.com", "whatsapp.com", "m.me", "t.me", "linktr.ee", "fb.me",
               "fb.com", "fb.watch", "ig.me", "msng.link")


def clean_ad_link(url: str) -> str:
    """The shop's own URL from an ad link: unwrap Facebook / Instagram redirectors
    (``l.facebook.com/l.php?u=…``) and drop tracking parameters (utm_*, fbclid …) so every ad for
    the same page becomes one candidate."""
    for _ in range(3):
        parts = urlsplit(url)
        if (parts.hostname or "").lower() in _FB_REDIRECTORS:
            target = dict(parse_qsl(parts.query)).get("u")
            if not target:
                break
            url = unquote(target)
            continue
        break
    parts = urlsplit(url)
    query = urlencode(
        [
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not _TRACKING.match(k)
        ]
    )
    return urlunsplit(
        (parts.scheme or "https", (parts.netloc or "").lower(), parts.path or "/", query, "")
    )


async def stream_meta_ads(
    providers: ProviderRegistry,
    keywords: list[str],
    countries: list[str],
    officials: set[str],
    *,
    terms: relevance.BrandTerms | None = None,
    max_queries: int = 6,
    ads_per_search: int = 30,
    on_query: Callable[..., None] | None = None,
) -> StreamResult:
    """Ads in Meta's Ad Library (via SearchApi.io) that use the brand's product keywords in each
    chosen country, and the shops they link to. ``officials`` holds the brand's own domains *and*
    its authorised retailers (whitelist kind "reseller"), which are never suspects.

    Meta matches words, not meaning ("on cloud" also finds cloud-storage and TV-series ads), so every
    ad first has to be *about the brand* (``relevance.ad_relevance``): it names the brand or a product,
    or says the brand's words next to what the brand sells. An ad that only shares the words is read
    by the AI when one is configured, otherwise skipped. One URL per shop host becomes a candidate;
    every ad that pointed at it is kept in ``ads_by_host`` (for the finding and for reporting the ad
    and the page to Meta)."""
    from brandwatch.detection import ai as ai_mod

    keywords = [k for k in dict.fromkeys(k.strip() for k in keywords) if k] or []
    countries = [c.upper() for c in dict.fromkeys(c.strip() for c in countries) if c] or ["US"]
    runs = [(k, c) for c in countries for k in keywords][:max_queries]
    if not runs:
        return StreamResult(
            "meta_ads", degraded=True, note="no ad keywords — add them in the brand profile"
        )
    hits: list[DiscoveryHit] = []
    looked: list[dict] = []
    by_host: dict[str, list[dict]] = {}
    errors: list[str] = []
    ignored = ai_checked = requests = 0
    totals: dict[str, Any] = {}
    for keyword, country in runs:
        # page through the Ad Library until the brand's "ads per search" are read (~30 a page)
        page_ads: list[dict] = []
        token: str | None = None
        failed: str | None = None
        for _page in range(MAX_AD_PAGES):
            res = await providers.ads().meta_ads(keyword, country, next_page_token=token)
            requests += 1
            if not res.ok:
                failed = res.error
                break
            got = list((res.data or {}).get("ads") or [])
            page_ads += got
            totals[f"{keyword}|{country}"] = (res.data or {}).get("total")
            token = (res.data or {}).get("next_page_token")
            if not token or not got or len(page_ads) >= ads_per_search:
                break
        if failed and not page_ads:
            errors.append(f"“{keyword}” ({country}): {failed}")
            continue
        page_ads = page_ads[:ads_per_search]
        this_query: list[dict] = []
        rows: list[tuple[dict, dict]] = []  # (console entry, ad)
        unclear: list[tuple[dict, dict]] = []  # the ones the AI has to read
        for raw in page_ads:
            url = clean_ad_link(raw.get("link_url") or "")
            host = _host_of(url)
            if not host:
                continue
            ad = {**raw, "landing_url": url}
            rel, why = relevance.ad_relevance(ad, terms) if terms is not None else ("yes", "")
            if _is_official(host, officials):
                tag, verdict, visit = "official / authorised", "the brand's own site or an authorised retailer", False
            elif rel == "no":
                tag, verdict, visit = "not about the brand", why, False
            elif host in _NOT_A_SHOP or any(host.endswith("." + x) for x in _NOT_A_SHOP):
                tag, verdict, visit = "chat link", "sends people to a chat or a Facebook page, not to a shop", False
            elif is_known_platform(host) or is_app_store(host):
                tag, verdict, visit = "platform", (
                    f"about the brand ({why}), but it sends buyers to {host}, not to a web shop"
                    if rel == "yes" else "a well-known platform, not a shop"), False  # fmt: skip
            elif rel == "maybe":
                tag, verdict, visit = "unclear", why, False
            else:
                tag, verdict, visit = "shop", f"a shop advertising the brand's products ({why}) — checked next", True
            entry = {"label": ad.get("page_name") or host, "url": ad.get("library_url") or url, "host": host,
                     "tag": f"ad → {host}", "note": (ad.get("text") or "")[:120], "visit": visit,
                     "official": tag.startswith("official"), "query": keyword, "geo": country, "verdict": verdict,
                     "relevance": tag}  # fmt: skip
            this_query.append(entry)
            rows.append((entry, ad))
            if tag == "unclear":
                unclear.append((entry, ad))
        if unclear:  # the brand's words but nothing else: the AI reads these ads (30 per call)
            answers: dict | None = None
            for i in range(0, len(unclear), 30):
                try:
                    part = await ai_mod.ads_about_brand(
                        providers, brand_name=terms.brand if terms else keyword, sells=terms.sells if terms else "",
                        products=list(terms.products) if terms else [], keyword=keyword,
                        ads=[a for _e, a in unclear[i : i + 30]],
                    )  # fmt: skip
                except Exception:  # noqa: BLE001 - the AI is advisory; no answer → skip the unclear ads
                    part = None
                if part is not None:
                    answers = {**(answers or {}), **part}
            ai_checked += len(unclear)
            for entry, ad in unclear:
                about, ai_why = (answers or {}).get(str(ad.get("ad_id")), (False, ""))
                if answers is None:
                    entry.update(relevance="not about the brand",
                                 verdict=f"{entry['verdict']} — no AI configured to read it, so it was skipped")  # fmt: skip
                elif about:
                    entry.update(relevance="shop", visit=True,
                                 verdict=f"the AI read the ad: {ai_why or 'it sells the brand'} — checked next")  # fmt: skip
                else:
                    entry.update(relevance="not about the brand",
                                 verdict=f"the AI read the ad: {ai_why or 'it is about something else'}")  # fmt: skip
        for entry in this_query:
            if entry["relevance"] == "not about the brand":
                entry["tag"] = f"not about the brand → {entry['host']}"
                ignored += 1
        looked.extend(this_query)
        for entry, ad in rows:
            if not entry["visit"]:
                continue
            host, url = entry["host"], ad["landing_url"]
            ads = by_host.setdefault(host, [])
            if not any(a.get("ad_id") == ad.get("ad_id") for a in ads):
                ads.append({**{k: ad.get(k) for k in ("ad_id", "page_id", "page_name", "text", "start_date", "platforms", "library_url", "image")},
                            "country": country, "keyword": keyword, "landing_url": url, "why": entry["verdict"]})  # fmt: skip
            if len(ads) == 1:  # the first ad for this shop makes it a candidate
                path = urlsplit(url).path
                hits.append(DiscoveryHit(DiscoverySource.META_ADS, url, Surface.PATH if path not in ("", "/") else Surface.NAME,
                                         matched_pattern=f"meta_ad:{country}:{ad.get('ad_id')}"))  # fmt: skip
        if on_query is not None:
            on_query(keyword, country, this_query, totals.get(f"{keyword}|{country}"))
        trace.log("meta_ads", f"Meta ads {country} “{keyword}”: {len(this_query)} ads",
                  ads=[{"page": e["label"], "host": e["host"], "relevance": e["relevance"], "verdict": e["verdict"]}
                       for e in this_query])  # fmt: skip
    if errors and len(errors) == len(runs):
        return StreamResult(
            "meta_ads", degraded=True, note="; ".join(errors)[:300], api_calls=requests
        )
    note = (
        f"{len(errors)} of {len(runs)} searches failed: " + "; ".join(errors)[:200]
        if errors
        else None
    )
    return StreamResult(
        "meta_ads", hits, note=note, api_calls=requests, seen=looked, ads_by_host=by_host,
        not_about_brand=ignored, ai_checked=ai_checked, ad_totals=totals,
    )  # fmt: skip


def merge_hits(
    results: Iterable[StreamResult], *, max_total: int | None = None
) -> list[DiscoveryHit]:
    """Deduplicate across streams on the raw value (the Normalize stage dedups canonically)."""
    out: list[DiscoveryHit] = []
    seen: set[str] = set()
    for r in results:
        for h in r.hits:
            key = h.raw_value.lower().rstrip("/")
            if key in seen:
                continue
            seen.add(key)
            out.append(h)
            if max_total is not None and len(out) >= max_total:
                return out
    return out
