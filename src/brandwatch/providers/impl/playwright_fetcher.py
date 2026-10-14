"""Sandboxed real-browser fetch (spec §7 "Browser sandbox", §3 Analysis Tier 3).



Policy, enforced in code (the container around the worker is deployment):



* **Egress public-only** — every request the page makes (document, scripts, images, XHR) passes

  through ``page.route``; its URL is validated and its host resolved with the same SSRF guard as

  the plain fetcher. Private / loopback / link-local / metadata destinations are aborted.

* **Fresh worker per fetch** — a new headless Chromium is launched for each URL and closed in a

  ``finally`` block: capture evidence, then destroy the worker.

* **Hard caps** — ``BROWSER_OP_TIMEOUT`` for the whole operation, redirect / size limits inherit

  from the system limits, downloads and dialogs are refused, JavaScript stays enabled (kits

  render client-side) but nothing is clicked or typed.



Returned ``data`` keys match the other browser fetchers (``html``, ``dom``, ``screenshot_png``,

``favicon_png``, ``status``, ``final_url`` …) so the enrichment stage is backend-agnostic.

"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable, Sequence
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from urllib.parse import urljoin

from brandwatch.db.enums import ProviderStatus
from brandwatch.providers.base import ProviderError, ProviderResult
from brandwatch.security.fetcher_guard import (
    SsrfBlocked,
    guard_message,
    resolve_and_validate,
    validate_url,
)
from brandwatch.security.limits import SYSTEM_LIMITS, SystemLimits

Resolver = Callable[[str], Sequence[IPv4Address | IPv6Address]]


BOT_UA = "Mozilla/5.0 (compatible; BrandWatchBot/0.1; +https://example.invalid/bot)"
SEARCH_REFERER = "https://www.google.com/"
# A phone: phishing kits that target mobile victims show the lure only to a mobile browser. Profile "mobile" is a phone from the
# data-centre IP; "residential+mobile" a phone through the proxy (residential or mobile network, whichever is configured).
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
             "Chrome/124.0.0.0 Mobile Safari/537.36")
MOBILE_VIEWPORT = (412, 915)


def is_mobile_profile(profile: str) -> bool:
    return profile == "mobile" or profile.endswith("+mobile")


def uses_proxy(profile: str) -> bool:
    return profile.startswith("residential")

# Speed knobs (the hard ceiling stays SYSTEM_LIMITS.BROWSER_OP_TIMEOUT): phishing kits answer in
# seconds; big legitimate sites must not stall the pipeline for a minute each.
NAV_TIMEOUT = 15.0  # s until DOMContentLoaded
SETTLE_TIMEOUT = 3.0  # s for the load event after that
RENDER_PAUSE_MS = 700  # client-side frameworks paint after load
ICON_TIMEOUT_MS = 4000
CHALLENGE_WAIT_STEPS = 8  # seconds to give a Cloudflare-style challenge before giving up
FORWARD_WAIT = 6.0  # s a blank page is given to forward the visit (meta refresh, a script, an auto-submitted form)
FORWARD_MIN_TEXT = 40  # characters of visible text below which a page is a gate, not a page
_SKIPPED_RESOURCES = frozenset(
    {"media", "font", "websocket", "manifest", "texttrack", "eventsource"}
)
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _looks_like_challenge(title: str | None, html: str | None) -> bool:
    from brandwatch.detection.html import is_bot_challenge

    return is_bot_challenge(title, html)


class RoutePolicy:
    """Decides, per outgoing browser request, whether it may leave the sandbox."""

    def __init__(self, resolver: Resolver | None = None, limits: SystemLimits = SYSTEM_LIMITS):

        self._resolver = resolver

        self._limits = limits

        self._host_cache: dict[str, bool] = {}

        self.blocked: list[str] = []

        self.allowed = 0

    def allow(self, url: str) -> bool:

        try:
            target = validate_url(url, self._limits)

        except SsrfBlocked as exc:
            self.blocked.append(f"{url} ({exc})")

            return False

        ok = self._host_cache.get(target.host)

        if ok is None:
            try:
                resolve_and_validate(target.host, self._resolver, self._limits)

                ok = True

            except SsrfBlocked as exc:
                self.blocked.append(f"{url} ({exc})")

                ok = False

            self._host_cache[target.host] = ok

        if ok:
            self.allowed += 1

        return ok


PROFILE_PROCEED = "datacenter-proceed"  # a full check: press through Cloudflare's phishing warning too


class PlaywrightBrowserFetcher:
    name = "playwright"

    requires_key = False

    cost_per_call = 0.0

    def __init__(
        self,
        api_key: str | None = None,
        *,
        resolver: Resolver | None = None,
        limits: SystemLimits = SYSTEM_LIMITS,
        viewport: tuple[int, int] = (1280, 800),
        launch_args: Sequence[str] = (),
        chromium_path: str | None = None,
        residential_proxy: str | None = None,
    ) -> None:
        self._residential_proxy = residential_proxy

        self._resolver = resolver

        self._limits = limits

        self._viewport = viewport

        self._launch_args = list(launch_args)

        self._chromium_path = chromium_path

    async def peek(self, url: str) -> ProviderResult:
        """The page as one plain, SSRF-guarded HTTP request sees it — no browser. Enough to recognise a security
        product's warning page (a verdict somebody already made), so such a site never needs a Chromium visit."""
        from brandwatch.providers.impl import HttpxBrowserFetcher
        from brandwatch.security.fetcher_guard import SafeFetcher

        return await HttpxBrowserFetcher(fetcher=SafeFetcher(resolver=self._resolver, limits=self._limits)).peek(url)

    async def fetch(self, url: str, profile: str = "datacenter") -> ProviderResult:
        # "datacenter-proceed": a full check by an analyst — also press through Cloudflare's phishing warning to look at
        # the site behind it. Every other visit leaves a warning page alone: somebody already judged the site.
        proceed = profile == PROFILE_PROCEED
        if proceed:
            profile = "datacenter"

        try:
            from playwright.async_api import Error as PlaywrightError
            from playwright.async_api import TimeoutError as PlaywrightTimeout
            from playwright.async_api import async_playwright

            async def _content(pg: object) -> str:
                # a page doing a client-side navigation refuses .content(); wait and retry, then
                # fall back to the raw DOM via JS ("page is navigating and changing the content")
                for _ in range(4):
                    try:
                        return await pg.content()
                    except PlaywrightError as exc:
                        if (
                            "navigat" in str(exc).lower()
                            or "changing the content" in str(exc).lower()
                        ):
                            await pg.wait_for_timeout(700)
                            continue
                        raise
                try:
                    return await pg.evaluate("() => document.documentElement.outerHTML")
                except PlaywrightError:
                    return ""

        except ImportError as exc:
            raise ProviderError("playwright is not installed", retryable=False) from exc

        try:
            target = validate_url(url, self._limits)

            resolve_and_validate(target.host, self._resolver, self._limits)

        except SsrfBlocked as exc:
            raise ProviderError(guard_message(exc), retryable=False) from exc

        policy = RoutePolicy(self._resolver, self._limits)
        proxy = None
        if uses_proxy(profile):
            if not self._residential_proxy:
                raise ProviderError("no residential / mobile proxy configured", retryable=False)
            from urllib.parse import urlsplit as _us

            pu = _us(self._residential_proxy)
            proxy = {"server": f"{pu.scheme}://{pu.hostname}:{pu.port}"}
            if pu.username:
                proxy.update({"username": pu.username, "password": pu.password or ""})
        mobile = is_mobile_profile(profile)
        user_agent = MOBILE_UA if mobile else (BOT_UA if profile == "bot" else _UA)
        extra_headers = {"Referer": SEARCH_REFERER} if profile == "referer" else {}

        started = time.monotonic()

        deadline = self._limits.BROWSER_OP_TIMEOUT

        browser = None

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    executable_path=self._chromium_path,
                    args=[
                        "--disable-gpu",
                        "--no-first-run",
                        "--disable-blink-features=AutomationControlled",
                        *self._launch_args,
                    ],  # fmt: skip
                    proxy=proxy,
                )

                device = {"is_mobile": True, "has_touch": True, "device_scale_factor": 2.0} if mobile else {}
                context = await browser.new_context(
                    viewport={"width": (MOBILE_VIEWPORT if mobile else self._viewport)[0],
                              "height": (MOBILE_VIEWPORT if mobile else self._viewport)[1]},
                    **device,
                    user_agent=user_agent,
                    extra_http_headers=extra_headers,
                    ignore_https_errors=True,  # bad certs are evidence, not a reason to look away
                    accept_downloads=False,
                    java_script_enabled=True,
                    service_workers="block",
                )

                context.set_default_timeout(int(deadline * 1000))

                # headless Chromium announces itself via navigator.webdriver; a plain browser does not
                await context.add_init_script(
                    "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
                )
                page = await context.new_page()

                page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))

                navs: list[str] = []  # every address the main frame was at, in order: HTTP redirects, meta refresh, scripts
                nav_status: list[int] = []  # the status of the last document the main frame loaded

                def _on_nav(frame: Any) -> None:
                    if frame == page.main_frame and (not navs or navs[-1] != frame.url):
                        navs.append(frame.url)

                def _on_response(resp: Any) -> None:
                    try:
                        if resp.request.is_navigation_request() and resp.frame == page.main_frame:
                            nav_status.append(resp.status)
                    except Exception:  # noqa: BLE001 - bookkeeping only
                        pass

                page.on("framenavigated", _on_nav)
                page.on("response", _on_response)

                async def gate(route, request):
                    # media / fonts / websockets add seconds and never matter for a screenshot
                    if request.resource_type in _SKIPPED_RESOURCES:
                        await route.abort("blockedbyclient")
                        return
                    # the SSRF check resolves DNS: run it off the event loop (cached per host)
                    if await asyncio.to_thread(policy.allow, request.url):
                        await route.continue_()
                    else:
                        await route.abort("blockedbyclient")

                await context.route("**/*", gate)

                status: int | None = None

                final_url = target.url

                tls_error = None

                request_headers: dict[str, str] = {}  # what this visit really sent (the last request of the redirect chain)
                hops: list[str] = []  # the addresses it was redirected away from, in order

                try:
                    response = await page.goto(
                        target.url, wait_until="domcontentloaded",
                        timeout=int(min(NAV_TIMEOUT, deadline) * 1000),
                    )  # fmt: skip

                    if response is not None:
                        status = response.status

                        final_url = response.url

                        try:
                            request_headers = {k.lower(): v for k, v in (await response.request.all_headers()).items()}
                        except Exception:  # noqa: BLE001 - the headers are evidence detail, never a reason to fail the visit
                            request_headers = {}
                        hop = response.request
                        while hop.redirected_from is not None and len(hops) < 10:
                            hop = hop.redirected_from
                            hops.insert(0, hop.url)

                        sec = await response.security_details()

                        if sec is None and target.scheme == "https":
                            tls_error = "no TLS details (possibly invalid certificate)"

                except PlaywrightTimeout as exc:
                    raise ProviderError(
                        f"browser timeout after {min(NAV_TIMEOUT, deadline):.0f}s"
                    ) from exc

                except PlaywrightError as exc:
                    msg = str(exc).split("\n", 1)[0]

                    if "ERR_BLOCKED_BY_CLIENT" in msg:
                        raise ProviderError(
                            f"navigation blocked by sandbox policy: {msg}", retryable=False
                        ) from exc

                    raise ProviderError(f"navigation failed: {msg}") from exc

                remaining = max(1.0, deadline - (time.monotonic() - started))

                try:
                    await page.wait_for_load_state(
                        "load", timeout=int(min(SETTLE_TIMEOUT, remaining) * 1000)
                    )
                except PlaywrightTimeout:
                    pass  # busy pages never finish loading; capture what we have
                await page.wait_for_timeout(RENDER_PAUSE_MS)  # let client-side rendering paint

                # A blank page is often a gate that forwards the visit a moment later (a meta refresh, a script, an
                # auto-submitted form: the traffic-distribution links kits hide behind). Give it a few seconds and follow it,
                # so the page captured is the one the visitor lands on, and the chain says how it got there.
                if await _visible_chars(page) < FORWARD_MIN_TEXT:
                    await _follow_forwarder(page, deadline=deadline, started=started)
                    if nav_status:
                        status = nav_status[-1]
                    final_url = page.url or final_url

                if page.url.startswith(("http://", "https://")):  # a page that forwards itself (a script, a meta refresh) after it loaded: where the visitor ends up is the last address, not the first document
                    final_url = page.url

                dom = await _content(page)

                title = await page.title()

                # bot-protection interstitial (Cloudflare 'Just a moment…'): give the challenge a few

                # seconds to clear, then report it so the analyst knows the page was gated

                from brandwatch.detection.html import is_cloudflare_phish_warning

                # a phishing warning is not a bot check that clears by itself: do not wait for it
                challenged = _looks_like_challenge(title, dom) and not is_cloudflare_phish_warning(title, dom)

                if challenged:
                    for _ in range(CHALLENGE_WAIT_STEPS):
                        await page.wait_for_timeout(1000)

                        title = await page.title()

                        if not _looks_like_challenge(title, None):
                            dom = await _content(page)

                            challenged = _looks_like_challenge(title, dom)

                            break

                    else:
                        dom = await _content(page)

                # Cloudflare's own "Suspected Phishing" interstitial: Cloudflare has already judged the
                # site. Keep the warning (it is evidence and a signal), then press its "Ignore & Proceed"
                # — inside this sandbox, through the same route gate — to capture the site behind it,
                # the way an analyst would look at it by hand.
                cf_warning = await _proceed_past_cloudflare_warning(page, title, dom, deadline, started, proceed=proceed)
                if cf_warning and cf_warning.get("proceeded"):
                    dom, title = cf_warning.pop("_dom"), cf_warning.pop("_title")
                    final_url = cf_warning.get("final_url") or final_url
                    status = cf_warning.get("status") or status
                    challenged = _looks_like_challenge(title, dom)

                screenshot = await page.screenshot(type="png", full_page=False)

                favicon: bytes | None = None

                favicon_error: str | None = None

                icon_href = await page.evaluate(
                    "() => { const l = document.querySelector('link[rel~=\"icon\"]'); return l ? l.href : null; }"
                )

                icon_url = icon_href or urljoin(final_url, "/favicon.ico")

                if policy.allow(icon_url):
                    favicon, favicon_error = await _fetch_icon(
                        context, icon_url, policy, self._limits
                    )
                else:
                    favicon_error = "blocked by sandbox policy"

                body_bytes = dom.encode("utf-8", errors="replace")

                return ProviderResult(
                    provider=self.name,
                    status=ProviderStatus.POSITIVE,
                    data={
                        "url": url,
                        "final_url": final_url,
                        "profile": profile,
                        "status": status,
                        "content_type": "text/html",
                        "html": dom,
                        "dom": dom,
                        "title": title,
                        "html_sha256": hashlib.sha256(body_bytes).hexdigest(),
                        "screenshot_png": screenshot,
                        "favicon_png": favicon,
                        "favicon_error": favicon_error,
                        "redirect_chain": [u for u in dict.fromkeys([*hops, *navs]) if u != final_url] or ([url] if final_url != target.url else []),
                        "client_redirects": max(0, len(dict.fromkeys(navs)) - 1 - len(hops)),  # hops made by the page itself, not by HTTP
                        "user_agent": user_agent,
                        "request_headers": request_headers,
                        "tls_error": tls_error,
                        "bot_challenge": challenged,
                        "cloudflare_warning": cf_warning,
                        "requests_allowed": policy.allowed,
                        "requests_blocked": policy.blocked,
                    },
                    raw={"title": title, "status": status, "blocked": policy.blocked},
                    latency_ms=int((time.monotonic() - started) * 1000),
                )

        finally:
            if browser is not None:
                try:
                    await browser.close()  # destroy the worker

                except Exception:  # noqa: BLE001
                    pass


async def _visible_chars(page: Any) -> int:
    try:
        return int(await page.evaluate("() => ((document.body && document.body.innerText) || '').trim().length"))
    except Exception:  # noqa: BLE001 - a page that is navigating cannot be read; count it as empty
        return 0


async def _follow_forwarder(page: Any, *, deadline: float, started: float) -> None:
    """Wait (at most ``FORWARD_WAIT`` seconds) for a blank page to go on by itself, and settle on wherever it ends up. Stops as soon
    as the page has something to read and the address has stopped changing."""
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    budget = min(FORWARD_WAIT, max(0.0, deadline - (time.monotonic() - started) - 5.0))
    end = time.monotonic() + budget
    last = page.url
    while time.monotonic() < end:
        await page.wait_for_timeout(400)
        moved = page.url != last
        if moved:
            last = page.url
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=3000)
            except (PlaywrightTimeout, PlaywrightError):
                pass
            await page.wait_for_timeout(RENDER_PAUSE_MS)
        if not moved and await _visible_chars(page) >= FORWARD_MIN_TEXT:
            return


_IMAGE_MAGIC = (b"\x89PNG", b"\x00\x00\x01\x00", b"GIF8", b"RIFF")


async def _proceed_past_cloudflare_warning(
    page: Any, title: str | None, dom: str, deadline: float, started: float, proceed: bool = False
) -> dict[str, Any] | None:
    """If the page is Cloudflare's phishing interstitial, submit its bypass form and return what was
    seen: the warning (title, hash, a copy of its HTML) and, when it worked, the site behind it."""
    from playwright.async_api import Error as PlaywrightError
    from playwright.async_api import TimeoutError as PlaywrightTimeout

    from brandwatch.detection.html import is_cloudflare_phish_warning

    if not is_cloudflare_phish_warning(title, dom):
        return None
    body = dom.encode("utf-8", errors="replace")
    out: dict[str, Any] = {"title": title, "html_sha256": hashlib.sha256(body).hexdigest(),
                           "interstitial_html": dom[:40000], "proceeded": False}  # fmt: skip
    if not proceed:  # the warning is the verdict: keep it as evidence and do not open the site behind it
        out["skipped"] = "Cloudflare already judged the site; the page behind its warning was not opened"
        return out
    low = dom.lower()
    if "cf-turnstile" in low or "challenges.cloudflare.com/turnstile" in low:
        # Cloudflare put a human check (Turnstile) on "Ignore & Proceed": BrandWatch does not solve
        # CAPTCHAs — the warning itself is the evidence, and urlscan / VirusTotal history show the site
        out["error"] = "Cloudflare asks for a human check (Turnstile) before proceeding — not attempted"
        out["human_check"] = True
        return out
    remaining = deadline - (time.monotonic() - started)
    if remaining < 6:
        out["error"] = "no time left to proceed"
        return out
    try:
        async with page.expect_navigation(wait_until="domcontentloaded", timeout=int(min(NAV_TIMEOUT, remaining - 3) * 1000)) as nav:
            submitted = await page.evaluate(
                "() => { const f = document.querySelector('form[action*=\"phish-bypass\"]');"
                " if (!f) return false; f.submit(); return true; }"
            )
            if not submitted:
                raise ProviderError("no bypass form on the warning page", retryable=False)
        response = await nav.value
        try:
            await page.wait_for_load_state("load", timeout=int(min(SETTLE_TIMEOUT, max(1.0, remaining - 5)) * 1000))
        except PlaywrightTimeout:
            pass
        await page.wait_for_timeout(RENDER_PAUSE_MS)
        new_title = await page.title()
        try:
            new_dom = await page.content()
        except PlaywrightError:
            new_dom = await page.evaluate("() => document.documentElement.outerHTML")
        code = response.status if response else None
        if is_cloudflare_phish_warning(new_title, new_dom):
            out["error"] = "the warning came back after proceeding"
        elif (code or 0) >= 400 or len(new_dom) < 250:
            # refused (e.g. a human check the page did not announce): never analyse the error page
            out["error"] = f"proceeding was refused (HTTP {code})"
        else:
            out.update({"proceeded": True, "final_url": page.url, "status": code, "_dom": new_dom, "_title": new_title})
            return out
        try:  # back to the warning, so the screenshot shows what a visitor sees
            await page.go_back(wait_until="domcontentloaded", timeout=5000)
        except (PlaywrightTimeout, PlaywrightError):
            pass
    except (PlaywrightTimeout, PlaywrightError, ProviderError) as exc:
        out["error"] = str(exc).split("\n", 1)[0][:200]
    return out


def _looks_like_image(body: bytes, content_type: str) -> bool:
    return content_type.startswith("image/") or body[:4] in _IMAGE_MAGIC or body[:2] == b"\xff\xd8"


async def _fetch_icon(
    context, icon_url: str, policy: RoutePolicy, limits: SystemLimits
) -> tuple[bytes | None, str | None]:
    """Favicon bytes via (1) a routed second tab, (2) a direct request with manual, policy-checked
    redirects. Both paths are subject to the sandbox policy; neither follows redirects blindly."""
    from playwright.async_api import Error as PlaywrightError

    max_bytes = 512 * 1024
    page = await context.new_page()
    try:
        resp = await page.goto(icon_url, wait_until="commit", timeout=ICON_TIMEOUT_MS)
        if resp is not None and resp.ok:
            body = await resp.body()
            ctype = (resp.headers.get("content-type") or "").lower()
            if body and len(body) <= max_bytes and _looks_like_image(body, ctype):
                return body, None
            return None, f"not an image ({ctype or 'no content-type'})"
        if resp is not None:
            return None, f"HTTP {resp.status}"
    except PlaywrightError:
        pass  # e.g. net::ERR_ABORTED when Chromium treats the icon as a download → fall back
    finally:
        await page.close()

    url = icon_url
    for _hop in range(limits.MAX_REDIRECTS + 1):
        if not policy.allow(url):
            return None, "redirect target blocked by sandbox policy"
        try:
            resp = await context.request.get(url, timeout=ICON_TIMEOUT_MS, max_redirects=0)
        except PlaywrightError as exc:
            return None, str(exc).split(chr(10), 1)[0]
        if 300 <= resp.status < 400 and resp.headers.get("location"):
            url = urljoin(url, resp.headers["location"])
            continue
        if not resp.ok:
            return None, f"HTTP {resp.status}"
        body = await resp.body()
        ctype = (resp.headers.get("content-type") or "").lower()
        if body and len(body) <= max_bytes and _looks_like_image(body, ctype):
            return body, None
        return None, f"not an image ({ctype or 'no content-type'})"
    return None, "too many redirects"
