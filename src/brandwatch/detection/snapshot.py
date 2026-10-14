"""A public urlscan.io snapshot of a site that will not let BrandWatch's own browser in.

Bot protection (Akamai, Cloudflare, DataDome …) answers 403 / a bot check to a scanner. Someone else's browser has
often seen the page already, and urlscan.io keeps its screenshot (public) and, for a logged-in caller, its DOM. Used
for the brand's own site (``baseline.build_baseline``) and for every suspect that refuses the scan
(``enrichment``): the screenshot and the title are enough to compare a look-alike with the real thing, and the
snapshot is always labelled as such — it is someone else's, and possibly old.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from brandwatch.providers.registry import ProviderRegistry


async def urlscan_snapshot(
    providers: ProviderRegistry, hosts: list[str], scan_id: str | None = None, peek: bool = False
) -> tuple[dict[str, Any] | None, str]:
    """The newest public urlscan.io scan of the homepage (or the scan the analyst pointed at), and — when there is
    none — WHY: not configured, rate limited, key rejected, never scanned … A snapshot is a fallback, so nothing
    here may break onboarding, but a failure must never be silent either. ``peek`` only looks."""
    why = "urlscan.io was not asked"
    seen: set[str] = set()
    for h in hosts:
        if not h or h in seen:
            continue
        seen.add(h)
        try:
            res = await providers.urlscan().snapshot(h, scan_id=scan_id, peek=peek)
        except Exception as exc:  # noqa: BLE001
            why = f"urlscan.io: {type(exc).__name__}: {str(exc)[:140]}"
            continue
        data = res.data or {}
        if res.ok and (data.get("screenshot_png") or (peek and data.get("scan_id"))):
            return dict(data), ""
        why = str(res.error or data.get("note") or "urlscan.io answered without a usable scan")
        if scan_id:  # the analyst named one scan: other hosts would not change the answer
            break
    return None, why


async def urlscan_picture(providers: ProviderRegistry, hosts: list[str]) -> tuple[dict[str, Any] | None, str]:
    """A picture that shows something, for a page whose own screenshot is blank: a public scan of the site itself, or of an address that
    names it (a tracking redirect it sits behind). A scan whose picture is blank too is skipped. ``(None, why)`` when there is none."""
    why = "urlscan.io was not asked"
    for h in dict.fromkeys(x for x in hosts if x):
        try:
            res = await providers.urlscan().picture_of(h)
        except Exception as exc:  # noqa: BLE001
            why = f"urlscan.io: {type(exc).__name__}: {str(exc)[:140]}"
            continue
        data = res.data or {}
        if res.ok and data.get("screenshot_png"):
            return dict(data), ""
        why = str(res.error or data.get("note") or "urlscan.io answered without a usable scan")
    return None, why
