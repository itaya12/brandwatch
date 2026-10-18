"""Automatic scans: how often each brand is scanned again, at what time, and which tasks run.

A brand is scanned automatically only when an analyst switched it on (``brands.schedule``); nothing
paid runs by itself. Each run is an ordinary brand scan whose job carries the chosen tasks, so the
scan console and report look the same as for a scan started by hand.

    every_hours  12 · 24 · 48 · 72 · 168 (twice a day … once a week)
    hour         preferred local hour 0–23, or None for "any time"; ``tz_offset`` is the browser's
                 ``getTimezoneOffset()`` (minutes to add to local time to get UTC) at save time
    tasks        any of ``TASKS``

The next run is counted from the last *automatic* run (a scan started by hand does not move it), and
lands on the preferred hour: "every day at 03:00" runs every day at 03:00.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

TASKS: dict[str, tuple[str, str]] = {
    "dnstwist": ("Look-alike domains", "typos and combinations of the brand's domains, checked in DNS"),
    "ct": ("New HTTPS certificates", "certificate-transparency logs: a phishing kit needs HTTPS"),
    "nrd": ("Newly registered domains", "yesterday's registrations that carry the brand"),
    "search": ("Google search", "the approved Google search queries, in each search country"),
    "urlscan": ("urlscan archive", "pages other researchers scanned that carry the brand"),
    "meta_ads": ("Facebook / Instagram ads", "ads that sell the brand's products, and the shops behind them"),
    "social": ("Fake social accounts", "Facebook pages and Instagram profiles under the brand's name"),
    "ai_answers": ("AI answers", "what ChatGPT, Gemini and Google AI Mode tell users about the brand's phone, e-mail and login"),
    "watchlist": ("Re-check the watchlist", "visit suspicious sites and open findings again to catch changes"),
    "fingerprint": ("Refresh the fingerprint", "re-read the official site: logo, colours, keywords"),
}  # fmt: skip
STREAM_TASKS = ("dnstwist", "ct", "nrd", "search", "urlscan")
FREQUENCIES: dict[int, str] = {12: "twice a day", 24: "every day", 48: "every 2 days", 72: "every 3 days", 168: "every week"}
DAYS_PER_MONTH = 30


@dataclass
class Schedule:
    enabled: bool = False
    every_hours: int = 24
    hour: int | None = 3
    tz_offset: int = 0  # minutes: UTC = local + tz_offset
    tasks: list[str] = field(default_factory=list)
    updated_at: str | None = None
    updated_by: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def label(self) -> str:
        when = FREQUENCIES.get(self.every_hours, f"every {self.every_hours} h")
        if self.hour is not None and self.every_hours >= 24:
            when += f" at {self.hour:02d}:00"
        return when


def default_tasks(detection: Any, retail: bool) -> list[str]:
    """What a scan of this brand does today: its track's streams, ads for resold brands, social
    accounts when on, and the watchlist."""
    out = [s for s in STREAM_TASKS if s in (getattr(detection, "streams", None) or [])]
    if retail:
        out.append("meta_ads")
    if getattr(detection, "social_accounts", True):
        out.append("social")
    if getattr(detection, "ai_answers", False):
        out.append("ai_answers")
    return [*out, "watchlist"]


def load(brand: Any, detection: Any) -> Schedule:
    raw = dict(getattr(brand, "schedule", None) or {})
    retail = (getattr(brand, "kind", None) or "service") == "retail"
    tasks = [t for t in raw.get("tasks") or [] if t in TASKS] if raw.get("tasks") is not None else default_tasks(detection, retail)
    hour = raw.get("hour", 3)
    return Schedule(
        enabled=bool(raw.get("enabled")), every_hours=int(raw.get("every_hours") or 24),
        hour=None if hour is None else max(0, min(23, int(hour))), tz_offset=int(raw.get("tz_offset") or 0),
        tasks=tasks, updated_at=raw.get("updated_at"), updated_by=raw.get("updated_by"),
    )  # fmt: skip


def clean(body: dict[str, Any]) -> dict[str, Any]:
    """A schedule as submitted → validated (unknown tasks dropped, ranges clamped)."""
    every = int(body.get("every_hours") or 24)
    if every not in FREQUENCIES:
        every = max(6, min(720, every))
    hour = body.get("hour")
    hour = None if hour in (None, "", "any") else max(0, min(23, int(hour)))
    tz = max(-840, min(840, int(body.get("tz_offset") or 0)))
    tasks = [t for t in TASKS if t in set(body.get("tasks") or [])]
    return {"enabled": bool(body.get("enabled")) and bool(tasks), "every_hours": every, "hour": hour,
            "tz_offset": tz, "tasks": tasks}  # fmt: skip


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def next_due(s: Schedule, last_auto: datetime | None, now: datetime) -> datetime:
    """When the next automatic run is due. Counted from the last automatic run (or from when the
    schedule was switched on), then moved to the preferred hour."""
    now = _aware(now)
    if last_auto is None:
        start = _aware(datetime.fromisoformat(s.updated_at)) if s.updated_at else now
        earliest = start
    else:
        earliest = _aware(last_auto) + timedelta(hours=s.every_hours) - timedelta(hours=3 if s.every_hours >= 24 else 0)
    if s.hour is None or s.every_hours < 24:
        return earliest if last_auto is not None else start
    minutes = (s.hour * 60 + s.tz_offset) % 1440  # the preferred local hour, in UTC
    cand = earliest.replace(hour=minutes // 60, minute=minutes % 60, second=0, microsecond=0)
    if cand < earliest:
        cand += timedelta(days=1)
    return cand


def cost_estimate(s: Schedule, *, approved_queries: int, search_max: int, geos: int, retail: bool,
                  ad_queries: int, shops_checked: int = 15, ai_requests: int = 0) -> dict[str, Any]:  # fmt: skip
    """An upper bound per run in USD, from the per-call prices of the paid APIs (SerpApi ~$0.01,
    SearchApi ~$0.004); DNS, certificate logs, new domains and urlscan are free."""
    lines: list[tuple[str, float]] = []
    if "search" in s.tasks and approved_queries:
        lines.append(("Google search", min(approved_queries, search_max) * max(1, geos) * 0.01))
    if "meta_ads" in s.tasks and retail:
        # ad_queries = page requests; + the shops checked in full (registry, two searches, the AI)
        lines.append(("Facebook / Instagram ads", ad_queries * 0.004 + shops_checked * 0.021))
    if "social" in s.tasks:
        lines.append(("Fake social accounts", (2 + 8 * 2) * 0.004 + 2 * 0.01))
    if "ai_answers" in s.tasks and ai_requests:
        # every approved question to every assistant, + up to two follow-ups and one Google search per wrong contact
        lines.append(("AI answers", ai_requests * 0.004 + min(ai_requests, 10) * (2 * 0.004 + 0.01)))
    per_run = sum(v for _k, v in lines)
    runs_per_month = DAYS_PER_MONTH * 24 / s.every_hours
    return {"lines": [{"task": k, "usd": round(v, 3)} for k, v in lines], "per_run": round(per_run, 2),
            "per_month": round(per_run * runs_per_month, 2), "runs_per_month": round(runs_per_month, 1)}  # fmt: skip


def view(session: Any, brand: Any, detection: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """Everything the brand page shows about automatic scans."""
    import sqlalchemy as sa

    from brandwatch.db.models import ScanJob

    now = _aware(now or datetime.now(UTC))
    s = load(brand, detection)
    jobs = session.scalars(
        sa.select(ScanJob).where(ScanJob.brand_id == brand.id, ScanJob.kind == "brand_scan")
        .order_by(ScanJob.created_at.desc()).limit(40)
    ).all()  # fmt: skip
    auto = [j for j in jobs if (j.payload or {}).get("scheduled")]
    last = auto[0] if auto else None
    due = next_due(s, last.created_at if last else None, now) if s.enabled else None
    return {
        **s.as_dict(), "label": s.label,
        "last": {"id": str(last.id), "at": _aware(last.created_at).isoformat(), "state": last.state.value} if last else None,
        "next": due.isoformat() if due else None, "auto_runs": len(auto),
    }  # fmt: skip
