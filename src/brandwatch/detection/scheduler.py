"""Watchlist scheduler (spec §6 watch window, §14 Operations Center "scheduled scans").

``WatchScheduler.tick()`` is a pure-ish, testable step; ``start()`` runs it on a daemon thread
every ``scheduler_interval_seconds``. Each tick:

1. **Expire** — WATCHING candidates whose content has not changed for ``watch_window_days`` move
   to LONG_WATCH; LONG_WATCH candidates older than ``long_watch_multiplier`` × window are
   DISMISSED (expired). Every transition is audited.
2. **Re-observe** — candidates whose ``next_scan_at`` is due are batched per brand into
   ``url_scan`` jobs (bounded per tick).
3. **Automatic brand scans** — only for brands whose automatic scans are switched on
   (``brands.schedule``, ``detection/schedule.py``): at the chosen frequency and hour, with the chosen
   tasks. Re-observing the watchlist (step 2) is one of those tasks.
4. **Daily digest** — once per UTC day per workspace (Phase 3 notifications).
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from brandwatch.config.settings import Settings
from brandwatch.db.enums import CandidateState, JobState
from brandwatch.db.models import AuditEvent, Brand, Candidate, ScanJob, Workspace
from brandwatch.db.types import utcnow
from brandwatch.detection.runner import load_brand_config
from brandwatch.jobs.queue import JobQueue

log = logging.getLogger(__name__)


@dataclass(slots=True)
class TickReport:
    at: datetime
    long_watched: int = 0
    expired: int = 0
    rescan_jobs: list[uuid.UUID] = field(default_factory=list)
    rescanned_candidates: int = 0
    brand_scan_jobs: list[uuid.UUID] = field(default_factory=list)
    digests_sent: int = 0
    errors: list[str] = field(default_factory=list)


class WatchScheduler:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        queue: JobQueue,
        settings: Settings,
        *,
        max_rescans_per_tick: int = 200,
        notifier=None,
    ) -> None:
        self._factory = session_factory
        self._queue = queue
        self._settings = settings
        self._max_rescans = max_rescans_per_tick
        self._notifier = notifier
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_report: TickReport | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="watch-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        from brandwatch.db.base import writer_thread

        writer_thread()  # the scheduler reads then writes: take the lock up front
        interval = self._settings.scheduler_interval_seconds
        while not self._stop.wait(interval):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - the scheduler must survive a bad tick
                log.exception("scheduler tick failed")

    # ------------------------------------------------------------------ one step
    def tick(self, now: datetime | None = None) -> TickReport:
        now = now or utcnow()
        report = TickReport(at=now)
        with self._factory() as session:
            try:
                self._expire(session, now, report)
                self._rescan_due(session, now, report)
                self._brand_scans(session, now, report)
                session.commit()
            except Exception as exc:  # noqa: BLE001
                session.rollback()
                report.errors.append(f"{type(exc).__name__}: {exc}")
                raise
        if self._notifier is not None:
            try:
                report.digests_sent = self._digests(now)
            except Exception as exc:  # noqa: BLE001
                report.errors.append(f"digest: {type(exc).__name__}: {exc}")
        self.last_report = report
        return report

    # ------------------------------------------------------------------ steps
    def _expire(self, session: Session, now: datetime, report: TickReport) -> None:
        brands = {b.id: b for b in session.scalars(sa.select(Brand)).all()}
        cfgs = {bid: load_brand_config(session, bid).detection for bid in brands}
        cands = session.scalars(
            sa.select(Candidate).where(
                Candidate.state.in_([CandidateState.WATCHING, CandidateState.LONG_WATCH])
            )
        ).all()
        for c in cands:
            det = cfgs.get(c.brand_id)
            if det is None:
                continue
            window = timedelta(days=det.watch_window_days)
            age = now - _aware(c.first_seen)
            if c.state is CandidateState.WATCHING and age > window:
                _transition(session, brands[c.brand_id].workspace_id, c, CandidateState.LONG_WATCH,
                            f"no change for {det.watch_window_days}d → long watch")  # fmt: skip
                c.next_scan_at = now + timedelta(hours=det.watch_cadence_hours * 3)
                report.long_watched += 1
            elif c.state is CandidateState.LONG_WATCH and age > window * det.long_watch_multiplier:
                _transition(session, brands[c.brand_id].workspace_id, c, CandidateState.DISMISSED,
                            f"expired after {det.watch_window_days * det.long_watch_multiplier}d without activity")  # fmt: skip
                c.next_scan_at = None
                report.expired += 1
        session.flush()

    def _rescan_due(self, session: Session, now: datetime, report: TickReport) -> None:
        from brandwatch.detection import schedule as sched_mod

        # only brands whose automatic scans are on and include "re-check the watchlist"
        allowed = [
            b.id for b in session.scalars(sa.select(Brand)).all()
            if (sc := sched_mod.load(b, load_brand_config(session, b.id).detection)).enabled and "watchlist" in sc.tasks
        ]  # fmt: skip
        if not allowed:
            return
        due = session.scalars(
            sa.select(Candidate)
            .where(
                Candidate.brand_id.in_(allowed),
                Candidate.next_scan_at.is_not(None),
                Candidate.next_scan_at <= now,
                Candidate.state.in_(
                    [CandidateState.WATCHING, CandidateState.LONG_WATCH, CandidateState.FLAGGED]
                ),
            )
            .order_by(Candidate.priority.desc(), Candidate.next_scan_at)
            .limit(self._max_rescans)
        ).all()
        from brandwatch.detection.protect import is_protected, protected_set

        protected: dict[uuid.UUID, set[str]] = {}
        by_brand: dict[uuid.UUID, list[Candidate]] = {}
        for c in due:
            ps = protected.setdefault(c.brand_id, protected_set(session, c.brand_id))
            if is_protected(
                c.hostname, ps
            ):  # the brand's own site: off the watchlist, not re-scanned
                c.state = CandidateState.DISMISSED
                c.next_scan_at = None
                continue
            by_brand.setdefault(c.brand_id, []).append(c)
        for brand_id, cands in by_brand.items():
            brand = session.get(Brand, brand_id)
            for c in cands:  # push next_scan_at forward so a slow job is not re-queued next tick
                c.next_scan_at = now + timedelta(hours=1)
            session.commit()
            job_id = self._queue.enqueue(
                "url_scan",
                {
                    "urls": [c.canonical_url for c in cands],
                    "scheduled": True,
                    "reason": "watchlist_due",
                },
                workspace_id=brand.workspace_id,
                brand_id=brand_id,
            )
            report.rescan_jobs.append(job_id)
            report.rescanned_candidates += len(cands)

    def _brand_scans(self, session: Session, now: datetime, report: TickReport) -> None:
        """A brand scan for every brand whose automatic scans are on and due."""
        from brandwatch.detection import schedule as sched_mod

        for brand in session.scalars(sa.select(Brand)).all():
            sc = sched_mod.load(brand, load_brand_config(session, brand.id).detection)
            scan_tasks = [t for t in sc.tasks if t != "watchlist"]
            if not sc.enabled or not scan_tasks:
                continue
            jobs = session.scalars(
                sa.select(ScanJob).where(ScanJob.brand_id == brand.id, ScanJob.kind == "brand_scan")
                .order_by(ScanJob.created_at.desc()).limit(40)
            ).all()  # fmt: skip
            if any(j.state in (JobState.QUEUED, JobState.RUNNING) for j in jobs):
                continue  # one scan at a time per brand
            last = next((j for j in jobs if (j.payload or {}).get("scheduled")), None)
            if now < sched_mod.next_due(sc, last.created_at if last else None, now):
                continue
            job_id = self._queue.enqueue(
                "brand_scan",
                {"scheduled": True, "reason": "schedule", "schedule": sc.label, "tasks": scan_tasks,
                 "rebuild_baseline": "fingerprint" in scan_tasks},
                workspace_id=brand.workspace_id,
                brand_id=brand.id,
            )  # fmt: skip
            report.brand_scan_jobs.append(job_id)

    def _digests(self, now: datetime) -> int:
        sent = 0
        with self._factory() as session:
            for ws in session.scalars(sa.select(Workspace)).all():
                last = session.scalar(
                    sa.select(sa.func.max(AuditEvent.at)).where(
                        AuditEvent.workspace_id == ws.id, AuditEvent.action == "notification.digest"
                    )
                )
                if last is not None and _aware(last).date() == now.date():
                    continue
                if self._notifier.daily_digest(session, ws.id, now):
                    sent += 1
            session.commit()
        return sent


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _transition(
    session: Session, workspace_id: uuid.UUID, cand: Candidate, to: CandidateState, reason: str
) -> None:
    old = cand.state
    cand.state = to
    session.add(
        AuditEvent(
            workspace_id=workspace_id,
            actor_type="system",
            actor_id=None,
            action=f"candidate.{to.value}",
            object_type="candidate",
            object_id=cand.id,
            old_value={"state": old.value},
            new_value={"state": to.value},
            reason=reason,
        )  # fmt: skip
    )
