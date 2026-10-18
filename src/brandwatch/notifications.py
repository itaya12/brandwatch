"""Notifications (spec §14 Settings → notifications: e-mail / Slack / Telegram, critical + daily digest).

``NotificationService`` fans a message out to the configured channels; every delivery (or
failure) is audited as ``notification.sent`` / ``notification.failed``. The ``log`` channel keeps
an in-memory outbox so demo mode and tests can assert on what *would* have been sent. Nothing
here ever sends takedown requests — notifications are for the analysts, not for third parties.
"""

from __future__ import annotations

import logging
import smtplib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any, Protocol

import httpx
import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.settings import Settings
from brandwatch.db.enums import FindingState, Severity
from brandwatch.db.models import AuditEvent, Brand, Candidate, Finding, ScanJob

log = logging.getLogger("brandwatch.notify")
_SEV_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass(slots=True)
class Message:
    subject: str
    body: str
    severity: Severity | None = None
    meta: dict[str, Any] = field(default_factory=dict)


class Notifier(Protocol):
    name: str

    def send(self, message: Message) -> None: ...


class LogNotifier:
    name = "log"

    def __init__(self) -> None:
        self.outbox: list[Message] = []

    def send(self, message: Message) -> None:
        self.outbox.append(message)
        log.info("[notify] %s", message.subject)


class SlackWebhookNotifier:
    name = "slack"

    def __init__(self, webhook_url: str, client: httpx.Client | None = None) -> None:
        self._url = webhook_url
        self._client = client or httpx.Client(timeout=10)

    def send(self, message: Message) -> None:
        text = f"*{message.subject}*\n{message.body}"
        r = self._client.post(self._url, json={"text": text})
        r.raise_for_status()


class TelegramNotifier:
    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str, client: httpx.Client | None = None) -> None:
        self._url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        self._chat = chat_id
        self._client = client or httpx.Client(timeout=10)

    def send(self, message: Message) -> None:
        r = self._client.post(
            self._url, json={"chat_id": self._chat, "text": f"{message.subject}\n\n{message.body}"}
        )
        r.raise_for_status()


class EmailNotifier:
    name = "email"

    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def send(self, message: Message) -> None:
        s = self._s
        if not (s.smtp_host and s.smtp_from and s.smtp_to):
            raise RuntimeError("SMTP not configured (SMTP_HOST / SMTP_FROM / SMTP_TO)")
        msg = EmailMessage()
        msg["Subject"] = message.subject
        msg["From"] = s.smtp_from
        msg["To"] = ", ".join(s.smtp_to)
        msg.set_content(message.body)
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as smtp:
            smtp.starttls()
            if s.smtp_user and s.smtp_password:
                smtp.login(s.smtp_user, s.smtp_password.get_secret_value())
            smtp.send_message(msg)


def build_notifiers(settings: Settings) -> list[Notifier]:
    out: list[Notifier] = []
    for ch in settings.notify_channels:
        if ch == "log":
            out.append(LogNotifier())
        elif ch == "slack" and settings.slack_webhook_url:
            out.append(SlackWebhookNotifier(settings.slack_webhook_url.get_secret_value()))
        elif ch == "telegram" and settings.telegram_bot_token and settings.telegram_chat_id:
            out.append(
                TelegramNotifier(
                    settings.telegram_bot_token.get_secret_value(), settings.telegram_chat_id
                )
            )
        elif ch == "email":
            out.append(EmailNotifier(settings))
    return out or [LogNotifier()]


class NotificationService:
    def __init__(self, settings: Settings, notifiers: list[Notifier] | None = None) -> None:
        self.settings = settings
        self.notifiers = notifiers if notifiers is not None else build_notifiers(settings)
        self.min_severity = Severity(settings.notify_min_severity)
        self.public_url = (settings.public_url or "").rstrip("/")

    def link(self, path: str) -> str:
        """An absolute link when PUBLIC_URL is set (Slack and mail make it clickable); the path otherwise."""
        return f"{self.public_url}{path}" if self.public_url else path

    def prefs(self, session: Session, workspace_id: uuid.UUID) -> dict[str, Any]:
        from brandwatch.tenancy import workspace_notify

        return workspace_notify(session, workspace_id, self.settings)

    @property
    def log_outbox(self) -> list[Message]:
        for n in self.notifiers:
            if isinstance(n, LogNotifier):
                return n.outbox
        return []

    def _deliver(
        self,
        session: Session,
        workspace_id: uuid.UUID,
        message: Message,
        *,
        kind: str,
        object_id=None,
        channels: list[str] | None = None,
    ) -> int:
        delivered = 0
        for n in self.notifiers:
            if channels is not None and n.name not in channels and n.name != "log":  # the log channel always keeps a copy
                continue
            try:
                n.send(message)
                delivered += 1
                action = f"notification.{kind}" if kind == "digest" else "notification.sent"
                session.add(AuditEvent(workspace_id=workspace_id, actor_type="system", action=action,
                                       object_type="notification", object_id=object_id,
                                       new_value={"channel": n.name, "subject": message.subject, "kind": kind}))  # fmt: skip
            except Exception as exc:  # noqa: BLE001 - a dead channel must not break the scan
                session.add(AuditEvent(workspace_id=workspace_id, actor_type="system", action="notification.failed",
                                       object_type="notification", object_id=object_id,
                                       new_value={"channel": n.name, "kind": kind}, reason=f"{type(exc).__name__}: {exc}"[:500]))  # fmt: skip
        session.flush()
        return delivered

    # ------------------------------------------------------------------ events
    def notify_finding(
        self, session: Session, finding: Finding, *, score: int, confidence: float, created: bool
    ) -> bool:
        brand = session.get(Brand, finding.brand_id)
        prefs = self.prefs(session, brand.workspace_id)
        if _SEV_ORDER.index(finding.severity) < _SEV_ORDER.index(Severity(prefs["min_severity"])):
            return False
        if str(brand.id) in prefs["brands_off"]:
            return False
        cand = session.get(Candidate, finding.candidate_id)
        subject = f"[BrandWatch] {finding.severity.value.upper()} {'new finding' if created else 'rescored'}: {cand.hostname} impersonates {brand.name}"
        body = (
            f"Host: {cand.hostname}\nURL: {cand.canonical_url}\nBrand: {brand.name}\n"
            f"Risk: {score}/100 ({finding.severity.value}) · confidence {confidence:.0f}%\n"
            f"Finding: {self.link(f'/ui/findings/{finding.id}')}\n"
            "Action: review the evidence, confirm or dismiss. Nothing is sent automatically."
        )
        self._deliver(session, brand.workspace_id, Message(subject, body, finding.severity, {"finding_id": str(finding.id)}),
                      kind="finding", object_id=finding.id, channels=prefs["channels"])  # fmt: skip
        return True

    def send_test(self, session: Session, workspace_id: uuid.UUID, *, by: str) -> int:
        """Settings → Notifications → "Send a test": one message through the chosen channels, audited like the rest."""
        prefs = self.prefs(session, workspace_id)
        body = (f"A test from BrandWatch, requested by {by}.\nAlerts: {prefs['min_severity']} and above"
                f"{' · digest on' if prefs['digest'] else ' · digest off'}.\nQueue: {self.link('/ui/findings?state=open')}")  # fmt: skip
        return self._deliver(session, workspace_id, Message("[BrandWatch] test notification", body), kind="test", channels=prefs["channels"])

    def daily_digest(
        self, session: Session, workspace_id: uuid.UUID, now: datetime | None = None
    ) -> bool:
        now = now or datetime.now(UTC)
        since = now - timedelta(days=1)
        prefs = self.prefs(session, workspace_id)
        if not prefs["digest"]:
            return False
        new = session.execute(
            sa.select(Finding.severity, sa.func.count())
            .join(Brand, Brand.id == Finding.brand_id)
            .where(Brand.workspace_id == workspace_id, Finding.created_at >= since)
            .group_by(Finding.severity)
        ).all()
        open_count = session.scalar(
            sa.select(sa.func.count()).select_from(Finding).join(Brand, Brand.id == Finding.brand_id)
            .where(Brand.workspace_id == workspace_id, Finding.state == FindingState.OPEN)
        )  # fmt: skip
        jobs = session.scalar(
            sa.select(sa.func.count()).select_from(ScanJob)
            .where(ScanJob.workspace_id == workspace_id, ScanJob.created_at >= since)
        )  # fmt: skip
        counts = {sev.value: 0 for sev in Severity}
        for sev, n in new:
            counts[sev.value] = n
        # the new High / Critical ones by name, each with its link: the digest is readable without opening the app
        top = session.execute(
            sa.select(Finding.id, Finding.severity, Candidate.hostname, Brand.name)
            .join(Brand, Brand.id == Finding.brand_id).join(Candidate, Candidate.id == Finding.candidate_id)
            .where(Brand.workspace_id == workspace_id, Finding.created_at >= since,
                   Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]), Finding.state == FindingState.OPEN)
            .order_by(Finding.severity.desc(), Finding.created_at.desc()).limit(20)
        ).all()  # fmt: skip
        lines = [f"  {sev.value.upper():8} {host} ({brand}) {self.link(f'/ui/findings/{fid}')}" for fid, sev, host, brand in top]
        woke = session.scalar(
            sa.select(sa.func.count()).select_from(Finding).join(Brand, Brand.id == Finding.brand_id)
            .where(Brand.workspace_id == workspace_id, Finding.state == FindingState.OPEN, Finding.snoozed_until > since, Finding.snoozed_until <= now)
        ) or 0  # fmt: skip
        subject = f"[BrandWatch] daily digest {now.date().isoformat()}: {sum(counts.values())} new finding(s), {open_count} open"
        body = (
            f"New findings (24h): critical {counts['critical']}, high {counts['high']}, medium {counts['medium']}, low {counts['low']}\n"
            f"Open findings awaiting a verdict: {open_count}\nScan jobs run (24h): {jobs}\n"
            + (("Waiting for a verdict:\n" + "\n".join(lines) + "\n") if lines else "")
            + (f"Back from snooze today: {woke}\n" if woke else "")
            + f"Review queue: {self.link('/ui/findings?state=open')}"
        )
        return self._deliver(session, workspace_id, Message(subject, body), kind="digest", channels=prefs["channels"]) > 0
