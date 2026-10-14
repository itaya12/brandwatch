"""Quota / cost accounting (spec §12, §13): every provider call writes an ``api_usage`` row,
and the economic limits are checked *before* a call is made."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from brandwatch.config.settings import EconomicLimits
from brandwatch.db.models import ApiUsage


class InMemoryLedger:
    """Process-local ledger for tests, mocks and dry runs."""

    def __init__(self, limits: EconomicLimits | None = None) -> None:
        self.limits = limits or EconomicLimits()
        self.calls = 0
        self.paid_calls = 0
        self.spend = 0.0
        self.rows: list[dict[str, Any]] = []

    def check(self, provider: str, cost_usd: float) -> bool:
        if not cost_usd:  # same rule as the DB ledger: only paid calls count and can be refused
            return True
        if self.limits.max_api_calls and self.paid_calls + 1 > self.limits.max_api_calls:
            return False
        if self.limits.max_daily_spend and self.spend + cost_usd > self.limits.max_daily_spend:
            return False
        return True

    def record(self, provider: str, calls: int, cost_usd: float, job_id: Any = None) -> None:
        self.calls += calls
        self.paid_calls += calls if cost_usd else 0
        self.spend += cost_usd
        self.rows.append(
            {"provider": provider, "calls": calls, "cost_usd": cost_usd, "job_id": job_id}
        )


class DbUsageLedger:
    """Ledger backed by ``api_usage``; limits are evaluated over the trailing 24 hours."""

    def __init__(self, session: Session, workspace_id: uuid.UUID, limits: EconomicLimits) -> None:
        self.session = session
        self.workspace_id = workspace_id
        self.limits = limits

    def _window_totals(self) -> tuple[int, float]:
        """Paid calls and spend over the trailing 24 hours. Free calls (local DNS and WHOIS, the
        sandboxed browser, keyless lookups) are recorded for the dashboard but are not "API calls"
        the budget limits — counting them let a big scan use up the day's budget on DNS lookups."""
        since = datetime.now(UTC) - timedelta(hours=24)
        row = self.session.execute(
            sa.select(
                sa.func.coalesce(sa.func.sum(sa.case((ApiUsage.cost_usd > 0, ApiUsage.calls), else_=0)), 0),
                sa.func.coalesce(sa.func.sum(ApiUsage.cost_usd), 0),
            ).where(ApiUsage.workspace_id == self.workspace_id, ApiUsage.at >= since)
        ).one()
        return int(row[0]), float(row[1])

    def check(self, provider: str, cost_usd: float) -> bool:
        if not cost_usd:  # a free call never spends the budget, so the budget never refuses it
            return True
        calls, spend = self._window_totals()
        if self.limits.max_api_calls and calls + 1 > self.limits.max_api_calls:
            return False
        if self.limits.max_daily_spend and spend + cost_usd > self.limits.max_daily_spend:
            return False
        return True

    def record(self, provider: str, calls: int, cost_usd: float, job_id: Any = None) -> None:
        self.session.add(
            ApiUsage(
                workspace_id=self.workspace_id,
                provider=provider,
                job_id=job_id,
                calls=calls,
                cost_usd=Decimal(str(round(cost_usd, 4))),
            )
        )
        self.session.flush()
