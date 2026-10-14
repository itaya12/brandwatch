"""Admin maintenance: delete a brand together with everything it produced ("start over").

Evidence tables are immutable by database trigger (spec §2). A purge is the one sanctioned
exception: it runs inside a single transaction with the immutability triggers suspended and
re-installed afterwards, is reachable only by an admin (DELETE /api/brands/{id}) and leaves an
audit event behind. Audit events themselves are never deleted.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import brandwatch.db.models  # noqa: F401 - registers every table on Base.metadata
from brandwatch.db.base import Base
from brandwatch.db.models import IMMUTABLE_TABLES

KEEP_TABLES: frozenset[str] = frozenset({"brands", "audit_events"})


@contextmanager
def immutability_suspended(session: Session) -> Iterator[None]:
    """Drop (SQLite) or disable (PostgreSQL) the immutability triggers for the duration of the
    block and restore them afterwards. On any error the transaction is rolled back, which also
    restores the SQLite triggers (DDL is transactional there)."""
    dialect = session.get_bind().dialect.name
    if dialect == "sqlite":
        rows = session.execute(
            sa.text(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_%'"
            )
        ).all()
        for name, _ddl in rows:
            session.execute(sa.text(f'DROP TRIGGER IF EXISTS "{name}"'))
        try:
            yield
        except Exception:
            session.rollback()  # the DROPs are rolled back with everything else
            raise
        for _name, ddl in rows:
            if ddl:
                session.execute(sa.text(ddl))
    else:
        tables = sorted({*IMMUTABLE_TABLES, "risk_scores"})
        for t in tables:
            session.execute(sa.text(f"ALTER TABLE {t} DISABLE TRIGGER USER"))
        try:
            yield
        except Exception:
            session.rollback()
            raise
        for t in tables:
            session.execute(sa.text(f"ALTER TABLE {t} ENABLE TRIGGER USER"))


def _brand_condition(table: sa.Table, brand_id: uuid.UUID, seen: frozenset[str]) -> Any | None:
    """A WHERE clause selecting the rows of ``table`` that belong to the brand, found by walking
    foreign keys up to ``brands.id`` (candidates → evidence → screenshots, jobs → events …).
    A table can reach the brand through several columns (an IOC through its finding, its
    evidence or its campaign); every path counts, so no row that points at the brand's data
    is left behind."""
    conds: list[Any] = []
    for col in table.columns:
        for fk in col.foreign_keys:
            parent = fk.column.table
            if parent.name == "brands":
                conds.append(col == brand_id)
            elif parent is not table and parent.name not in seen:
                cond = _brand_condition(parent, brand_id, seen | {table.name})
                if cond is not None:
                    pk = next(iter(parent.primary_key.columns))
                    conds.append(col.in_(sa.select(pk).where(cond)))
    if not conds:
        return None
    return conds[0] if len(conds) == 1 else sa.or_(*conds)


def artifact_locations(session: Session, brand_id: uuid.UUID) -> list[str]:
    """Evidence artifacts (screenshots, HTML, favicons) and fingerprint images of the brand, so
    the caller can remove the files once the rows are gone."""
    t = Base.metadata.tables
    out: list[str] = []
    cond = _brand_condition(t["evidence"], brand_id, frozenset())
    out += [
        loc for (loc,) in session.execute(
            sa.select(t["evidence"].c.artifact_location).where(cond)
        ) if loc
    ]  # fmt: skip
    fp = t["brand_fingerprints"]
    for logo, shots in session.execute(
        sa.select(fp.c.logo_path, fp.c.screenshots).where(fp.c.brand_id == brand_id)
    ):
        if logo:
            out.append(logo)
        for entry in (shots or {}).values() if isinstance(shots, dict) else []:
            if isinstance(entry, dict) and entry.get("artifact"):
                out.append(entry["artifact"])
    return sorted(set(out))


def purge_brand(session: Session, brand_id: uuid.UUID) -> dict[str, int]:
    """Delete the brand and every row reachable from it. Returns ``{table: rows deleted}``.
    When the workspace has no brand left afterwards, IOC rows that no longer link to anything
    are removed too (they can only have come from the purged brand)."""
    deleted: dict[str, int] = {}
    brands_t = Base.metadata.tables["brands"]
    workspace_id = session.execute(
        sa.select(brands_t.c.workspace_id).where(brands_t.c.id == brand_id)
    ).scalar()
    with immutability_suspended(session):
        # Children before parents. The schema has FK cycles (findings ↔ evidence), so the
        # topological order is not enough: retry a table that still has dependants until the
        # whole set is gone (or no progress is made, which means a real schema problem).
        pending = [
            (t, cond)
            for t in reversed(Base.metadata.sorted_tables)
            if t.name not in KEEP_TABLES
            and (cond := _brand_condition(t, brand_id, frozenset())) is not None
        ]
        # Break reference cycles first (findings.primary_evidence_id ↔ evidence.finding_id,
        # evidence.parent_evidence_id): nullable links inside the purge set are cleared.
        in_scope = {t.name for t, _ in pending}
        for table, cond in pending:
            nullable_links = {
                col.name: None
                for col in table.columns
                if col.nullable and any(fk.column.table.name in in_scope for fk in col.foreign_keys)
            }
            if nullable_links:
                session.execute(sa.update(table).where(cond).values(**nullable_links))
        while pending:
            still: list[tuple[sa.Table, Any]] = []
            for table, cond in pending:
                try:
                    with session.begin_nested():
                        n = session.execute(sa.delete(table).where(cond)).rowcount
                except IntegrityError:
                    still.append((table, cond))  # a dependant row is still there: later
                    continue
                if n:
                    deleted[table.name] = int(n)
            if len(still) == len(pending):
                raise RuntimeError(
                    "purge cannot make progress; tables still blocked: "
                    + ", ".join(t.name for t, _ in still)
                )
            pending = still
        deleted["brands"] = int(
            session.execute(sa.delete(brands_t).where(brands_t.c.id == brand_id)).rowcount
        )
        remaining = session.execute(
            sa.select(sa.func.count())
            .select_from(brands_t)
            .where(brands_t.c.workspace_id == workspace_id)
        ).scalar()
        if not remaining and "iocs" in Base.metadata.tables:
            iocs = Base.metadata.tables["iocs"]
            links = [c for c in iocs.columns if c.foreign_keys and c.name != "workspace_id"]
            n = session.execute(
                sa.delete(iocs).where(
                    iocs.c.workspace_id == workspace_id, *[c.is_(None) for c in links]
                )
            ).rowcount
            if n:
                deleted["iocs_orphaned"] = int(n)
    session.flush()
    return deleted
