"""Brand & attack-surface baseline (spec §21 — brands, brand_domains, brand_fingerprints, configs).

Resolution of the spec's circular reference (brands.config_id <-> configs.brand_id): only
``configs.brand_id`` exists, UNIQUE and nullable, so a brand has at most one config and
global presets can live in ``configs`` without a brand.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.types import JSONB, CIText, created_at, fk, uuid_pk


class Brand(Base):
    __tablename__ = "brands"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = fk("workspaces.id", index=True)
    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    positioning: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    vertical: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    # "retail": its products are resold by other shops (scam-shop detection from Meta ads runs);
    # "service": nobody else sells it (phase 2 looks for fake pages instead)
    kind: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="service", server_default="service"
    )
    # countries, ad_keywords, products [{name, price, currency, country, source}], official_pages
    profile: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # automatic scans: {enabled, every_hours, hour, tz_offset, tasks} — detection/schedule.py
    schedule: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # a regional campaign of a global brand: its main brand and the region's name — detection/regions.py
    parent_id: Mapped[uuid.UUID | None] = fk("brands.id", nullable=True, index=True)
    region: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    created_at: Mapped[datetime] = created_at()

    @property
    def search_name(self) -> str:
        """The brand's own name for searching and matching: a regional campaign "ShopNova · Israel" is
        displayed with its region, but its ads, queries and social pages look for "ShopNova"."""
        suffix = f" · {self.region}" if self.parent_id and self.region else ""
        return self.name[: -len(suffix)] if suffix and self.name.endswith(suffix) else self.name

    domains: Mapped[list[BrandDomain]] = relationship(back_populates="brand")
    config: Mapped[Config | None] = relationship(back_populates="brand", uselist=False)


class BrandDomain(Base):
    __tablename__ = "brand_domains"
    __table_args__ = (
        sa.UniqueConstraint("brand_id", "domain", name="uq_brand_domains_brand_id_domain"),
        sa.Index("ix_brand_domains_domain", "domain"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    brand_id: Mapped[uuid.UUID] = fk("brands.id")
    domain: Mapped[str] = mapped_column(CIText, nullable=False)
    is_official: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="official")

    brand: Mapped[Brand] = relationship(back_populates="domains")


class BrandFingerprint(Base):
    """Brand Attack-Surface Profile (spec §11). Versioned; one row per onboarding/refresh."""

    __tablename__ = "brand_fingerprints"
    __table_args__ = (
        sa.UniqueConstraint("brand_id", "version", name="uq_brand_fingerprints_brand_id_version"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    brand_id: Mapped[uuid.UUID] = fk("brands.id")
    version: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    favicon_mmh3: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    favicon_phash: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    logo_path: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    screenshots: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    colors: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    keywords: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    features: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    llm_analysis: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    asns: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    cdns: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    certificates: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    auth_methods: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    payment_providers: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    languages: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    countries: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = created_at()


class Config(Base):
    """Per-brand detection / economic / scoring config (spec §13).

    System security limits are deliberately NOT here — they live in
    :mod:`brandwatch.security.limits` and cannot be overridden per brand.
    """

    __tablename__ = "configs"

    id: Mapped[uuid.UUID] = uuid_pk()
    brand_id: Mapped[uuid.UUID | None] = fk("brands.id", nullable=True, unique=True)
    preset: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="basic")
    detection: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    economic_limits: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    scoring: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = created_at()

    brand: Mapped[Brand | None] = relationship(back_populates="config")
