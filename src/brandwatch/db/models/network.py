"""Distinct network objects (spec §2, §21): Domain != Hostname != URL."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from brandwatch.db.base import Base
from brandwatch.db.types import INET, JSONB, CIText, TZDateTime, fk, utcnow, uuid_pk


class Registrar(Base):
    __tablename__ = "registrars"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(sa.Text, nullable=False, unique=True)
    abuse_email: Mapped[str | None] = mapped_column(sa.Text, nullable=True)


class Asn(Base):
    __tablename__ = "asns"

    id: Mapped[uuid.UUID] = uuid_pk()
    asn: Mapped[int] = mapped_column(sa.Integer, nullable=False, unique=True)
    org: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    country: Mapped[str | None] = mapped_column(sa.String(2), nullable=True)


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(CIText, nullable=False, unique=True)
    registrar_id: Mapped[uuid.UUID | None] = fk("registrars.id", nullable=True)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)


class Hostname(Base):
    __tablename__ = "hostnames"

    id: Mapped[uuid.UUID] = uuid_pk()
    domain_id: Mapped[uuid.UUID] = fk("domains.id", index=True)
    fqdn: Mapped[str] = mapped_column(CIText, nullable=False, unique=True)


class Url(Base):
    __tablename__ = "urls"

    id: Mapped[uuid.UUID] = uuid_pk()
    hostname_id: Mapped[uuid.UUID] = fk("hostnames.id", index=True)
    url: Mapped[str] = mapped_column(sa.Text, nullable=False)
    path: Mapped[str | None] = mapped_column(sa.Text, nullable=True)


class IpAddress(Base):
    __tablename__ = "ip_addresses"

    id: Mapped[uuid.UUID] = uuid_pk()
    ip: Mapped[str] = mapped_column(INET, nullable=False, unique=True)
    asn_id: Mapped[uuid.UUID | None] = fk("asns.id", nullable=True)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)
    country: Mapped[str | None] = mapped_column(sa.String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    lat: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    lon: Mapped[float | None] = mapped_column(sa.Float, nullable=True)
    org: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    geo_source: Mapped[str | None] = mapped_column(sa.String(64), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)


class Certificate(Base):
    __tablename__ = "certificates"

    id: Mapped[uuid.UUID] = uuid_pk()
    fingerprint_sha256: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    issuer: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    sans: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    seen_at: Mapped[datetime] = mapped_column(TZDateTime, nullable=False, default=utcnow)


class Nameserver(Base):
    __tablename__ = "nameservers"

    id: Mapped[uuid.UUID] = uuid_pk()
    host: Mapped[str] = mapped_column(CIText, nullable=False, unique=True)
