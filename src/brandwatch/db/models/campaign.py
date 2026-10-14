"""Campaign graph (spec §8, §21 — campaigns, campaign_nodes, campaign_edges)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from brandwatch.db.base import Base
from brandwatch.db.enums import EdgeType, NodeType
from brandwatch.db.types import JSONB, created_at, enum_type, fk, uuid_pk


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[uuid.UUID] = uuid_pk()
    brand_id: Mapped[uuid.UUID] = fk("brands.id", index=True)
    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    actor_profile: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = created_at()

    nodes: Mapped[list[CampaignNode]] = relationship(back_populates="campaign")
    edges: Mapped[list[CampaignEdge]] = relationship(back_populates="campaign")


class CampaignNode(Base):
    """A pivot node; ``included``/``triage_reason``/``ai_verdict`` hold the co-hosted triage result."""

    __tablename__ = "campaign_nodes"
    __table_args__ = (
        sa.UniqueConstraint(
            "campaign_id", "type", "value", name="uq_campaign_nodes_campaign_id_type_value"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    campaign_id: Mapped[uuid.UUID] = fk("campaigns.id")
    type: Mapped[NodeType] = mapped_column(enum_type(NodeType), nullable=False)
    value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    included: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    triage_reason: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    ai_verdict: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    campaign: Mapped[Campaign] = relationship(back_populates="nodes")


class CampaignEdge(Base):
    __tablename__ = "campaign_edges"

    id: Mapped[uuid.UUID] = uuid_pk()
    campaign_id: Mapped[uuid.UUID] = fk("campaigns.id")
    src_node_id: Mapped[uuid.UUID] = fk("campaign_nodes.id")
    dst_node_id: Mapped[uuid.UUID] = fk("campaign_nodes.id")
    type: Mapped[EdgeType] = mapped_column(enum_type(EdgeType), nullable=False)
    evidence_id: Mapped[uuid.UUID | None] = fk("evidence.id", nullable=True)

    campaign: Mapped[Campaign] = relationship(back_populates="edges")
