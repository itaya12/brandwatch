"""Initial schema - every table of spec section 21 with its constraints.

Revision ID: 001
Revises:
Create Date: 2026-10-07

Self-contained on purpose: type aliases and enum values are inlined so this migration keeps
its meaning even when application models change later. Dialect-aware: PostgreSQL gets citext /
inet / jsonb / native enums / plpgsql triggers; SQLite gets portable equivalents.

Invariants enforced by the DB (not Python):
  * uq_risk_scores_current — exactly one is_current score per finding (partial unique index)
  * dedup uniques on candidates, candidate_sources, iocs, campaign_nodes, scan_events
  * ON DELETE RESTRICT on every FK — history never cascade-deletes
  * immutability triggers: UPDATE/DELETE rejected on evidence*, observations, audit_events;
    risk_scores rejects DELETE and any UPDATE other than flipping is_current
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---- portable types (mirror brandwatch.db.types at the time of this revision) ----------
GUID = sa.Uuid(as_uuid=True)
CIText = sa.String(collation="NOCASE").with_variant(postgresql.CITEXT(), "postgresql")
INET = sa.String(45).with_variant(postgresql.INET(), "postgresql")
JSONB = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
TZDateTime = sa.DateTime(timezone=True)
Money = sa.Numeric(10, 4)
Percent = sa.Numeric(5, 2)

ENUMS: dict[str, list[str]] = {
    "user_role": ["admin", "analyst", "viewer"],
    "candidate_state": ["new", "watching", "analyzing", "flagged", "long_watch", "dismissed"],
    "finding_state": ["open", "confirmed", "dismissed"],
    "analyst_verdict": ["phishing", "legitimate", "suspicious", "unknown"],
    "severity": ["low", "medium", "high", "critical"],
    "surface": ["name", "subdomain", "path", "content"],
    "discovery_source": [
        "dnstwist",
        "combosquat",
        "llm",
        "ct",
        "nrd",
        "serpapi",
        "urlscan",
        "urlhaus",
        "phishtank",
        "logo_search",
        "manual",
    ],
    "scanner_profile": ["datacenter", "residential", "mobile"],
    "evidence_type": [
        "screenshot",
        "html",
        "http",
        "dns",
        "whois",
        "ssl",
        "reputation",
        "favicon",
        "certificate",
        "kit",
    ],
    "provider_status": ["positive", "negative", "unknown", "error", "not_applicable"],
    "evidence_role": ["primary", "supporting", "contradicting", "context"],
    "job_state": ["queued", "running", "done", "failed", "cancelled"],
    "takedown_state": [
        "draft",
        "review",
        "approved",
        "sent",
        "acknowledged",
        "in_progress",
        "resolved",
        "rejected",
        "reopened",
    ],
    "ioc_type": [
        "domain",
        "hostname",
        "url",
        "ip",
        "asn",
        "cert_fp",
        "favicon_hash",
        "sha256",
        "email",
        "telegram",
        "wallet",
        "tracking_id",
    ],
    "node_type": ["domain", "hostname", "ip", "certificate", "registrant", "tracking_id"],
    "edge_type": ["passive_dns", "favicon", "cert", "reverse_whois", "reverse_ns", "tracking_id"],
}

# Append-only tables: UPDATE and DELETE rejected.
IMMUTABLE_TABLES: tuple[str, ...] = (
    "audit_events",
    "observations",
    "evidence",
    "screenshots",
    "html_snapshots",
    "http_responses",
    "dns_observations",
    "whois_observations",
    "ssl_observations",
    "reputation_observations",
)
# Append-only except for the listed columns.
PARTIALLY_MUTABLE_TABLES: dict[str, tuple[str, ...]] = {"risk_scores": ("is_current",)}


def _dialect() -> str:
    return op.get_bind().dialect.name


def _enum(name: str) -> sa.types.TypeEngine:
    """Native enum on PostgreSQL (pre-created in upgrade()); VARCHAR + CHECK elsewhere."""
    if _dialect() == "postgresql":
        return postgresql.ENUM(*ENUMS[name], name=name, create_type=False)
    return sa.Enum(*ENUMS[name], name=name, native_enum=False, create_constraint=True)


def _frozen_columns(table: str) -> list[str]:
    insp = sa.inspect(op.get_bind())
    mutable = set(PARTIALLY_MUTABLE_TABLES[table])
    return [c["name"] for c in insp.get_columns(table) if c["name"] not in mutable]


def _create_immutability_triggers() -> None:
    if _dialect() == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION brandwatch_reject_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$
            BEGIN
              RAISE EXCEPTION 'immutable table %: % not allowed', TG_TABLE_NAME, TG_OP
                USING ERRCODE = 'P0001';
            END $$;
            """
        )
        for table in IMMUTABLE_TABLES:
            op.execute(
                f"CREATE TRIGGER trg_{table}_immutable BEFORE UPDATE OR DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION brandwatch_reject_mutation()"
            )
        for table, mutable in PARTIALLY_MUTABLE_TABLES.items():
            op.execute(
                f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION brandwatch_reject_mutation()"
            )
            cols = ", ".join(f"'{c}'" for c in mutable)
            op.execute(
                f"""
                CREATE OR REPLACE FUNCTION brandwatch_{table}_guard() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                  IF (to_jsonb(OLD) - ARRAY[{cols}]::text[])
                     IS DISTINCT FROM (to_jsonb(NEW) - ARRAY[{cols}]::text[]) THEN
                    RAISE EXCEPTION '{table} is append-only: only {cols} may change'
                      USING ERRCODE = 'P0001';
                  END IF;
                  RETURN NEW;
                END $$;
                """
            )
            op.execute(
                f"CREATE TRIGGER trg_{table}_guard BEFORE UPDATE ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION brandwatch_{table}_guard()"
            )
        return

    # SQLite (and any other dialect): RAISE(ABORT) triggers.
    for table in IMMUTABLE_TABLES:
        for verb in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER trg_{table}_no_{verb.lower()} BEFORE {verb} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, 'immutable table {table}: {verb} not allowed'); END"
            )
    for table in PARTIALLY_MUTABLE_TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} "
            f"BEGIN SELECT RAISE(ABORT, 'immutable table {table}: DELETE not allowed'); END"
        )
        changed = " OR ".join(f"NEW.{c} IS NOT OLD.{c}" for c in _frozen_columns(table))
        op.execute(
            f"CREATE TRIGGER trg_{table}_guard BEFORE UPDATE ON {table} WHEN ({changed}) "
            f"BEGIN SELECT RAISE(ABORT, '{table} is append-only: only "
            f"{', '.join(PARTIALLY_MUTABLE_TABLES[table])} may change'); END"
        )


def upgrade() -> None:
    if _dialect() == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS citext")
        op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        bind = op.get_bind()
        for name, values in ENUMS.items():
            postgresql.ENUM(*values, name=name).create(bind, checkfirst=True)

    op.create_table(
        "api_providers",
        sa.Column("id", GUID, nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("config", JSONB, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_api_providers"),
        sa.UniqueConstraint("key", name="uq_api_providers_key"),
    )

    op.create_table(
        "asns",
        sa.Column("id", GUID, nullable=False),
        sa.Column("asn", sa.Integer(), nullable=False),
        sa.Column("org", sa.Text(), nullable=True),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_asns"),
        sa.UniqueConstraint("asn", name="uq_asns_asn"),
    )

    op.create_table(
        "certificates",
        sa.Column("id", GUID, nullable=False),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("sans", JSONB, nullable=True),
        sa.Column("seen_at", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_certificates"),
        sa.UniqueConstraint("fingerprint_sha256", name="uq_certificates_fingerprint_sha256"),
    )

    op.create_table(
        "nameservers",
        sa.Column("id", GUID, nullable=False),
        sa.Column("host", CIText, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_nameservers"),
        sa.UniqueConstraint("host", name="uq_nameservers_host"),
    )

    op.create_table(
        "registrars",
        sa.Column("id", GUID, nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("abuse_email", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_registrars"),
        sa.UniqueConstraint("name", name="uq_registrars_name"),
    )

    op.create_table(
        "risk_score_versions",
        sa.Column("id", GUID, nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("weights", JSONB, nullable=False),
        sa.Column("thresholds", JSONB, nullable=False),
        sa.Column("combination_rules", JSONB, nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_risk_score_versions"),
        sa.UniqueConstraint("version", name="uq_risk_score_versions_version"),
    )

    op.create_table(
        "rule_versions",
        sa.Column("id", GUID, nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_rule_versions"),
        sa.UniqueConstraint("kind", "version", name="uq_rule_versions_kind_version"),
    )

    op.create_table(
        "workspaces",
        sa.Column("id", GUID, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_workspaces"),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("dek_wrapped", sa.LargeBinary(), nullable=False),
        sa.Column("last4", sa.String(length=8), nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("rotated_at", TZDateTime, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_api_keys"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_api_keys_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("workspace_id", "provider", name="uq_api_keys_workspace_id_provider"),
    )

    op.create_table(
        "audit_events",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", GUID, nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("object_type", sa.String(length=64), nullable=False),
        sa.Column("object_id", GUID, nullable=True),
        sa.Column("old_value", JSONB, nullable=True),
        sa.Column("new_value", JSONB, nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_audit_events_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_audit_events_object", "audit_events", ["object_type", "object_id"], unique=False
    )
    op.create_index(
        "ix_audit_events_workspace_at", "audit_events", ["workspace_id", "at"], unique=False
    )

    op.create_table(
        "brands",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("positioning", sa.Text(), nullable=True),
        sa.Column("vertical", sa.String(length=64), nullable=True),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_brands"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_brands_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_brands_workspace_id", "brands", ["workspace_id"], unique=False)

    op.create_table(
        "domains",
        sa.Column("id", GUID, nullable=False),
        sa.Column("name", CIText, nullable=False),
        sa.Column("registrar_id", GUID, nullable=True),
        sa.Column("first_seen", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_domains"),
        sa.ForeignKeyConstraint(
            ["registrar_id"],
            ["registrars.id"],
            name="fk_domains_registrar_id_registrars",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("name", name="uq_domains_name"),
    )

    op.create_table(
        "ip_addresses",
        sa.Column("id", GUID, nullable=False),
        sa.Column("ip", INET, nullable=False),
        sa.Column("asn_id", GUID, nullable=True),
        sa.Column("first_seen", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_ip_addresses"),
        sa.ForeignKeyConstraint(
            ["asn_id"], ["asns.id"], name="fk_ip_addresses_asn_id_asns", ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("ip", name="uq_ip_addresses_ip"),
    )

    op.create_table(
        "users",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("email", CIText, nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", _enum("user_role"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_users_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_workspace_id", "users", ["workspace_id"], unique=False)

    op.create_table(
        "brand_domains",
        sa.Column("id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=False),
        sa.Column("domain", CIText, nullable=False),
        sa.Column("is_official", sa.Boolean(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_brand_domains"),
        sa.ForeignKeyConstraint(
            ["brand_id"],
            ["brands.id"],
            name="fk_brand_domains_brand_id_brands",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("brand_id", "domain", name="uq_brand_domains_brand_id_domain"),
    )
    op.create_index("ix_brand_domains_domain", "brand_domains", ["domain"], unique=False)

    op.create_table(
        "brand_fingerprints",
        sa.Column("id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("favicon_mmh3", sa.BigInteger(), nullable=True),
        sa.Column("favicon_phash", sa.String(length=64), nullable=True),
        sa.Column("logo_path", sa.Text(), nullable=True),
        sa.Column("screenshots", JSONB, nullable=True),
        sa.Column("colors", JSONB, nullable=True),
        sa.Column("keywords", JSONB, nullable=True),
        sa.Column("features", JSONB, nullable=True),
        sa.Column("llm_analysis", JSONB, nullable=True),
        sa.Column("asns", JSONB, nullable=True),
        sa.Column("cdns", JSONB, nullable=True),
        sa.Column("certificates", JSONB, nullable=True),
        sa.Column("auth_methods", JSONB, nullable=True),
        sa.Column("payment_providers", JSONB, nullable=True),
        sa.Column("languages", JSONB, nullable=True),
        sa.Column("countries", JSONB, nullable=True),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_brand_fingerprints"),
        sa.ForeignKeyConstraint(
            ["brand_id"],
            ["brands.id"],
            name="fk_brand_fingerprints_brand_id_brands",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("brand_id", "version", name="uq_brand_fingerprints_brand_id_version"),
    )

    op.create_table(
        "campaigns",
        sa.Column("id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("actor_profile", JSONB, nullable=True),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_campaigns"),
        sa.ForeignKeyConstraint(
            ["brand_id"], ["brands.id"], name="fk_campaigns_brand_id_brands", ondelete="RESTRICT"
        ),
    )
    op.create_index("ix_campaigns_brand_id", "campaigns", ["brand_id"], unique=False)

    op.create_table(
        "candidates",
        sa.Column("id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=False),
        sa.Column("canonical_domain", CIText, nullable=False),
        sa.Column("canonical_url", sa.Text(), nullable=False),
        sa.Column("hostname", CIText, nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("state", _enum("candidate_state"), nullable=False),
        sa.Column("surface", _enum("surface"), nullable=False),
        sa.Column("first_seen", TZDateTime, nullable=False),
        sa.Column("last_seen", TZDateTime, nullable=False),
        sa.Column("next_scan_at", TZDateTime, nullable=True),
        sa.Column("scan_count", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_candidates"),
        sa.ForeignKeyConstraint(
            ["brand_id"], ["brands.id"], name="fk_candidates_brand_id_brands", ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "brand_id", "canonical_url", name="uq_candidates_brand_id_canonical_url"
        ),
    )
    op.create_index(
        "ix_candidates_brand_id_state", "candidates", ["brand_id", "state"], unique=False
    )
    op.create_index(
        "ix_candidates_due",
        "candidates",
        ["next_scan_at"],
        unique=False,
        postgresql_where=sa.text("state IN ('watching', 'long_watch')"),
        sqlite_where=sa.text("state IN ('watching', 'long_watch')"),
    )

    op.create_table(
        "configs",
        sa.Column("id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=True),
        sa.Column("preset", sa.String(length=32), nullable=False),
        sa.Column("detection", JSONB, nullable=False),
        sa.Column("economic_limits", JSONB, nullable=False),
        sa.Column("scoring", JSONB, nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_configs"),
        sa.ForeignKeyConstraint(
            ["brand_id"], ["brands.id"], name="fk_configs_brand_id_brands", ondelete="RESTRICT"
        ),
        sa.UniqueConstraint("brand_id", name="uq_configs_brand_id"),
    )

    op.create_table(
        "hostnames",
        sa.Column("id", GUID, nullable=False),
        sa.Column("domain_id", GUID, nullable=False),
        sa.Column("fqdn", CIText, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_hostnames"),
        sa.ForeignKeyConstraint(
            ["domain_id"],
            ["domains.id"],
            name="fk_hostnames_domain_id_domains",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("fqdn", name="uq_hostnames_fqdn"),
    )
    op.create_index("ix_hostnames_domain_id", "hostnames", ["domain_id"], unique=False)

    op.create_table(
        "reports",
        sa.Column("id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("format", sa.String(length=16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_reports"),
        sa.ForeignKeyConstraint(
            ["brand_id"], ["brands.id"], name="fk_reports_brand_id_brands", ondelete="RESTRICT"
        ),
    )
    op.create_index("ix_reports_brand_id", "reports", ["brand_id"], unique=False)

    op.create_table(
        "scan_jobs",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=True),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("state", _enum("job_state"), nullable=False),
        sa.Column("payload", JSONB, nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("cost_usd", Money, nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", TZDateTime, nullable=True),
        sa.Column("finished_at", TZDateTime, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_scan_jobs"),
        sa.ForeignKeyConstraint(
            ["brand_id"], ["brands.id"], name="fk_scan_jobs_brand_id_brands", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_scan_jobs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_scan_jobs_workspace_id_state", "scan_jobs", ["workspace_id", "state"], unique=False
    )

    op.create_table(
        "api_usage",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("job_id", GUID, nullable=True),
        sa.Column("calls", sa.Integer(), nullable=False),
        sa.Column("cost_usd", Money, nullable=False),
        sa.Column("at", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_api_usage"),
        sa.ForeignKeyConstraint(
            ["job_id"], ["scan_jobs.id"], name="fk_api_usage_job_id_scan_jobs", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_api_usage_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_api_usage_provider_at", "api_usage", ["provider", "at"], unique=False)

    op.create_table(
        "campaign_nodes",
        sa.Column("id", GUID, nullable=False),
        sa.Column("campaign_id", GUID, nullable=False),
        sa.Column("type", _enum("node_type"), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("included", sa.Boolean(), nullable=False),
        sa.Column("triage_reason", sa.Text(), nullable=True),
        sa.Column("ai_verdict", JSONB, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_campaign_nodes"),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name="fk_campaign_nodes_campaign_id_campaigns",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "campaign_id", "type", "value", name="uq_campaign_nodes_campaign_id_type_value"
        ),
    )

    op.create_table(
        "candidate_sources",
        sa.Column("id", GUID, nullable=False),
        sa.Column("candidate_id", GUID, nullable=False),
        sa.Column("source", _enum("discovery_source"), nullable=False),
        sa.Column("matched_pattern", sa.Text(), nullable=True),
        sa.Column("found_at", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_candidate_sources"),
        sa.ForeignKeyConstraint(
            ["candidate_id"],
            ["candidates.id"],
            name="fk_candidate_sources_candidate_id_candidates",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "candidate_id", "source", name="uq_candidate_sources_candidate_id_source"
        ),
    )

    op.create_table(
        "findings",
        sa.Column("id", GUID, nullable=False),
        sa.Column("candidate_id", GUID, nullable=False),
        sa.Column("brand_id", GUID, nullable=False),
        sa.Column("state", _enum("finding_state"), nullable=False),
        sa.Column("severity", _enum("severity"), nullable=False),
        sa.Column("confidence", Percent, nullable=True),
        sa.Column("analyst_verdict", _enum("analyst_verdict"), nullable=True),
        sa.Column("campaign_id", GUID, nullable=True),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.ForeignKeyConstraint(
            ["brand_id"], ["brands.id"], name="fk_findings_brand_id_brands", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name="fk_findings_campaign_id_campaigns",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["candidate_id"],
            ["candidates.id"],
            name="fk_findings_candidate_id_candidates",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_findings_brand_id_state_severity",
        "findings",
        ["brand_id", "state", "severity"],
        unique=False,
    )
    op.create_index("ix_findings_campaign_id", "findings", ["campaign_id"], unique=False)
    op.create_index("ix_findings_candidate_id", "findings", ["candidate_id"], unique=False)

    op.create_table(
        "scan_events",
        sa.Column("id", GUID, nullable=False),
        sa.Column("job_id", GUID, nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("stage", sa.String(length=64), nullable=False),
        sa.Column("step", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("level", sa.String(length=8), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("progress", JSONB, nullable=True),
        sa.Column("counts", JSONB, nullable=False),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False),
        sa.Column("data", JSONB, nullable=True),
        sa.Column("at", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_scan_events"),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["scan_jobs.id"],
            name="fk_scan_events_job_id_scan_jobs",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("job_id", "seq", name="uq_scan_events_job_id_seq"),
    )
    op.create_index("ix_scan_events_job_id_at", "scan_events", ["job_id", "at"], unique=False)

    op.create_table(
        "scan_stages",
        sa.Column("id", GUID, nullable=False),
        sa.Column("job_id", GUID, nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("state", _enum("job_state"), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.Column("api_calls", sa.Integer(), nullable=False),
        sa.Column("cost_usd", Money, nullable=False),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False),
        sa.Column("started_at", TZDateTime, nullable=True),
        sa.Column("finished_at", TZDateTime, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_scan_stages"),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["scan_jobs.id"],
            name="fk_scan_stages_job_id_scan_jobs",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_scan_stages_job_id", "scan_stages", ["job_id"], unique=False)

    op.create_table(
        "urls",
        sa.Column("id", GUID, nullable=False),
        sa.Column("hostname_id", GUID, nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("path", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_urls"),
        sa.ForeignKeyConstraint(
            ["hostname_id"],
            ["hostnames.id"],
            name="fk_urls_hostname_id_hostnames",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_urls_hostname_id", "urls", ["hostname_id"], unique=False)

    op.create_table(
        "analyst_labels",
        sa.Column("id", GUID, nullable=False),
        sa.Column("finding_id", GUID, nullable=False),
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("analyst_id", GUID, nullable=False),
        sa.Column("at", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_analyst_labels"),
        sa.ForeignKeyConstraint(
            ["analyst_id"],
            ["users.id"],
            name="fk_analyst_labels_analyst_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_analyst_labels_finding_id_findings",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_analyst_labels_finding_id", "analyst_labels", ["finding_id"], unique=False)

    op.create_table(
        "evidence",
        sa.Column("id", GUID, nullable=False),
        sa.Column("candidate_id", GUID, nullable=False),
        sa.Column("finding_id", GUID, nullable=True),
        sa.Column("type", _enum("evidence_type"), nullable=False),
        sa.Column("observed_at", TZDateTime, nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("collector", sa.String(length=64), nullable=False),
        sa.Column("collector_version", sa.String(length=32), nullable=False),
        sa.Column("parser_version", sa.String(length=32), nullable=True),
        sa.Column("scoring_version", sa.String(length=32), nullable=True),
        sa.Column("request_profile", JSONB, nullable=True),
        sa.Column("response_meta", JSONB, nullable=True),
        sa.Column("content_sha256", sa.String(length=64), nullable=True),
        sa.Column("artifact_location", sa.Text(), nullable=True),
        sa.Column("trust_level", sa.String(length=16), nullable=True),
        sa.Column("parent_evidence_id", GUID, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_evidence"),
        sa.ForeignKeyConstraint(
            ["candidate_id"],
            ["candidates.id"],
            name="fk_evidence_candidate_id_candidates",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_evidence_finding_id_findings",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["parent_evidence_id"],
            ["evidence.id"],
            name="fk_evidence_parent_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_evidence_candidate_id_type_observed_at",
        "evidence",
        ["candidate_id", "type", "observed_at"],
        unique=False,
    )
    op.create_index(
        "ix_evidence_parent_evidence_id", "evidence", ["parent_evidence_id"], unique=False
    )

    op.create_table(
        "risk_scores",
        sa.Column("id", GUID, nullable=False),
        sa.Column("finding_id", GUID, nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("raw_score", sa.Integer(), nullable=False),
        sa.Column("severity", _enum("severity"), nullable=False),
        sa.Column("confidence", Percent, nullable=False),
        sa.Column("scoring_version", sa.String(length=32), nullable=False),
        sa.Column("signals", JSONB, nullable=False),
        sa.Column("groups", JSONB, nullable=False),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id", name="pk_risk_scores"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_risk_scores_finding_id_findings",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "uq_risk_scores_current",
        "risk_scores",
        ["finding_id"],
        unique=True,
        postgresql_where=sa.text("is_current"),
        sqlite_where=sa.text("is_current"),
    )

    op.create_table(
        "takedown_drafts",
        sa.Column("id", GUID, nullable=False),
        sa.Column("finding_id", GUID, nullable=False),
        sa.Column("state", _enum("takedown_state"), nullable=False),
        sa.Column("abuse_contact", sa.Text(), nullable=True),
        sa.Column("registrar", sa.Text(), nullable=True),
        sa.Column("host", sa.Text(), nullable=True),
        sa.Column("reference", sa.Text(), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("sent_at", TZDateTime, nullable=True),
        sa.Column("response_at", TZDateTime, nullable=True),
        sa.Column("resolved_at", TZDateTime, nullable=True),
        sa.Column("created_at", TZDateTime, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_takedown_drafts"),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_takedown_drafts_finding_id_findings",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_takedown_drafts_finding_id", "takedown_drafts", ["finding_id"], unique=False
    )

    op.create_table(
        "campaign_edges",
        sa.Column("id", GUID, nullable=False),
        sa.Column("campaign_id", GUID, nullable=False),
        sa.Column("src_node_id", GUID, nullable=False),
        sa.Column("dst_node_id", GUID, nullable=False),
        sa.Column("type", _enum("edge_type"), nullable=False),
        sa.Column("evidence_id", GUID, nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_campaign_edges"),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name="fk_campaign_edges_campaign_id_campaigns",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["dst_node_id"],
            ["campaign_nodes.id"],
            name="fk_campaign_edges_dst_node_id_campaign_nodes",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_campaign_edges_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["src_node_id"],
            ["campaign_nodes.id"],
            name="fk_campaign_edges_src_node_id_campaign_nodes",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "dns_observations",
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("records", JSONB, nullable=False),
        sa.Column("resolver", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_dns_observations"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_dns_observations_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "finding_evidence",
        sa.Column("finding_id", GUID, nullable=False),
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("role", _enum("evidence_role"), nullable=False),
        sa.PrimaryKeyConstraint("finding_id", "evidence_id", name="pk_finding_evidence"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_finding_evidence_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_finding_evidence_finding_id_findings",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "html_snapshots",
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("dom_hash", sa.String(length=64), nullable=True),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("meta", JSONB, nullable=True),
        sa.Column("path", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_html_snapshots"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_html_snapshots_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "http_responses",
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("status", sa.Integer(), nullable=True),
        sa.Column("headers", JSONB, nullable=True),
        sa.Column("ip", INET, nullable=True),
        sa.Column("redirect_chain", JSONB, nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_http_responses"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_http_responses_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "iocs",
        sa.Column("id", GUID, nullable=False),
        sa.Column("workspace_id", GUID, nullable=False),
        sa.Column("type", _enum("ioc_type"), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("finding_id", GUID, nullable=True),
        sa.Column("campaign_id", GUID, nullable=True),
        sa.Column("source_evidence_id", GUID, nullable=True),
        sa.Column("first_seen", TZDateTime, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_iocs"),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name="fk_iocs_campaign_id_campaigns",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name="fk_iocs_finding_id_findings", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["source_evidence_id"],
            ["evidence.id"],
            name="fk_iocs_source_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"],
            ["workspaces.id"],
            name="fk_iocs_workspace_id_workspaces",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "workspace_id", "type", "value", name="uq_iocs_workspace_id_type_value"
        ),
    )
    op.create_index("ix_iocs_campaign_id", "iocs", ["campaign_id"], unique=False)
    op.create_index("ix_iocs_finding_id", "iocs", ["finding_id"], unique=False)

    op.create_table(
        "observations",
        sa.Column("id", GUID, nullable=False),
        sa.Column("candidate_id", GUID, nullable=False),
        sa.Column("observed_at", TZDateTime, nullable=False),
        sa.Column("source", _enum("discovery_source"), nullable=False),
        sa.Column("scanner_profile", _enum("scanner_profile"), nullable=False),
        sa.Column("state_at_time", _enum("candidate_state"), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("screenshot_evidence_id", GUID, nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("changed", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_observations"),
        sa.ForeignKeyConstraint(
            ["candidate_id"],
            ["candidates.id"],
            name="fk_observations_candidate_id_candidates",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["screenshot_evidence_id"],
            ["evidence.id"],
            name="fk_observations_screenshot_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_observations_candidate_id_observed_at",
        "observations",
        ["candidate_id", "observed_at"],
        unique=False,
    )

    op.create_table(
        "reputation_observations",
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("status", _enum("provider_status"), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=True),
        sa.Column("raw", JSONB, nullable=True),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_reputation_observations"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_reputation_observations_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "screenshots",
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column("phash", sa.String(length=64), nullable=True),
        sa.Column("path", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_screenshots"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_screenshots_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "ssl_observations",
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("issuer", sa.Text(), nullable=True),
        sa.Column("not_before", sa.Date(), nullable=True),
        sa.Column("not_after", sa.Date(), nullable=True),
        sa.Column("sans", JSONB, nullable=True),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_ssl_observations"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_ssl_observations_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )

    op.create_table(
        "whois_observations",
        sa.Column("evidence_id", GUID, nullable=False),
        sa.Column("registered_at", sa.Date(), nullable=True),
        sa.Column("registrar", sa.Text(), nullable=True),
        sa.Column("registrant", JSONB, nullable=True),
        sa.Column("raw", JSONB, nullable=True),
        sa.Column("age_days", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("evidence_id", name="pk_whois_observations"),
        sa.ForeignKeyConstraint(
            ["evidence_id"],
            ["evidence.id"],
            name="fk_whois_observations_evidence_id_evidence",
            ondelete="RESTRICT",
        ),
    )

    _create_immutability_triggers()


def downgrade() -> None:
    op.drop_table("whois_observations")
    op.drop_table("ssl_observations")
    op.drop_table("screenshots")
    op.drop_table("reputation_observations")
    op.drop_table("observations")
    op.drop_table("iocs")
    op.drop_table("http_responses")
    op.drop_table("html_snapshots")
    op.drop_table("finding_evidence")
    op.drop_table("dns_observations")
    op.drop_table("campaign_edges")
    op.drop_table("takedown_drafts")
    op.drop_table("risk_scores")
    op.drop_table("evidence")
    op.drop_table("analyst_labels")
    op.drop_table("urls")
    op.drop_table("scan_stages")
    op.drop_table("scan_events")
    op.drop_table("findings")
    op.drop_table("candidate_sources")
    op.drop_table("campaign_nodes")
    op.drop_table("api_usage")
    op.drop_table("scan_jobs")
    op.drop_table("reports")
    op.drop_table("hostnames")
    op.drop_table("configs")
    op.drop_table("candidates")
    op.drop_table("campaigns")
    op.drop_table("brand_fingerprints")
    op.drop_table("brand_domains")
    op.drop_table("users")
    op.drop_table("ip_addresses")
    op.drop_table("domains")
    op.drop_table("brands")
    op.drop_table("audit_events")
    op.drop_table("api_keys")
    op.drop_table("workspaces")
    op.drop_table("rule_versions")
    op.drop_table("risk_score_versions")
    op.drop_table("registrars")
    op.drop_table("nameservers")
    op.drop_table("certificates")
    op.drop_table("asns")
    op.drop_table("api_providers")
    if _dialect() == "postgresql":
        for table in PARTIALLY_MUTABLE_TABLES:
            op.execute(f"DROP FUNCTION IF EXISTS brandwatch_{table}_guard()")
        op.execute("DROP FUNCTION IF EXISTS brandwatch_reject_mutation()")
        bind = op.get_bind()
        for name in ENUMS:
            postgresql.ENUM(name=name).drop(bind, checkfirst=True)
