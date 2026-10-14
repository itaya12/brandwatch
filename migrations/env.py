"""Alembic environment.

The database URL comes from ``brandwatch.config.settings.Settings`` (env / .env) unless the
caller passed ``-x url=...`` or set ``sqlalchemy.url`` programmatically (the test suite does the
latter). ``render_as_batch`` is enabled on SQLite so future ALTERs work there too.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from brandwatch.db import models  # noqa: F401  (registers every table on Base.metadata)
from brandwatch.db.base import Base

config = context.config
if config.config_file_name is not None and not config.attributes.get("skip_logging_config"):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _resolve_url() -> str:
    x_url = context.get_x_argument(as_dictionary=True).get("url")
    if x_url:
        return x_url
    configured = config.get_main_option("sqlalchemy.url")
    if config.attributes.get("url_from_caller"):
        return configured
    try:
        from brandwatch.config.settings import get_settings

        return get_settings().database_url
    except Exception:  # pragma: no cover - settings import is optional for `alembic` CLI use
        return configured


def run_migrations_offline() -> None:
    url = _resolve_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = config.attributes.get("connection")
    if connectable is None:
        section = config.get_section(config.config_ini_section, {})
        section["sqlalchemy.url"] = _resolve_url()
        connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
        with connectable.connect() as connection:
            _run(connection)
    else:
        _run(connectable)


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
