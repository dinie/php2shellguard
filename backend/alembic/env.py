"""Alembic environment for the php2shell stats store.

When migrations run inside the app (``Storage`` construction, recheck,
tests), the caller's engine arrives via ``config.attributes["engine"]`` so
the migrations apply to that exact database — required for in-memory
SQLite. Standalone CLI runs (``alembic upgrade head``) fall back to
``PHP2SHELL_DATABASE_URL``, ``PHP2SHELL_DB``, then ``sqlalchemy.url`` from
alembic.ini.
"""

import os
from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

from app.storage import database_url, metadata  # noqa: E402

target_metadata = metadata


def _cli_url() -> str:
    location = os.environ.get("PHP2SHELL_DATABASE_URL") or os.environ.get("PHP2SHELL_DB")
    if location:
        return database_url(location)
    return config.get_main_option("sqlalchemy.url")


def run_migrations_offline() -> None:
    context.configure(
        url=_cli_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = config.attributes.get("engine")
    if engine is None:
        engine = create_engine(_cli_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
