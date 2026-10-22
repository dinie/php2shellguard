"""Stats persistence — SQLite by default, PostgreSQL when configured.

Privacy-limited by design: only the hostname, detected PHP version, verdict
and check timestamp are stored. Full URLs, paths, query strings and raw
header values are never persisted.

The backend is chosen by where ``Storage`` finds its connection details
(the first match wins):

1. the ``location`` argument (SQLite path, ``:memory:`` or a SQLAlchemy URL)
2. ``PHP2SHELL_DATABASE_URL`` — full SQLAlchemy URL, e.g.
   ``postgresql://user:pass@host:5432/php2shell``
3. ``PHP2SHELL_DB`` — SQLite file path
4. ``php2shell-stats.db`` next to the ``app`` package (SQLite)

Schema versions are managed by Alembic (``backend/alembic``); constructing a
``Storage`` applies pending migrations, so both the app and the recheck
script always run against the current schema.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.pool import StaticPool

BACKEND_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BACKEND_DIR / "php2shell-stats.db"
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"

metadata = sa.MetaData()

# Timestamps stay TEXT ("YYYY-MM-DD HH:MM:SS", UTC) for lexicographic
# ordering and identical query semantics across SQLite and PostgreSQL.
checks = sa.Table(
    "checks",
    metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("host", sa.Text, nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column("php_version", sa.Text),
    sa.Column("source", sa.Text),
    sa.Column(
        "origin", sa.Text, nullable=False, server_default=sa.text("'extension'")
    ),
    sa.Column("checked_at", sa.Text, nullable=False),
    sa.Index("idx_checks_host", "host"),
    sa.Index("idx_checks_checked_at", "checked_at"),
)

stream_state = sa.Table(
    "stream_state",
    metadata,
    sa.Column("key", sa.Text, primary_key=True),
    sa.Column("value", sa.Text),
)

host_registry = sa.Table(
    "host_registry",
    metadata,
    sa.Column("host", sa.Text, primary_key=True),
    sa.Column("original_status", sa.Text, nullable=False),
    sa.Column("original_checked_at", sa.Text, nullable=False),
    sa.Column("current_status", sa.Text, nullable=False),
    sa.Column("current_checked_at", sa.Text, nullable=False),
)

# Latest verdict per hostname, correlated by id so timestamp ties resolve to
# the most recent insert.
_LATEST_IDS = (
    sa.select(checks.c.host, sa.func.max(checks.c.id).label("max_id"))
    .group_by(checks.c.host)
    .subquery()
)
_LATEST_PER_HOST = (
    sa.select(
        checks.c.host,
        checks.c.status,
        checks.c.php_version,
        checks.c.source,
        checks.c.origin,
        checks.c.checked_at,
    )
    .join(_LATEST_IDS, checks.c.id == _LATEST_IDS.c.max_id)
    .subquery()
)


def database_url(location: str | None = None) -> str:
    """Resolve *location* (SQLite path, ``:memory:`` or URL) and the
    ``PHP2SHELL_DATABASE_URL`` / ``PHP2SHELL_DB`` fallbacks to a SQLAlchemy
    URL. Bare ``postgres://`` / ``postgresql://`` URLs default to the
    psycopg v3 driver."""
    location = (
        location
        or os.environ.get("PHP2SHELL_DATABASE_URL")
        or os.environ.get("PHP2SHELL_DB")
        or str(DEFAULT_DB_PATH)
    )
    if location == ":memory:":
        return "sqlite:///:memory:"
    if "://" not in location:
        path = Path(location)
        path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{path}"
    scheme, rest = location.split("://", 1)
    if scheme in ("postgres", "postgresql"):
        return f"postgresql+psycopg://{rest}"
    return location


def _create_engine(url: str) -> sa.engine.Engine:
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if url == "sqlite:///:memory:":
            # Keep one shared connection so the in-memory database survives
            # across pooled checkouts.
            kwargs["poolclass"] = StaticPool
        return sa.create_engine(url, **kwargs)
    return sa.create_engine(url)


def _run_migrations(engine: sa.engine.Engine) -> None:
    # Private attribute so alembic/env.py reuses this very engine (required
    # for in-memory SQLite, where each engine is its own database).
    config = Config(str(ALEMBIC_INI))
    config.attributes["engine"] = engine
    command.upgrade(config, "head")


class Storage:
    def __init__(self, location: str | None = None):
        self._engine = _create_engine(database_url(location))
        _run_migrations(self._engine)

    @property
    def location(self) -> str:
        url = self._engine.url
        if url.get_backend_name() == "sqlite":
            return url.database or ":memory:"
        return str(url)  # str() masks the password

    @staticmethod
    def _stamp(moment: datetime | None) -> str:
        moment = moment or datetime.now(timezone.utc)
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
        return moment.strftime("%Y-%m-%d %H:%M:%S")

    def _upsert(self, table: sa.Table, values: dict, set_: dict):
        """INSERT ... ON CONFLICT (pk) DO UPDATE for either dialect."""
        index_elements = [column.name for column in table.primary_key]
        if self._engine.dialect.name == "postgresql":
            stmt = postgresql.insert(table).values(values)
        else:
            stmt = sqlite.insert(table).values(values)
        return stmt.on_conflict_do_update(index_elements=index_elements, set_=set_)

    def record_check(
        self,
        host: str,
        status: str,
        php_version: str | None = None,
        source: str | None = None,
        checked_at: datetime | None = None,
        origin: str = "extension",
    ) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                checks.insert().values(
                    host=host,
                    status=status,
                    php_version=php_version,
                    source=source,
                    origin=origin,
                    checked_at=self._stamp(checked_at),
                )
            )

    def checked_recently(self, host: str, ttl_hours: float) -> bool:
        cutoff = self._stamp(datetime.now(timezone.utc) - timedelta(hours=ttl_hours))
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(checks.c.id)
                .where(checks.c.host == host.lower(), checks.c.checked_at >= cutoff)
                .limit(1)
            ).first()
        return row is not None

    def record_recheck(
        self,
        host: str,
        status: str,
        php_version: str | None = None,
        source: str | None = None,
        checked_at: datetime | None = None,
    ) -> None:
        """Record a periodic re-verification and track the host's original status.

        The registry's original_* columns are written on first sight and never
        updated; current_* follow every recheck.
        """
        stamp = self._stamp(checked_at)
        with self._engine.begin() as conn:
            first = conn.execute(
                sa.select(checks.c.status, checks.c.checked_at)
                .where(checks.c.host == host)
                .order_by(checks.c.id)
                .limit(1)
            ).mappings().first()
            original_status = first["status"] if first else status
            original_at = first["checked_at"] if first else stamp
            conn.execute(
                checks.insert().values(
                    host=host,
                    status=status,
                    php_version=php_version,
                    source=source,
                    origin="recheck",
                    checked_at=stamp,
                )
            )
            conn.execute(
                self._upsert(
                    host_registry,
                    {
                        "host": host,
                        "original_status": original_status,
                        "original_checked_at": original_at,
                        "current_status": status,
                        "current_checked_at": stamp,
                    },
                    set_={
                        "current_status": status,
                        "current_checked_at": stamp,
                    },
                )
            )

    def registry(self) -> list[dict]:
        with self._engine.connect() as conn:
            rows = conn.execute(
                sa.select(host_registry).order_by(host_registry.c.host)
            ).mappings().all()
        return [dict(row) for row in rows]

    def get_state(self, key: str) -> str | None:
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(stream_state.c.value).where(stream_state.c.key == key)
            ).first()
        return row[0] if row else None

    def set_state(self, key: str, value: str) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                self._upsert(
                    stream_state, {"key": key, "value": value}, set_={"value": value}
                )
            )

    def stats(self) -> dict:
        day = sa.func.substr(checks.c.checked_at, 1, 10)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily_since = (
            datetime.now(timezone.utc) - timedelta(days=13)
        ).strftime("%Y-%m-%d")
        with self._engine.connect() as conn:
            total_checks = conn.scalar(sa.select(sa.func.count(checks.c.id))) or 0
            checks_today = (
                conn.scalar(
                    sa.select(sa.func.count(checks.c.id)).where(day == today)
                )
                or 0
            )
            unique_hosts = conn.scalar(
                sa.select(sa.func.count(sa.distinct(checks.c.host)))
            )
            status_rows = conn.execute(
                sa.select(checks.c.status, sa.func.count().label("n")).group_by(
                    checks.c.status
                )
            ).mappings().all()
            host_status_rows = conn.execute(
                sa.select(_LATEST_PER_HOST.c.status, sa.func.count().label("n"))
                .select_from(_LATEST_PER_HOST)
                .group_by(_LATEST_PER_HOST.c.status)
            ).mappings().all()
            version_rows = conn.execute(
                sa.select(checks.c.php_version, sa.func.count().label("n"))
                .where(checks.c.php_version.isnot(None))
                .group_by(checks.c.php_version)
                .order_by(sa.desc("n"))
                .limit(10)
            ).mappings().all()
            daily_rows = conn.execute(
                sa.select(
                    day.label("day"), checks.c.status, sa.func.count().label("n")
                )
                .where(day >= daily_since)
                .group_by("day", checks.c.status)
                .order_by("day")
            ).mappings().all()
            recent_rows = conn.execute(
                sa.select(
                    checks.c.host,
                    checks.c.status,
                    checks.c.php_version,
                    checks.c.source,
                    checks.c.origin,
                    checks.c.checked_at,
                )
                .order_by(checks.c.id.desc())
                .limit(25)
            ).mappings().all()

        daily: dict[str, dict[str, int]] = {}
        for row in daily_rows:
            daily.setdefault(row["day"], {})[row["status"]] = row["n"]

        return {
            "total_checks": total_checks,
            "checks_today": checks_today,
            "unique_hosts": unique_hosts,
            "status_counts": {row["status"]: row["n"] for row in status_rows},
            "host_status_counts": {row["status"]: row["n"] for row in host_status_rows},
            "version_counts": [
                {"php_version": row["php_version"], "count": row["n"]}
                for row in version_rows
            ],
            "daily": [
                {"day": day_str, "counts": counts}
                for day_str, counts in sorted(daily.items())
            ],
            "recent": [dict(row) for row in recent_rows],
        }

    def hosts(self, status: str | None = None) -> list[dict]:
        """All hosts with their latest verdict, optionally filtered to hosts
        whose *latest* verdict equals *status*."""
        counts = (
            sa.select(
                checks.c.host,
                sa.func.count().label("total_checks"),
                sa.func.min(checks.c.checked_at).label("first_seen"),
                sa.func.max(checks.c.checked_at).label("last_seen"),
            )
            .group_by(checks.c.host)
            .subquery()
        )
        latest = _LATEST_PER_HOST
        stmt = (
            sa.select(
                latest.c.host,
                latest.c.status,
                latest.c.php_version,
                latest.c.source,
                latest.c.origin,
                counts.c.total_checks,
                counts.c.first_seen,
                counts.c.last_seen,
            )
            .select_from(latest.join(counts, counts.c.host == latest.c.host))
            .order_by(counts.c.last_seen.desc())
        )
        if status is not None:
            stmt = stmt.where(latest.c.status == status)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [dict(row) for row in rows]

    def host_detail(self, host: str) -> dict | None:
        host = host.lower()
        with self._engine.connect() as conn:
            summary = conn.execute(
                sa.select(
                    checks.c.host,
                    sa.func.count().label("total_checks"),
                    sa.func.min(checks.c.checked_at).label("first_seen"),
                    sa.func.max(checks.c.checked_at).label("last_seen"),
                )
                .where(checks.c.host == host)
                .group_by(checks.c.host)
            ).mappings().first()
            if summary is None:
                return None
            latest = conn.execute(
                sa.select(
                    checks.c.host,
                    checks.c.status,
                    checks.c.php_version,
                    checks.c.source,
                    checks.c.origin,
                    checks.c.checked_at,
                )
                .where(checks.c.host == host)
                .order_by(checks.c.id.desc())
                .limit(1)
            ).mappings().first()
            history = conn.execute(
                sa.select(
                    checks.c.status,
                    checks.c.php_version,
                    checks.c.source,
                    checks.c.origin,
                    checks.c.checked_at,
                )
                .where(checks.c.host == host)
                .order_by(checks.c.id.desc())
                .limit(50)
            ).mappings().all()
        return {
            "summary": dict(summary),
            "latest": dict(latest),
            "history": [dict(row) for row in history],
        }
