"""Storage backend selection, URL normalisation and migration behaviour."""

import sqlite3

from app.storage import Storage, database_url

LEGACY_SCHEMA = """
CREATE TABLE checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    status TEXT NOT NULL,
    php_version TEXT,
    source TEXT,
    origin TEXT NOT NULL DEFAULT 'extension',
    checked_at TEXT NOT NULL
);
CREATE INDEX idx_checks_host ON checks(host);
CREATE INDEX idx_checks_checked_at ON checks(checked_at);
CREATE TABLE stream_state (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE host_registry (
    host TEXT PRIMARY KEY,
    original_status TEXT NOT NULL,
    original_checked_at TEXT NOT NULL,
    current_status TEXT NOT NULL,
    current_checked_at TEXT NOT NULL
);
"""


def test_database_url_infers_sqlite_from_path():
    assert database_url("stats.db") == "sqlite:///stats.db"
    assert database_url(":memory:") == "sqlite:///:memory:"


def test_database_url_normalises_postgres_to_psycopg():
    for scheme in ("postgres", "postgresql"):
        url = database_url(f"{scheme}://user:pass@db:5432/stats")
        assert url == "postgresql+psycopg://user:pass@db:5432/stats"
    # Explicit drivers are respected as-is.
    assert database_url("postgresql+psycopg2://u@db/stats") == (
        "postgresql+psycopg2://u@db/stats"
    )


def test_database_url_env_precedence(monkeypatch, tmp_path):
    monkeypatch.setenv("PHP2SHELL_DB", str(tmp_path / "from-db-var.db"))
    assert database_url() == f"sqlite:///{tmp_path}/from-db-var.db"

    monkeypatch.setenv("PHP2SHELL_DATABASE_URL", "postgresql://u@db/stats")
    # PHP2SHELL_DATABASE_URL wins over PHP2SHELL_DB.
    assert database_url() == "postgresql+psycopg://u@db/stats"
    # An explicit argument wins over both env vars.
    assert database_url(":memory:") == "sqlite:///:memory:"


def test_storage_honours_database_url_env_var(tmp_path, monkeypatch):
    db = tmp_path / "via-env.db"
    monkeypatch.setenv("PHP2SHELL_DATABASE_URL", f"sqlite:///{db}")
    storage = Storage()
    assert storage.location == str(db)
    storage.record_check(host="a.example.com", status="patched")
    assert storage.host_detail("a.example.com")["summary"]["total_checks"] == 1
    assert db.exists()


def test_storage_runs_migrations_and_stamps_version(tmp_path):
    db = tmp_path / "stats.db"
    Storage(str(db))
    with sqlite3.connect(db) as conn:
        version = conn.execute("SELECT version_num FROM alembic_version").fetchone()
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )}
    assert version is not None
    assert {"checks", "stream_state", "host_registry", "alembic_version"} <= tables


def test_legacy_pre_alembic_database_is_adopted(tmp_path):
    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as conn:
        conn.executescript(LEGACY_SCHEMA)
        conn.execute(
            "INSERT INTO checks (host, status, php_version, source, checked_at)"
            " VALUES ('old.example.com', 'vulnerable', '8.2.10', 'x-powered-by',"
            "        '2026-10-01 00:00:00')"
        )

    storage = Storage(str(db))
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT version_num FROM alembic_version").fetchone()

    detail = storage.host_detail("old.example.com")
    assert detail["latest"]["origin"] == "extension"
    assert storage.stats()["total_checks"] == 1
    assert storage.registry() == []
    storage.set_state("k", "v")
    assert storage.get_state("k") == "v"


def test_storage_memory_roundtrip():
    storage = Storage(":memory:")
    storage.record_check(host="a.example.com", status="patched")
    assert storage.hosts()[0]["host"] == "a.example.com"
