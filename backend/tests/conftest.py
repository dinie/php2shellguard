import pytest


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    """Keep tests hermetic: real credentials/config in the shell or in a
    local .env file must not leak in."""
    for var in (
        "NEXTDNS_API_KEY",
        "NEXTDNS_PROFILE",
        "NEXTDNS_BASE_URL",
        "NEXTDNS_PROBE_CONCURRENCY",
        "NEXTDNS_CHECK_TTL_HOURS",
        "PHP2SHELL_DB",
        "PHP2SHELL_DATABASE_URL",
        "PHP2SHELL_ACTIVE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("app.main.load_dotenv", lambda *a, **k: False)
