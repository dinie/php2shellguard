import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "test-stats.db"))
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_check_vulnerable(client):
    response = client.post(
        "/api/v1/check",
        json={
            "url": "https://shop.example.com/products",
            "server": "Apache/2.4.58 (Unix)",
            "x_powered_by": "PHP/8.2.10",
            "cookie_names": ["PHPSESSID"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["host"] == "shop.example.com"
    assert body["status"] == "vulnerable"
    assert body["php_version"] == "8.2.10"
    assert body["patched_version"] == "8.2.35"
    assert {cve["id"] for cve in body["cves"]} == {
        "CVE-2026-109618",
        "CVE-2026-109619",
    }


def test_check_patched_from_server_header(client):
    response = client.post(
        "/api/v1/check",
        json={
            "url": "https://blog.example.com/",
            "server": "Apache/2.4.58 (Unix) PHP/8.3.36",
            "cookie_names": [],
        },
    )
    assert response.json()["status"] == "patched"


def test_check_records_stats(client):
    client.post(
        "/api/v1/check",
        json={"url": "https://a.example.com/", "x_powered_by": "PHP/8.1.0"},
    )
    client.post(
        "/api/v1/check",
        json={"url": "https://b.example.com/path?q=1", "server": "nginx"},
    )
    stats = client.get("/api/v1/stats").json()
    assert stats["total_checks"] == 2
    assert stats["checks_today"] == 2
    assert stats["unique_hosts"] == 2
    assert stats["host_status_counts"] == {"vulnerable": 1, "not_php": 1}
    assert stats["version_counts"][0]["php_version"] == "8.1.0"
    # Recent entries must contain the hostname only — never the full URL.
    hosts = {row["host"] for row in stats["recent"]}
    assert hosts == {"a.example.com", "b.example.com"}
    assert all("/path" not in repr(row) and "q=1" not in repr(row) for row in stats["recent"])
    # Extension-originated checks carry the default input origin.
    assert {row["origin"] for row in stats["recent"]} == {"extension"}


def test_check_rejects_bad_url(client):
    response = client.post("/api/v1/check", json={"url": "not a url at all"})
    assert response.status_code == 422


def test_hosts_listing_and_latest_wins(client):
    client.post(
        "/api/v1/check",
        json={"url": "https://a.example.com/", "x_powered_by": "PHP/8.2.10"},
    )
    client.post(
        "/api/v1/check",
        json={"url": "https://a.example.com/", "x_powered_by": "PHP/8.2.40"},
    )
    hosts = client.get("/api/v1/hosts").json()
    assert len(hosts) == 1
    assert hosts[0]["status"] == "patched"
    assert hosts[0]["total_checks"] == 2


def test_host_detail_json(client):
    client.post(
        "/api/v1/check",
        json={"url": "https://a.example.com/", "x_powered_by": "PHP/7.4.33"},
    )
    detail = client.get("/api/v1/hosts/a.example.com")
    assert detail.status_code == 200
    assert detail.json()["latest"]["status"] == "vulnerable"
    assert client.get("/api/v1/hosts/missing.example.com").status_code == 404


def test_dashboard_page(client):
    client.post(
        "/api/v1/check",
        json={"url": "https://a.example.com/", "x_powered_by": "PHP/8.2.10"},
    )
    response = client.get("/")
    assert response.status_code == 200
    assert "PHP2Shell" in response.text
    assert "a.example.com" in response.text


def test_host_report_page(client):
    client.post(
        "/api/v1/check",
        json={"url": "https://a.example.com/", "x_powered_by": "PHP/8.2.10"},
    )
    page = client.get("/hosts/a.example.com")
    assert page.status_code == 200
    assert "VULNERABLE" in page.text
    assert "CVE-2026-109618" in page.text
    missing = client.get("/hosts/missing.example.com")
    assert missing.status_code == 404
    assert "No checks recorded" in missing.text


def _wait_for_recheck_idle(client, timeout=5.0):
    """POST succeeds once the previous background run has finished."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.post("/recheck").status_code
        if status == 202:
            return status
        time.sleep(0.05)
    return status


def test_recheck_endpoint_starts_and_rejects_overlap(client, monkeypatch):
    finish = threading.Event()

    async def fake_run_rechecks(storage, http_client):
        while not finish.is_set():
            await asyncio.sleep(0.01)
        return []

    monkeypatch.setattr("app.recheck.run_rechecks", fake_run_rechecks)
    first = client.post("/recheck")
    assert first.status_code == 202
    assert first.json() == {"status": "started"}
    follow_up = client.post("/recheck")
    assert follow_up.status_code == 409
    finish.set()
    assert _wait_for_recheck_idle(client) == 202


def test_recheck_endpoint_get_not_allowed(client):
    assert client.get("/recheck").status_code == 405


def test_recheck_endpoint_requires_token_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("PHP2SHELL_RECHECK_TOKEN", "sekrit")

    async def quick_run(storage, http_client):
        return []

    monkeypatch.setattr("app.recheck.run_rechecks", quick_run)
    app = create_app(db_path=str(tmp_path / "tok.db"))
    with TestClient(app) as tok_client:
        assert tok_client.post("/recheck").status_code == 401
        wrong = tok_client.post("/recheck", headers={"authorization": "Bearer nope"})
        assert wrong.status_code == 401
        wrong_scheme = tok_client.post(
            "/recheck", headers={"authorization": "sekrit"}
        )
        assert wrong_scheme.status_code == 401
        ok = tok_client.post("/recheck", headers={"authorization": "Bearer sekrit"})
        assert ok.status_code == 202
