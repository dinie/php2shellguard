import asyncio
from datetime import datetime, timezone

import httpx

from app import recheck
from app.storage import Storage

SEED_STAMP = "2026-10-01 00:00:00"


def seed(storage, host="shop.example.com", status="vulnerable", php_version="8.2.10"):
    storage.record_check(
        host=host,
        status=status,
        php_version=php_version,
        source="x-powered-by",
        checked_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )


def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


def patched_php_handler(request):
    return httpx.Response(
        200,
        headers={
            "server": "Apache/2.4.58 (Unix)",
            "x-powered-by": "PHP/8.2.40",
        },
    )


def test_recheck_records_fresh_verdict_and_registry(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    seed(storage)

    results = run(recheck.run_rechecks(storage, make_client(patched_php_handler)))

    assert [r.host for r in results] == ["shop.example.com"]
    assert results[0].previous_status == "vulnerable"
    assert results[0].analysis.status == "patched"

    latest = storage.host_detail("shop.example.com")["latest"]
    assert latest["status"] == "patched"
    assert latest["php_version"] == "8.2.40"
    assert latest["origin"] == "recheck"

    (entry,) = storage.registry()
    assert entry["host"] == "shop.example.com"
    assert entry["original_status"] == "vulnerable"
    assert entry["original_checked_at"] == SEED_STAMP
    assert entry["current_status"] == "patched"


def test_recheck_preserves_original_status_across_runs(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    seed(storage)

    run(recheck.run_rechecks(storage, make_client(patched_php_handler)))
    # Second run: back to an unpatched build (e.g. rollback or new finding).
    def vulnerable_handler(request):
        return httpx.Response(200, headers={"x-powered-by": "PHP/8.2.30"})

    run(recheck.run_rechecks(storage, make_client(vulnerable_handler)))

    (entry,) = storage.registry()
    assert entry["original_status"] == "vulnerable"
    assert entry["original_checked_at"] == SEED_STAMP
    assert entry["current_status"] == "vulnerable"


def test_recheck_probe_failure_leaves_no_trace(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    seed(storage)

    def failing_handler(request):
        raise httpx.ConnectError("refused")

    results = run(recheck.run_rechecks(storage, make_client(failing_handler)))

    assert results[0].analysis is None
    assert "refused" in results[0].error
    assert storage.registry() == []
    assert storage.host_detail("shop.example.com")["summary"]["total_checks"] == 1


def test_record_recheck_on_never_checked_host(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    storage.record_recheck(host="new.example.com", status="patched")

    (entry,) = storage.registry()
    assert entry["original_status"] == "patched"
    assert entry["current_status"] == "patched"
    assert entry["original_checked_at"] == entry["current_checked_at"]


def test_report_logs_transitions_and_summary(tmp_path, capsys):
    storage = Storage(str(tmp_path / "stats.db"))
    seed(storage)
    seed(storage, host="blog.example.com", status="patched", php_version="8.3.36")

    def handler(request):
        if request.url.host == "shop.example.com":
            return httpx.Response(200, headers={"x-powered-by": "PHP/8.2.40"})
        return httpx.Response(
            200, headers={"server": "Apache/2.4.58 (Unix) PHP/8.3.36"}
        )

    results = run(recheck.run_rechecks(storage, make_client(handler)))
    recheck.print_report(results)

    out = capsys.readouterr().out
    assert "shop.example.com: vulnerable -> patched (8.2.40)" in out
    assert "blog.example.com: patched (8.3.36) [unchanged]" in out
    assert "2 probed, 1 status change(s), 0 failure(s)" in out
