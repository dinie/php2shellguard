import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app import active, nextdns, recheck
from app.main import create_app
from app.storage import Storage


def run(coro):
    return asyncio.run(coro)


def investigate(handler, host="site.example.com"):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return run(active.investigate(client, host))


def test_redirect_chain_reveal_shown_in_final_headers():
    def handler(request):
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                302, headers={"location": "/home", "set-cookie": "PHPSESSID=abc"}
            )
        if request.url.path == "/home":
            return httpx.Response(200, headers={"x-powered-by": "PHP/8.3.5"})
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "vulnerable"
    assert analysis.php_version == "8.3.5"
    assert analysis.evidence_source == "x-powered-by"


def test_chain_cookie_yields_unknown_without_other_signals():
    def handler(request):
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                302, headers={"location": "/home", "set-cookie": "PHPSESSID=abc"}
            )
        if request.url.path == "/home":
            return httpx.Response(200, text="<html><body>hi</body></html>")
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "unknown"
    assert analysis.evidence_source == "cookie"


def test_credits_easter_egg_leaks_version(monkeypatch):
    def handler(request):
        if request.url.query.startswith(b"=PHPB8B5F2A0"):
            return httpx.Response(
                200,
                text="<h1>Credits</h1><h1>PHP Version 8.2.10</h1>",
            )
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "vulnerable"
    assert analysis.php_version == "8.2.10"
    assert analysis.evidence_source == "credits-easter-egg"


def test_phpinfo_page_leaks_version():
    def handler(request):
        if request.url.path == "/phpinfo.php":
            return httpx.Response(
                200,
                text=(
                    '<html><body><h1 class="p">PHP Version 8.4.27</h1>'
                    "phpinfo()</body></html>"
                ),
            )
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "patched"
    assert analysis.php_version == "8.4.27"
    assert analysis.evidence_source == "phpinfo"


def test_generator_tag_marks_php_platform():
    def handler(request):
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                200,
                text=(
                    "<html><head>"
                    '<meta name="generator" content="Drupal 10.3.5 (https://www.drupal.org)" />'
                    "</head><body></body></html>"
                ),
            )
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "unknown"
    assert analysis.evidence_source == "generator-tag"


def test_wordpress_artifacts_mark_php_platform():
    def handler(request):
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                200,
                text='<html><head><link rel="stylesheet" '
                'href="/wp-content/themes/site/style.css"></head></html>',
            )
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "unknown"
    assert analysis.evidence_source == "cms-artifacts"


def test_php_form_target_marks_php_platform():
    def handler(request):
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                200,
                text='<form method="post" action="contact.php"></form>',
            )
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "unknown"
    assert analysis.evidence_source == "body-php-references"


def test_logo_easter_egg_alone_marks_php_platform():
    def handler(request):
        if request.url.path == "/" and request.url.query.startswith(b"=PHPE9568F35"):
            return httpx.Response(200, headers={"content-type": "image/gif"})
        return httpx.Response(404)

    analysis = investigate(handler)
    assert analysis.status == "unknown"
    assert analysis.evidence_source == "logo-easter-egg"


def test_silent_host_stays_not_php():
    def handler(request):
        return httpx.Response(200, text="<html><body>SPA</body></html>")

    analysis = investigate(handler)
    assert analysis.status == "not_php"


def test_passive_version_wins_without_extra_requests():
    requested_paths = []

    def handler(request):
        requested_paths.append(str(request.url))
        return httpx.Response(200, headers={"x-powered-by": "PHP/5.4.3"})

    analysis = investigate(handler)
    assert analysis.status == "vulnerable"
    assert analysis.php_version == "5.4.3"
    assert requested_paths == ["https://site.example.com/"]


def test_recheck_uses_active_detector(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    storage.record_check(host="shop.example.com", status="not_php")

    def handler(request):
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                200,
                text='<form method="post" action="/prod.php"></form>',
            )
        return httpx.Response(404)

    (result,) = run(
        recheck.run_rechecks(
            storage, httpx.AsyncClient(transport=httpx.MockTransport(handler))
        )
    )
    assert result.analysis.status == "unknown"
    assert result.analysis.evidence_source == "body-php-references"
    latest = storage.host_detail("shop.example.com")["history"][0]
    assert latest["source"] == "body-php-references"
    assert latest["status"] == "unknown"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_active_flag_truthy(monkeypatch, value):
    monkeypatch.setenv("PHP2SHELL_ACTIVE", value)
    assert active.enabled_from_env() is True


@pytest.mark.parametrize("value", ["", "0", "false", "off", "nope"])
def test_active_flag_falsy(monkeypatch, value):
    monkeypatch.setenv("PHP2SHELL_ACTIVE", value)
    assert active.enabled_from_env() is False


def build_check_client(tmp_path, handler, monkeypatch, active_value="true"):
    monkeypatch.setenv("PHP2SHELL_ACTIVE", active_value)
    factory = lambda **kwargs: httpx.AsyncClient(  # noqa: E731
        transport=httpx.MockTransport(handler), **kwargs
    )
    app = create_app(
        db_path=str(tmp_path / "stats.db"), http_client_factory=factory
    )
    return TestClient(app)


def test_check_endpoint_uses_active_detector_when_flagged(tmp_path, monkeypatch):
    def handler(request):
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                200,
                text='<link rel="stylesheet" href="/wp-content/themes/x/site.css">',
            )
        return httpx.Response(404)

    with build_check_client(tmp_path, handler, monkeypatch) as client:
        response = client.post("/api/v1/check", json={"url": "https://example.com/x"})

    body = response.json()
    assert body["status"] == "unknown"
    assert body["evidence_source"] == "cms-artifacts"


def test_check_endpoint_stays_passive_by_default(tmp_path, monkeypatch):
    probed = []

    def handler(request):
        probed.append(str(request.url))
        return httpx.Response(404)

    monkeypatch.setenv("PHP2SHELL_ACTIVE", "")
    with build_check_client(tmp_path, handler, monkeypatch, active_value="") as client:
        response = client.post(
            "/api/v1/check",
            json={"url": "https://shop.example.com/", "x_powered_by": "PHP/8.2.10"},
        )

    assert response.json()["status"] == "vulnerable"
    assert probed == []


def test_check_endpoint_falls_back_to_payload_when_probe_fails(tmp_path, monkeypatch):
    def handler(request):
        raise httpx.ConnectError("boom")

    with build_check_client(tmp_path, handler, monkeypatch) as client:
        response = client.post(
            "/api/v1/check",
            json={"url": "https://down.example.com/", "x_powered_by": "PHP/8.2.10"},
        )

    body = response.json()
    assert body["status"] == "vulnerable"
    assert body["evidence_source"] == "x-powered-by"


def test_nextdns_consumer_uses_active_detector_when_flagged(tmp_path):
    def handler(request):
        if request.url.path.endswith("/logs/stream"):
            return httpx.Response(
                200, content=b'id: evt-1\ndata: {"domain": "www.example.com"}\n\n'
            )
        if request.url.path == "/" and not request.url.query:
            return httpx.Response(
                200,
                text='<link rel="stylesheet" href="/wp-content/themes/x/site.css">',
                headers={"server": "nginx"},
            )
        return httpx.Response(404)

    storage = Storage(str(tmp_path / "stats.db"))
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    consumer = nextdns.NextDNSStreamConsumer(
        nextdns.NextDNSConfig(api_key="key", profile="p1"),
        storage,
        nextdns.StreamStatus(enabled=True),
        client=client,
        active_mode=True,
    )

    async def drive():
        try:
            await consumer._consume()
            if consumer._tasks:
                await asyncio.gather(*consumer._tasks)
        finally:
            await client.aclose()

    run(drive())

    detail = storage.host_detail("www.example.com")
    assert detail["latest"]["status"] == "unknown"
    assert detail["latest"]["source"] == "cms-artifacts"
    assert detail["latest"]["origin"] == "nextdns"


def test_nextdns_consumer_default_stays_header_only(tmp_path):
    def handler(request):
        if request.url.path.endswith("/logs/stream"):
            return httpx.Response(
                200, content=b'id: evt-1\ndata: {"domain": "www.example.com"}\n\n'
            )
        assert request.url.path == "/" and not request.url.query
        return httpx.Response(
            200, headers={"x-powered-by": "PHP/8.2.10", "server": "nginx"}
        )

    storage = Storage(str(tmp_path / "stats.db"))
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    consumer = nextdns.NextDNSStreamConsumer(
        nextdns.NextDNSConfig(api_key="key", profile="p1"),
        storage,
        nextdns.StreamStatus(enabled=True),
        client=client,
    )

    async def drive():
        try:
            await consumer._consume()
            if consumer._tasks:
                await asyncio.gather(*consumer._tasks)
        finally:
            await client.aclose()

    run(drive())

    detail = storage.host_detail("www.example.com")
    assert detail["latest"]["status"] == "vulnerable"
    assert detail["latest"]["source"] == "x-powered-by"
