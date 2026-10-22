import asyncio
import sqlite3

import httpx
from fastapi.testclient import TestClient

from app import nextdns
from app.main import create_app
from app.storage import Storage

SSE_BODY = (
    "id: evt-1\n"
    'data: {"timestamp":"2026-10-22T01:00:00.000Z","domain":"WWW.Example.com.",'
    '"status":"default","reasons":[]}\n'
    "\n"
).encode()


def make_config(**overrides):
    params = {"api_key": "key", "profile": "abc123"}
    params.update(overrides)
    return nextdns.NextDNSConfig(**params)


def test_config_from_env_disabled():
    assert nextdns.NextDNSConfig.from_env({}) is None
    assert nextdns.NextDNSConfig.from_env({"NEXTDNS_API_KEY": "k"}) is None
    assert nextdns.NextDNSConfig.from_env({"NEXTDNS_PROFILE": "p"}) is None


def test_config_from_env():
    config = nextdns.NextDNSConfig.from_env(
        {
            "NEXTDNS_API_KEY": "k",
            "NEXTDNS_PROFILE": "p",
            "NEXTDNS_PROBE_CONCURRENCY": "8",
            "NEXTDNS_CHECK_TTL_HOURS": "1.5",
        }
    )
    assert config.stream_url == "https://api.nextdns.io/profiles/p/logs/stream"
    assert config.probe_concurrency == 8
    assert config.check_ttl_hours == 1.5


def test_sse_parser_dispatches_on_blank_line():
    parser = nextdns.SseParser()
    assert parser.feed("id: evt-1") is None
    assert parser.feed('data: {"a": 1}') is None
    event = parser.feed("")
    assert event == nextdns.SseEvent(data='{"a": 1}', event_id="evt-1")
    # Buffered state is cleared after dispatch.
    assert parser.feed("") is None


def test_sse_parser_multiline_data_and_comments():
    parser = nextdns.SseParser()
    assert parser.feed(": keepalive") is None
    parser.feed("data: one")
    parser.feed("data: two")
    event = parser.feed("")
    assert event.data == "one\ntwo"
    assert event.event_id is None


def test_domain_from_event_ok():
    event = nextdns.SseEvent(
        data='{"domain": "WWW.Example.COM.", "status": "default"}'
    )
    assert nextdns.domain_from_event(event) == "www.example.com"


def test_domain_from_event_skips_blocked():
    event = nextdns.SseEvent(
        data='{"domain": "ads.example.com", "status": "blocked"}'
    )
    assert nextdns.domain_from_event(event) is None


def test_domain_from_event_skips_malformed():
    assert nextdns.domain_from_event(nextdns.SseEvent(data="not json")) is None
    assert (
        nextdns.domain_from_event(nextdns.SseEvent(data='{"status": "default"}'))
        is None
    )


def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def drive(consumer, client):
    try:
        await consumer._consume()
        if consumer._tasks:
            await asyncio.gather(*consumer._tasks)
    finally:
        await client.aclose()


def build_consumer(tmp_path, handler, storage=None, **config_overrides):
    client = make_client(handler)
    status = nextdns.StreamStatus(enabled=True)
    storage = storage or Storage(str(tmp_path / "stats.db"))
    consumer = nextdns.NextDNSStreamConsumer(
        make_config(**config_overrides), storage, status, client=client
    )
    return consumer, storage, status, client


def test_consumer_probes_streamed_domain(tmp_path):
    def handler(request):
        if request.url.path.endswith("/logs/stream"):
            assert request.headers["x-api-key"] == "key"
            return httpx.Response(200, content=SSE_BODY)
        assert request.url.host == "www.example.com"
        return httpx.Response(
            200,
            headers={
                "x-powered-by": "PHP/8.2.10",
                "set-cookie": "PHPSESSID=abc; path=/",
            },
        )

    consumer, storage, status, client = build_consumer(tmp_path, handler)
    asyncio.run(drive(consumer, client))

    assert status.connected is True
    assert status.events_seen == 1
    assert status.probes_recorded == 1
    detail = storage.host_detail("www.example.com")
    assert detail["summary"]["total_checks"] == 1
    assert detail["latest"]["status"] == "vulnerable"
    assert detail["latest"]["php_version"] == "8.2.10"
    assert detail["latest"]["source"] == "x-powered-by"
    assert detail["latest"]["origin"] == "nextdns"
    # Last SSE id is persisted so a restart resumes without gaps.
    assert storage.get_state(nextdns.STATE_KEY_LAST_EVENT_ID) == "evt-1"


def test_consumer_sends_resume_id(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    storage.set_state(nextdns.STATE_KEY_LAST_EVENT_ID, "evt-42")

    def handler(request):
        assert request.url.params.get("id") == "evt-42"
        return httpx.Response(200, content=b": quiet\n\n")

    consumer, _, _, client = build_consumer(tmp_path, handler, storage=storage)
    asyncio.run(drive(consumer, client))


def test_consumer_skips_host_checked_within_ttl(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    storage.record_check(host="www.example.com", status="patched")

    def handler(request):
        if request.url.path.endswith("/logs/stream"):
            return httpx.Response(200, content=SSE_BODY)
        raise AssertionError("host inside TTL must not be probed again")

    consumer, storage, status, client = build_consumer(tmp_path, handler, storage=storage)
    asyncio.run(drive(consumer, client))

    assert storage.host_detail("www.example.com")["summary"]["total_checks"] == 1
    assert status.events_seen == 1
    assert status.probes_recorded == 0


def test_probe_failure_does_not_kill_stream(tmp_path):
    def handler(request):
        if request.url.path.endswith("/logs/stream"):
            return httpx.Response(200, content=SSE_BODY)
        raise httpx.ConnectError("refused")

    consumer, _, status, client = build_consumer(tmp_path, handler)
    asyncio.run(drive(consumer, client))

    assert status.events_seen == 1
    assert status.probes_recorded == 0


def test_storage_migrates_origin_column(tmp_path):
    db_path = tmp_path / "old.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE checks ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " host TEXT NOT NULL, status TEXT NOT NULL,"
            " php_version TEXT, source TEXT, checked_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO checks (host, status, checked_at)"
            " VALUES ('legacy.example.com', 'patched', '2026-10-01 00:00:00')"
        )

    storage = Storage(str(db_path))
    detail = storage.host_detail("legacy.example.com")
    assert detail["latest"]["origin"] == "extension"
    storage.record_check(host="legacy.example.com", status="vulnerable", origin="nextdns")
    assert storage.host_detail("legacy.example.com")["latest"]["origin"] == "nextdns"


def test_storage_state_roundtrip(tmp_path):
    storage = Storage(str(tmp_path / "stats.db"))
    assert storage.get_state("missing") is None
    storage.set_state("k", "v1")
    storage.set_state("k", "v2")
    assert storage.get_state("k") == "v2"


class FakeConsumer:
    instances = []

    def __init__(self, config, storage, status, **kwargs):
        self.kwargs = kwargs
        self.ran = False
        self.closed = False
        FakeConsumer.instances.append(self)

    async def run(self):
        self.ran = True
        await asyncio.sleep(3600)

    async def aclose(self):
        self.closed = True


def test_status_endpoint_reports_disabled_when_unconfigured(tmp_path):
    app = create_app(db_path=str(tmp_path / "app.db"))
    with TestClient(app) as client:
        body = client.get("/api/v1/inputs/nextdns").json()
    assert body["enabled"] is False
    assert body["connected"] is False
    assert FakeConsumer.instances == []


def test_lifespan_starts_consumer_when_configured(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXTDNS_API_KEY", "key")
    monkeypatch.setenv("NEXTDNS_PROFILE", "abc123")
    monkeypatch.setattr(nextdns, "NextDNSStreamConsumer", FakeConsumer)
    app = create_app(db_path=str(tmp_path / "app.db"))
    with TestClient(app) as client:
        assert client.get("/api/v1/inputs/nextdns").json()["enabled"] is True
    assert len(FakeConsumer.instances) == 1
    consumer = FakeConsumer.instances[0]
    assert consumer.ran
    assert consumer.closed
