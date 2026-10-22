"""NextDNS logs stream input.

Consumes the Server-Sent Events stream at
``GET https://api.nextdns.io/profiles/{profile}/logs/stream`` and, for each
newly observed DNS domain, actively probes the site's HTTPS response headers
and evaluates the php2shell verdict. Verdicts are stored with
``origin="nextdns"``.

Unlike the browser-extension flow (strictly passive), this input source
sends traffic to the analysed sites: one header-only HTTPS request per
domain, de-duplicated by a TTL window. With ``PHP2SHELL_ACTIVE`` set it
upgrades to the full active detector (app/active.py) instead.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from . import active, probe
from .storage import Storage

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.nextdns.io"
STATE_KEY_LAST_EVENT_ID = "nextdns:last_event_id"

_BACKOFF_START_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 60.0


@dataclass(frozen=True)
class NextDNSConfig:
    api_key: str
    profile: str
    base_url: str = DEFAULT_BASE_URL
    probe_concurrency: int = 4
    check_ttl_hours: float = 12.0
    probe_timeout: float = 10.0
    connect_timeout: float = 15.0

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "NextDNSConfig | None":
        env = os.environ if environ is None else environ
        api_key = env.get("NEXTDNS_API_KEY")
        profile = env.get("NEXTDNS_PROFILE")
        if not api_key or not profile:
            return None
        return cls(
            api_key=api_key,
            profile=profile,
            base_url=env.get("NEXTDNS_BASE_URL", DEFAULT_BASE_URL),
            probe_concurrency=int(env.get("NEXTDNS_PROBE_CONCURRENCY", "4")),
            check_ttl_hours=float(env.get("NEXTDNS_CHECK_TTL_HOURS", "12")),
        )

    @property
    def stream_url(self) -> str:
        return f"{self.base_url}/profiles/{self.profile}/logs/stream"


@dataclass
class StreamStatus:
    enabled: bool = False
    connected: bool = False
    events_seen: int = 0
    probes_recorded: int = 0
    last_event_at: datetime | None = None
    last_error: str | None = None

    def snapshot(self) -> dict:
        return {
            "enabled": self.enabled,
            "connected": self.connected,
            "events_seen": self.events_seen,
            "probes_recorded": self.probes_recorded,
            "last_event_at": (
                self.last_event_at.isoformat() if self.last_event_at else None
            ),
            "last_error": self.last_error,
        }


@dataclass(frozen=True)
class SseEvent:
    data: str
    event_id: str | None = None


class SseParser:
    """Incremental server-sent-events parser; feed lines, get events."""

    def __init__(self) -> None:
        self._data_lines: list[str] = []
        self._event_id: str | None = None

    def feed(self, line: str) -> SseEvent | None:
        line = line.rstrip("\r")
        if not line:
            if not self._data_lines:
                return None
            event = SseEvent(data="\n".join(self._data_lines), event_id=self._event_id)
            self._data_lines = []
            self._event_id = None
            return event
        if line.startswith(":"):
            return None
        field, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if field == "data":
            self._data_lines.append(value)
        elif field == "id":
            self._event_id = value
        return None


def domain_from_event(event: SseEvent) -> str | None:
    """Pick the queried domain out of a NextDNS log event, or None to skip."""
    try:
        payload = json.loads(event.data)
    except json.JSONDecodeError:
        return None
    if payload.get("status", "default") != "default":
        return None
    domain = payload.get("domain")
    if not isinstance(domain, str) or not domain:
        return None
    return domain.rstrip(".").lower()


class NextDNSStreamConsumer:
    """Long-running consumer: stream NextDNS logs, probe observed domains."""

    def __init__(
        self,
        config: NextDNSConfig,
        storage: Storage,
        status: StreamStatus,
        client: httpx.AsyncClient | None = None,
        active_mode: bool = False,
    ) -> None:
        self._config = config
        self._storage = storage
        self._status = status
        self._active_mode = active_mode
        # Created lazily: asyncio primitives must bind inside a running loop.
        self._semaphore: asyncio.Semaphore | None = None
        self._tasks: set[asyncio.Task] = set()
        self._inflight: set[str] = set()
        if client is not None:
            self._owns_clients = False
            self._stream_client = client
            self._probe_client = client
        else:
            self._owns_clients = True
            # The long-lived stream must not carry a read timeout: the server
            # stays silent whenever there is no DNS activity.
            self._stream_client = httpx.AsyncClient(
                timeout=httpx.Timeout(None, connect=config.connect_timeout)
            )
            self._probe_client = httpx.AsyncClient(
                timeout=httpx.Timeout(config.probe_timeout)
            )

    async def aclose(self) -> None:
        if self._owns_clients:
            await self._stream_client.aclose()
            await self._probe_client.aclose()

    async def run(self) -> None:
        backoff = _BACKOFF_START_SECONDS
        try:
            while True:
                try:
                    await self._consume()
                    backoff = _BACKOFF_START_SECONDS
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # keep the consumer alive
                    self._status.last_error = str(exc)
                    logger.warning("nextdns stream dropped: %s", exc)
                self._status.connected = False
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, _BACKOFF_MAX_SECONDS)
        finally:
            for task in self._tasks:
                task.cancel()
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _consume(self) -> None:
        headers = {
            "Accept": "application/json",
            "X-Api-Key": self._config.api_key,
        }
        params = {}
        last_id = self._storage.get_state(STATE_KEY_LAST_EVENT_ID)
        if last_id:
            params["id"] = last_id
        async with self._stream_client.stream(
            "GET", self._config.stream_url, headers=headers, params=params
        ) as response:
            response.raise_for_status()
            self._status.connected = True
            self._status.last_error = None
            logger.info("connected to nextdns log stream")
            parser = SseParser()
            async for line in response.aiter_lines():
                event = parser.feed(line)
                if event is not None:
                    self._handle_event(event)

    def _handle_event(self, event: SseEvent) -> None:
        if event.event_id:
            self._storage.set_state(STATE_KEY_LAST_EVENT_ID, event.event_id)
        self._status.events_seen += 1
        self._status.last_event_at = datetime.now(timezone.utc)
        domain = domain_from_event(event)
        if (
            domain
            and domain not in self._inflight
            and not self._storage.checked_recently(domain, self._config.check_ttl_hours)
        ):
            self._schedule_probe(domain)

    def _schedule_probe(self, domain: str) -> None:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._config.probe_concurrency)
        self._inflight.add(domain)
        task = asyncio.create_task(self._probe(domain))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _probe(self, domain: str) -> None:
        scan = active.investigate if self._active_mode else probe.fetch_analysis
        try:
            assert self._semaphore is not None
            async with self._semaphore:
                analysis = await scan(self._probe_client, domain)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("probe of %s failed: %s", domain, exc)
            return
        finally:
            self._inflight.discard(domain)
        self._storage.record_check(
            host=domain,
            status=analysis.status,
            php_version=analysis.php_version,
            source=analysis.evidence_source,
            checked_at=datetime.now(timezone.utc),
            origin="nextdns",
        )
        self._status.probes_recorded += 1
