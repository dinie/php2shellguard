from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import detection, nextdns
from .models import CheckRequest, CheckResponse, CveInfo, StatsResponse
from .storage import Storage

BASE_DIR = Path(__file__).resolve().parent

CVES = [CveInfo(**cve) for cve in detection.CVES]

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)
_IPV6_RE = re.compile(r"^[0-9a-f:.%]+$")


def _extract_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if _HOSTNAME_RE.match(host) or _IPV6_RE.match(host):
        return host
    raise HTTPException(status_code=422, detail="url has no usable host")


def create_app(db_path: str | None = None) -> FastAPI:
    load_dotenv()
    # db_path/PHP2SHELL_DATABASE_URL/PHP2SHELL_DB resolution lives in Storage.
    storage = Storage(db_path)
    nextdns_config = nextdns.NextDNSConfig.from_env()
    stream_status = nextdns.StreamStatus(enabled=nextdns_config is not None)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        consumer = None
        stream_task = None
        if nextdns_config is not None:
            consumer = nextdns.NextDNSStreamConsumer(
                nextdns_config, storage, stream_status
            )
            stream_task = asyncio.create_task(consumer.run())
        yield
        if stream_task is not None:
            stream_task.cancel()
            await asyncio.gather(stream_task, return_exceptions=True)
        if consumer is not None:
            await consumer.aclose()

    app = FastAPI(title="PHP2Shell Guard API", version="1.0.0", lifespan=lifespan)
    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @app.post("/api/v1/check", response_model=CheckResponse)
    def check(payload: CheckRequest) -> CheckResponse:
        host = _extract_host(payload.url)
        analysis = detection.evaluate(
            server=payload.server,
            x_powered_by=payload.x_powered_by,
            cookie_names=payload.cookie_names,
        )
        checked_at = datetime.now(timezone.utc)
        storage.record_check(
            host=host,
            status=analysis.status,
            php_version=analysis.php_version,
            source=analysis.evidence_source,
            checked_at=checked_at,
        )
        return CheckResponse(
            host=host,
            status=analysis.status,
            php_version=analysis.php_version,
            branch=analysis.branch,
            patched_version=analysis.patched_version,
            evidence_source=analysis.evidence_source,
            reason=analysis.reason,
            cves=CVES,
            checked_at=checked_at,
        )

    @app.get("/api/v1/stats", response_model=StatsResponse)
    def stats() -> dict:
        return storage.stats()

    @app.get("/api/v1/hosts")
    def hosts() -> list[dict]:
        return storage.hosts()

    @app.get("/api/v1/hosts/{host}")
    def host_detail(host: str) -> dict:
        detail = storage.host_detail(host)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"no checks recorded for {host}")
        return detail

    @app.get("/api/v1/inputs/nextdns")
    def nextdns_input() -> dict:
        return stream_status.snapshot()

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        snapshot = storage.stats()
        chart_max = max(
            (sum(day["counts"].values()) for day in snapshot["daily"]), default=1
        )
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "stats": snapshot,
                "statuses": detection.ALL_STATUSES,
                "chart_max": chart_max,
                "cves": detection.CVES,
                "reference_url": "https://www.php2shell.com/",
            },
        )

    @app.get("/hosts/{host}", response_class=HTMLResponse)
    def host_report(request: Request, host: str) -> HTMLResponse:
        detail = storage.host_detail(host)
        status_code = 200 if detail is not None else 404
        return templates.TemplateResponse(
            request,
            "host.html",
            {
                "host": host.lower(),
                "detail": detail,
                "cves": detection.CVES,
                "mitigations": detection.MITIGATIONS,
                "upgrade_targets": detection.UPGRADE_TARGETS,
                "reference_url": "https://www.php2shell.com/",
            },
            status_code=status_code,
        )

    @app.exception_handler(404)
    async def not_found(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"detail": getattr(exc, "detail", "not found")},
        )

    return app


app = create_app()
