"""Periodic re-verification of every stored host — run from cron, e.g.:

    */15 * * * * cd /path/to/backend && .venv/bin/python -m app.recheck

Each run actively probes every host in the stats database (one header-only
HTTPS request per host, identical to the NextDNS input's probe), appends a
fresh verdict with ``origin="recheck"``, and maintains the ``host_registry``
table: the host's *original* status is captured on first sight and never
overwritten, while current_* tracks the latest verdict. Status transitions
are printed to stdout so they land in the cron log.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx
from dotenv import load_dotenv

from . import detection, probe
from .storage import Storage

PROBE_CONCURRENCY = 8


@dataclass(frozen=True)
class RecheckResult:
    host: str
    previous_status: str
    analysis: detection.Analysis | None
    error: str | None


async def _recheck_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    host: str,
    previous_status: str,
) -> RecheckResult:
    try:
        async with semaphore:
            analysis = await probe.fetch_analysis(client, host)
    except Exception as exc:
        return RecheckResult(host, previous_status, None, str(exc))
    return RecheckResult(host, previous_status, analysis, None)


async def run_rechecks(
    storage: Storage, client: httpx.AsyncClient, concurrency: int = PROBE_CONCURRENCY
) -> list[RecheckResult]:
    """Probe every stored host and record fresh verdicts + registry state."""
    hosts = storage.hosts()
    semaphore = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(
        *(
            _recheck_one(client, semaphore, row["host"], row["status"])
            for row in hosts
        )
    )
    for result in results:
        if result.analysis is not None:
            storage.record_recheck(
                host=result.host,
                status=result.analysis.status,
                php_version=result.analysis.php_version,
                source=result.analysis.evidence_source,
            )
    return list(results)


def print_report(results: list[RecheckResult]) -> None:
    probed = changed = failed = 0
    for result in results:
        if result.error is not None:
            failed += 1
            print(f"{result.host}: probe failed ({result.error})")
            continue
        probed += 1
        analysis = result.analysis
        version = f" ({analysis.php_version})" if analysis.php_version else ""
        if analysis.status != result.previous_status:
            changed += 1
            print(
                f"{result.host}: {result.previous_status} -> "
                f"{analysis.status}{version}"
            )
        else:
            print(f"{result.host}: {analysis.status}{version} [unchanged]")
    print(
        f"recheck complete: {probed} probed, "
        f"{changed} status change(s), {failed} failure(s)"
    )


def main() -> int:
    load_dotenv()
    storage = Storage()
    host_count = len(storage.hosts())
    if host_count == 0:
        print("no hosts stored; nothing to recheck")
        return 0
    print(f"rechecking {host_count} host(s) from {storage.location}")

    async def _run() -> list[RecheckResult]:
        timeout = httpx.Timeout(probe.DEFAULT_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await run_rechecks(storage, client)

    print_report(asyncio.run(_run()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
