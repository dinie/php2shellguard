"""Active header-only probing of hosts.

Fetches ``https://{host}/`` without downloading the response body, then
runs the standard php2shell verdict over the observed headers. Shared by the
NextDNS stream input (app/nextdns.py) and the periodic recheck script
(app/recheck.py).

Unlike the passive extension flow, calling these functions sends traffic to
the analysed site.
"""

from __future__ import annotations

import httpx

from . import detection

DEFAULT_TIMEOUT_SECONDS = 10.0


def cookie_names(headers: httpx.Headers) -> list[str]:
    names = []
    for value in headers.get_list("set-cookie"):
        name, _, _ = value.partition("=")
        name = name.strip()
        if name:
            names.append(name)
    return names


async def fetch_analysis(
    client: httpx.AsyncClient, host: str
) -> detection.Analysis:
    # Header-only fetch: the connection closes without reading the body.
    async with client.stream("GET", f"https://{host}/") as response:
        headers = response.headers
    return detection.evaluate(
        server=headers.get("server"),
        x_powered_by=headers.get("x-powered-by"),
        cookie_names=cookie_names(headers),
    )
