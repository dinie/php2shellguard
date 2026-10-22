"""Active PHP detection — a step beyond passive self-disclosure headers.

Used by the periodic recheck task (app/recheck.py). The browser extension
stays strictly passive and the NextDNS input stays header-only; this module
deliberately sends a few small GETs per host, mimicking a single browser
visit plus, where useful, PHP's own built-in disclosure endpoints:

1. ``GET /`` following redirects — the apex domain usually forwards to the
   real app, whose headers and Set-Cookies are what a browser would see.
   The passive matrix (detection.evaluate) runs on that final response.
2. Body analysis of the landing page (capped at ``BODY_CAP`` bytes): CMS
   generator meta tags, WordPress/Drupal asset paths, and ``.php`` links or
   form targets — all PHP fingerprints that never appear in headers.
3. PHP easter eggs (``/?=<credits hash>`` can leak the exact version) and an
   exposed ``/phpinfo.php`` — increasingly rare, but a strong version source
   on less hardened hosts.

A versioned verdict (vulnerable/patched, sourced from ``verdict_for_version``)
short-circuits; ``unknown`` candidates accumulate, strongest first. Bodies
are scanned transiently and never stored — storage still only ever sees
hostname, verdict, version and timestamp.
"""

from __future__ import annotations

import os
import re

import httpx

from . import detection
from .probe import cookie_names

BODY_CAP = 262_144

_TRUE_VALUES = {"1", "true", "yes", "on"}


def enabled_from_env() -> bool:
    """Whether the ``PHP2SHELL_ACTIVE`` env var turns the active detector on
    for the whole backend (``/api/v1/check`` and the NextDNS input)."""
    return os.environ.get("PHP2SHELL_ACTIVE", "").strip().lower() in _TRUE_VALUES

_CREDITS_HASH = "PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"
_LOGO_HASH = "PHPE9568F35-D428-11d2-A769-00AA001ACF42"

_VERSION_TAG_RE = re.compile(r"PHP\s*Version\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
_GENERATOR_A_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", re.IGNORECASE
)
_GENERATOR_B_RE = re.compile(
    r"""<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']""", re.IGNORECASE
)
_CMS_ARTIFACT_RE = re.compile(
    r"/(wp-content|wp-includes|wp-json|sites/default/files)/|misc/drupal\.js",
    re.IGNORECASE,
)
_PHP_REF_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["'][^"']*\.php(?:[\?'"]|$)""", re.IGNORECASE
)
# CMSes/frameworks that imply a PHP backend.
_PHP_CMS_NAMES = (
    "wordpress", "drupal", "joomla", "typo3", "magento", "silverstripe",
    "contao", "phpbb", "mediawiki", "octobercms", "laravel", "symfony",
)


async def _get(
    client: httpx.AsyncClient, url: str, *, follow_redirects: bool = False
) -> tuple[int, httpx.Headers, str, list[httpx.Headers]]:
    """GET *url*, returning (status, headers, capped body text, redirect chain)."""
    chunks, size = [], 0
    async with client.stream(
        "GET", url, follow_redirects=follow_redirects
    ) as response:
        status = response.status_code
        headers = response.headers
        chain = [r.headers for r in response.history]
        async for chunk in response.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= BODY_CAP:
                break
    return status, headers, b"".join(chunks).decode("utf-8", "replace"), chain


def _version_tag(body: str) -> tuple[int, int, int] | None:
    match = _VERSION_TAG_RE.search(body)
    if not match:
        return None
    parts = [int(part) for part in match.group(1).split(".")]
    parts += [0] * (3 - len(parts))
    return tuple(parts)


def _generator_signal(body: str) -> str | None:
    for pattern in (_GENERATOR_A_RE, _GENERATOR_B_RE):
        match = pattern.search(body)
        if match and any(name in match.group(1).lower() for name in _PHP_CMS_NAMES):
            return match.group(1)
    return None


def _body_candidates(body: str) -> list[detection.Analysis]:
    """PHP fingerprints found in the landing-page HTML (best first)."""
    generator = _generator_signal(body)
    if generator:
        return [
            detection.Analysis(
                status=detection.STATUS_UNKNOWN,
                evidence_source="generator-tag",
                reason=(
                    f"Generator tag {generator!r} declares a PHP-based CMS, "
                    "but the PHP version is not disclosed."
                ),
            )
        ]
    if _CMS_ARTIFACT_RE.search(body):
        return [
            detection.Analysis(
                status=detection.STATUS_UNKNOWN,
                evidence_source="cms-artifacts",
                reason=(
                    "Landing page loads WordPress/Drupal-style asset paths "
                    "(e.g. /wp-content/), but the PHP version is not disclosed."
                ),
            )
        ]
    match = _PHP_REF_RE.search(body)
    if match:
        return [
            detection.Analysis(
                status=detection.STATUS_UNKNOWN,
                evidence_source="body-php-references",
                reason=(
                    f"Page links or forms reference .php endpoints "
                    f"(e.g. {match.group(0)!r}), but the PHP version is not disclosed."
                ),
            )
        ]
    return []


async def investigate(client: httpx.AsyncClient, host: str) -> detection.Analysis:
    """Actively fingerprint *host* for PHP; at most 4 GETs are sent."""
    status, headers, body, chain = await _get(
        client, f"https://{host}/", follow_redirects=True
    )
    cookies: list[str] = []
    for hop in chain + [headers]:
        cookies.extend(cookie_names(hop))
    passive = detection.evaluate(
        server=headers.get("server"),
        x_powered_by=headers.get("x-powered-by"),
        cookie_names=cookies,
    )
    if passive.php_version is not None:
        return passive

    status, _, credits_body, _ = await _get(client, f"https://{host}/?={_CREDITS_HASH}")
    if status == 200:
        version = _version_tag(credits_body)
        if version:
            return detection.verdict_for_version(version, source="credits-easter-egg")
        if "PHP Credits" in credits_body:
            return detection.Analysis(
                status=detection.STATUS_UNKNOWN,
                evidence_source="credits-easter-egg",
                reason="PHP credits easter egg page answered.",
            )

    status, egg_headers, _, _ = await _get(client, f"https://{host}/?={_LOGO_HASH}")
    logo_candidate = (
        status == 200
        and (egg_headers.get("content-type") or "").startswith("image/")
    )

    status, _, phpinfo_body, _ = await _get(client, f"https://{host}/phpinfo.php")
    if status == 200:
        version = _version_tag(phpinfo_body)
        if version:
            return detection.verdict_for_version(version, source="phpinfo")
        if "phpinfo()" in phpinfo_body:
            return detection.Analysis(
                status=detection.STATUS_UNKNOWN,
                evidence_source="phpinfo",
                reason="Server exposes a /phpinfo.php page.",
            )

    # No version found anywhere: fall back to passive result or the best
    # active "PHP present, version hidden" candidate.
    if passive.status != detection.STATUS_NOT_PHP:
        return passive
    candidates = _body_candidates(body)
    if candidates:
        return candidates[0]
    if logo_candidate:
        return detection.Analysis(
            status=detection.STATUS_UNKNOWN,
            evidence_source="logo-easter-egg",
            reason="PHP logo easter egg returned an image.",
        )
    return passive
