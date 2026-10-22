"""Passive detection for the php2shell class of PHP-core vulnerabilities.

Covers CVE-2026-109618 (OOM corruption) and CVE-2026-109619 (stale global
state across requests). Works purely from response headers the browser
already received — no active probing of the target site is performed.

Reference matrix (https://www.php2shell.com/): patched releases are
8.2.35, 8.3.36, 8.4.27 and 8.5.12. Anything below those — including every
EOL branch down to reportedly PHP 5.4 — is treated as vulnerable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

STATUS_VULNERABLE = "vulnerable"
STATUS_PATCHED = "patched"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_PHP = "not_php"

ALL_STATUSES = (STATUS_VULNERABLE, STATUS_PATCHED, STATUS_UNKNOWN, STATUS_NOT_PHP)

# First release per supported branch that patches the php2shell CVEs.
PATCHED_RELEASES: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Newest branch covered by the disclosure; anything newer is assumed patched.
_HIGHEST_KNOWN_BRANCH = (8, 5)

UPGRADE_TARGETS = "8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or later)"

CVES: list[dict] = [
    {
        "id": "CVE-2026-109618",
        "cvss": 9.2,
        "title": "Out-of-memory corruption",
        "summary": (
            "Memory exhaustion corrupts PHP-core state, enabling "
            "unauthenticated remote code execution on the target server."
        ),
    },
    {
        "id": "CVE-2026-109619",
        "cvss": 9.2,
        "title": "Stale global state across requests",
        "summary": (
            "Request state persists across PHP worker reuse, leaking sensitive "
            "memory (credentials, tokens, keys) and enabling code execution."
        ),
    },
]

# Temporary mitigations per the php2shell.com disclosure. Upgrading is the
# only complete fix; these reduce exposure in the interim.
MITIGATIONS: list[dict] = [
    {
        "name": "Upgrade PHP",
        "detail": f"Move to {UPGRADE_TARGETS}. Only a full upgrade removes the vulnerability.",
    },
    {
        "name": "Restart PHP services",
        "detail": "Restart Apache / PHP-FPM / long-running workers after the upgrade so no stale workers remain.",
    },
    {
        "name": "memory_limit = -1",
        "detail": "Avoids the vulnerable OOM code path; contain usage with cgroup memory.max instead.",
    },
    {
        "name": "Reduce memory pressure",
        "detail": "Lower post_max_size and max_input_nesting_level; disable session.upload_progress.",
    },
    {
        "name": "display_errors = 0",
        "detail": "Hides error output, reducing memory-disclosure surface.",
    },
    {
        "name": "fatal_error_backtraces = 0",
        "detail": "Blocks one demonstrated trigger mechanism where the setting is supported.",
    },
    {
        "name": "Lower pm.max_requests",
        "detail": "Recycles PHP-FPM workers more often, limiting stale state across requests.",
    },
    {
        "name": "SELinux / AppArmor",
        "detail": "Constrain worker capabilities to limit the impact of a successful exploit.",
    },
]

_VERSION_RE = re.compile(r"PHP/(\d+)(?:\.(\d+))?(?:\.(\d+))?", re.IGNORECASE)
_PHP_TOKEN_RE = re.compile(r"\bphp\b", re.IGNORECASE)
_PHPSESSID_RE = re.compile(r"^phpsessid", re.IGNORECASE)


@dataclass
class Analysis:
    status: str
    php_version: str | None = None
    branch: str | None = None
    patched_version: str | None = None
    evidence_source: str | None = None  # "x-powered-by" | "server" | "cookie"
    reason: str = ""


def parse_version(text: str | None) -> tuple[int, int, int] | None:
    """Extract a PHP/x.y.z version tuple from a header value."""
    if not text:
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
    )


def _format_version(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


def evaluate(
    server: str | None = None,
    x_powered_by: str | None = None,
    cookie_names: list[str] | None = None,
) -> Analysis:
    """Produce a php2shell verdict from passively observed header values."""
    for source, value in (("x-powered-by", x_powered_by), ("server", server)):
        version = parse_version(value)
        if version:
            return _verdict_for_version(version, source)

    cookies = cookie_names or []
    if any(_PHPSESSID_RE.match(name) for name in cookies):
        return Analysis(
            status=STATUS_UNKNOWN,
            evidence_source="cookie",
            reason="PHPSESSID cookie observed, but the server does not disclose its PHP version.",
        )
    if _PHP_TOKEN_RE.search(x_powered_by or "") or _PHP_TOKEN_RE.search(server or ""):
        return Analysis(
            status=STATUS_UNKNOWN,
            evidence_source="server",
            reason="PHP token found in response headers, but no version was disclosed.",
        )
    return Analysis(
        status=STATUS_NOT_PHP,
        reason="No PHP indicators in the observed response headers.",
    )


def _verdict_for_version(version: tuple[int, int, int], source: str) -> Analysis:
    major_minor = version[:2]
    version_str = _format_version(version)
    branch_str = f"{version[0]}.{version[1]}"

    if major_minor in PATCHED_RELEASES:
        patched = PATCHED_RELEASES[major_minor]
        patched_str = _format_version(patched)
        if version < patched:
            return Analysis(
                status=STATUS_VULNERABLE,
                php_version=version_str,
                branch=branch_str,
                patched_version=patched_str,
                evidence_source=source,
                reason=f"PHP {version_str} is below the php2shell patch release {patched_str}.",
            )
        return Analysis(
            status=STATUS_PATCHED,
            php_version=version_str,
            branch=branch_str,
            patched_version=patched_str,
            evidence_source=source,
            reason=f"PHP {version_str} includes the php2shell fix (patched in {patched_str}).",
        )

    if major_minor > _HIGHEST_KNOWN_BRANCH:
        return Analysis(
            status=STATUS_PATCHED,
            php_version=version_str,
            branch=branch_str,
            evidence_source=source,
            reason=(
                f"PHP {version_str} is newer than every branch affected by php2shell "
                "and is assumed patched."
            ),
        )

    return Analysis(
        status=STATUS_VULNERABLE,
        php_version=version_str,
        branch=branch_str,
        evidence_source=source,
        reason=(
            f"PHP {version_str} predates the php2shell patch releases "
            f"({UPGRADE_TARGETS})."
        ),
    )
