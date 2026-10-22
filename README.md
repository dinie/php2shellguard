# PHP2Shell Guard

A browser tool that warns you when the site you are visiting is running a PHP
version affected by the **php2shell** class of vulnerabilities
([CVE-2026-109618](https://www.php2shell.com/) / CVE-2026-109619 — CVSS 9.2,
unauthenticated RCE and memory disclosure in PHP below 8.2.35 / 8.3.36 /
8.4.27 / 8.5.12).

Detection is **passive**: the extension forwards the response headers your
browser already received (`Server`, `X-Powered-By`, `Set-Cookie` names) to a
local FastAPI backend, which evaluates the advertised PHP version against the
patched-release matrix from [php2shell.com](https://www.php2shell.com/). No
traffic is ever sent to the analysed site beyond your normal page load.

## Components

| Component    | Path         | Role |
|--------------|--------------|------|
| Backend API  | `backend/`   | FastAPI: verdict evaluation, SQLite stats store, HTML dashboard + per-host reports |
| Extension    | `extension/` | Manifest V3 Chrome extension: header capture, badge + popup, forwards observations |

## Quick start

```bash
# 1. Start the analysis backend (requires Python 3.12)
cd backend
uv venv --python 3.12 .venv
. .venv/bin/activate
uv pip install -r requirements.txt
uvicorn app.main:app --reload
```

The backend listens at <http://localhost:8000> and immediately shows a stats
dashboard at <http://localhost:8000/>.

```text
# 2. Install the extension
#    → open chrome://extensions
#    → enable "Developer mode" (top right)
#    → "Load unpacked" → select the extension/ directory
```

Browse the web normally. The toolbar badge updates per tab:

| Badge | Meaning |
|-------|---------|
| `VULN` (red)  | PHP version is below the php2shell patch release — affected |
| `OK` (green)  | PHP version includes the php2shell fix |
| `?` (amber)   | PHP usage detected but the server hides its exact version |
| `OFF` (amber) | Backend unreachable — start the FastAPI server |
| *(none)*      | No PHP indicators in the response headers |

Click the extension icon for the current site's detail, CVE info, and links
to the full per-host report. The backend URL can be changed under
"Backend settings" in the popup.

## NextDNS stream input

Besides browser activity, the backend can ingest your NextDNS query log as a
second input source. Set two environment variables before starting it:

```bash
export NEXTDNS_API_KEY=…     # sent as the X-Api-Key header
export NEXTDNS_PROFILE=…     # your NextDNS profile ID
```

The backend then consumes
`GET https://api.nextdns.io/profiles/{profile}/logs/stream` (Server-Sent
Events) in the background and, for each newly observed DNS domain, actively
probes the site's HTTPS response headers and evaluates the php2shell
verdict — no browser visit required. Event consumption resumes from the last
stored SSE id after restarts, blocked domains are skipped, and each domain is
re-probed at most once per 12 hours (`NEXTDNS_CHECK_TTL_HOURS`). Check
`GET /api/v1/inputs/nextdns` or the dashboard's new "Input" column
(`extension` vs `nextdns`) to see it working.

## Verdict logic (`backend/app/detection.py`)

- Parses `PHP/x.y.z` out of `X-Powered-By` (preferred) or `Server` headers.
- Compares against `{8.2 → 8.2.35, 8.3 → 8.3.36, 8.4 → 8.4.27, 8.5 → 8.5.12}`.
- Below the patched release (or any EOL branch ≤ 8.1, down to 5.4) → `vulnerable`.
- At/above the patched release → `patched`.
- PHP evidenced only via a `PHPSESSID` cookie or bare `PHP` token → `unknown`.
- No PHP evidence at all → `not_php`.

## Privacy

Only the **hostname, detected PHP version, verdict, input source, and check
timestamp** are stored — never full URLs, paths, query strings, or raw header
values. All data stays in a local SQLite file by default
(`backend/php2shell-stats.db`, override with `PHP2SHELL_DB`), or in
PostgreSQL when `PHP2SHELL_DATABASE_URL` points at a Postgres server —
see `backend/README.md`.

Note that inputs differ in passivity: the extension only ever forwards
headers your browser already received, the optional NextDNS input sends one
header-only HTTPS request per observed domain, and the cron recheck
(`python -m app.recheck`, see `backend/README.md`) runs the active detector,
which follows redirects like a browser, scans the landing page for PHP
fingerprints, and tries the classic PHP easter-egg/`phpinfo.php` disclosure
endpoints (at most four small GETs per host per run). Body content is analysed
transiently and never stored. Setting `PHP2SHELL_ACTIVE=1` turns that active
detector on everywhere: submitted hosts are investigated server-side and the
NextDNS probes also escalate to full fingerprinting.

## Tests

```bash
cd backend
pytest
```

See `backend/README.md` for the full API reference.