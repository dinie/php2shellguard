# PHP2Shell Guard — backend

FastAPI service that receives passive header observations from the browser
extension, evaluates them against the php2shell patched-release matrix, and
stores usage statistics in SQLite — or PostgreSQL when
`PHP2SHELL_DATABASE_URL` is set.

## Setup

Requires Python 3.12 (see `.python-version`).

```bash
uv venv --python 3.12 .venv
. .venv/bin/activate
uv pip install -r requirements.txt
uvicorn app.main:app --reload        # http://localhost:8000
```

Copy `example.env` to `.env` to configure; both the app and the recheck
script load it. All values are also honoured straight from the environment.

Configuration:

| Env var         | Default                    | Purpose |
|-----------------|----------------------------|---------|
| `PHP2SHELL_DATABASE_URL` | — | SQLAlchemy database URL; when set, stats are stored there instead of SQLite. `postgresql://`/`postgres://` URLs use the psycopg v3 driver |
| `PHP2SHELL_DB`  | `backend/php2shell-stats.db` | SQLite stats database path (ignored when `PHP2SHELL_DATABASE_URL` is set) |
| `PHP2SHELL_ACTIVE` | off | When truthy (`1`/`true`/`yes`/`on`), the `/check` endpoint and the NextDNS input use the full active detector (`app/active.py`) instead of passive/header-only evaluation. Rechecks are always active |
| `PHP2SHELL_RECHECK_TOKEN` | — | When set, `POST /recheck` requires `Authorization: Bearer <token>` |
| `NEXTDNS_API_KEY` | — | NextDNS API key, sent as `X-Api-Key` (enables the stream input together with `NEXTDNS_PROFILE`) |
| `NEXTDNS_PROFILE` | — | NextDNS profile ID to stream logs from |
| `NEXTDNS_BASE_URL` | `https://api.nextdns.io` | API base URL override |
| `NEXTDNS_PROBE_CONCURRENCY` | `4` | Max concurrent domain probes |
| `NEXTDNS_CHECK_TTL_HOURS` | `12` | Re-probe a domain at most once per this window |

## NextDNS stream input

When `NEXTDNS_API_KEY` and `NEXTDNS_PROFILE` are set, the backend connects to
`GET https://api.nextdns.io/profiles/{profile}/logs/stream` (Server-Sent
Events) inside the FastAPI process and watches DNS log events in real time.
For each newly observed domain it **actively probes** the site's HTTPS
response headers (a single header-only request, de-duplicated by
`NEXTDNS_CHECK_TTL_HOURS`) and evaluates the php2shell verdict — unlike the
strictly passive browser-extension flow, this input source sends traffic to
the analysed sites. With `PHP2SHELL_ACTIVE` set, the probes escalate to the
full active detector (redirect-following, body fingerprints, disclosure
endpoints) described in "Periodic rechecks" below.

The last SSE event id is persisted in SQLite (`stream_state` table) and sent
back as the `id` parameter after reconnects, so restarts do not miss or
duplicate events. Verdicts are recorded with `origin="nextdns"` (extension
checks use `origin="extension"`); domains whose log status is blocked are
skipped.

## Periodic rechecks (cron)

`python -m app.recheck` re-verifies every stored host with the **active
detector** (`app/active.py`), which goes beyond self-disclosure headers. At
most four small GETs are sent per host per run:

1. `GET /` following redirects — the apex domain usually forwards to the real
   app, whose final response headers and Set-Cookies are what a browser
   would see; the passive verdict matrix runs on those.
2. Landing-page body fingerprints (capped at 256 KiB, scanned transiently,
   never stored): CMS `<meta name="generator">` tags, WordPress/Drupal asset
   paths (`/wp-content/`, `/sites/default/files/…`), and `.php` links or
   form targets. These upgrade a silent host from `not_php` to `unknown`.
3. PHP easter eggs (`/?=<credits hash>` can leak the exact version) and an
   exposed `/phpinfo.php`, either of which can produce a versioned verdict.

Each run appends a fresh verdict with `origin="recheck"` (the `source`
column records which signal produced it) and updates the `host_registry`
table: the host's **original** status is captured on first sight and never
overwritten, while `current_*` tracks the latest verdict. Status transitions
are printed to stdout for the cron log.

```cron
*/15 * * * * cd /path/to/php2shell/backend && .venv/bin/python -m app.recheck
```

Probe failures are logged and counted in the run summary but never fail the
run (exit code stays 0).

### Triggering rechecks over HTTP

`POST /recheck` starts a recheck run in the background inside the running
FastAPI process: it answers `202 {"status": "started"}` immediately, or
`409` while a previous run is still on. The run prints its report to the
server log. Set `PHP2SHELL_RECHECK_TOKEN` to require a bearer token on this
endpoint (recommended on internet-facing deployments).

`.github/workflows/recheck.yml` ships a GitHub Actions workflow that calls
this endpoint on a schedule (every 30 minutes, plus manual dispatch). Setup:

1. Keep `POST /recheck` reachable from GitHub's runners (public URL or a
   private network path — GitHub-hosted runners need a public route).
2. In the repository: **Settings → Environments → `production` → Environment
   secrets**, add `PHP2SHELL_BASE_URL` (e.g.
   `https://php2shellguard.mydomain.com` — no trailing path or slash) and, if
   configured on the server, `PHP2SHELL_RECHECK_TOKEN`.
3. To use a different environment name, edit `environment:` in the workflow.

A run still executes when the endpoint is not called — `python -m
app.recheck` via cron works as before.

## API

### `POST /api/v1/check`

Ingest one observation and return a verdict. By default the verdict is
evaluated purely from the headers the extension forwarded (passive). With
`PHP2SHELL_ACTIVE` set the backend instead investigates the host with the
active detector, falling back to the forwarded headers if the probe fails.

```json
{
  "url": "https://example.com/page",
  "server": "Apache/2.4.58 (Unix)",
  "x_powered_by": "PHP/8.2.10",
  "cookie_names": ["PHPSESSID"]
}
```

Response (`200`):

```json
{
  "host": "example.com",
  "status": "vulnerable",
  "php_version": "8.2.10",
  "branch": "8.2",
  "patched_version": "8.2.35",
  "evidence_source": "x-powered-by",
  "reason": "PHP 8.2.10 is below the php2shell patch release 8.2.35.",
  "cves": [ ... ],
  "checked_at": "2026-10-22T01:23:45.678901+00:00"
}
```

`status` is one of `vulnerable`, `patched`, `unknown` (PHP detected, version
hidden), `not_php`.

### `GET /api/v1/stats`

Aggregates: total checks, checks today, unique hosts, per-status counts
(event-level and latest-per-host), top PHP versions, 14-day daily series,
and the 25 most recent checks.

### `GET /api/v1/hosts` / `GET /api/v1/hosts/{host}`

Latest verdict per host, or full detail for one host (summary, latest
verdict, last 50 checks). `404` when the host was never checked.

### `GET /` (HTML)

Dashboard: stat cards (the verdict cards link to the filtered host
listings), daily activity chart, version histogram, CVE summary, recent
checks.

### `GET /hosts` (HTML)

Full host listing with latest verdict per host. `?status=` filters to one
verdict: `vulnerable`, `patched`, `unknown` (undetermined) or `not_php`;
invalid values return `422`.

### `GET /hosts/{host}` (HTML)

Per-host report: verdict banner, evidence source, CVE coverage, remediation
guidance (upgrade targets + temporary mitigations), check history.

### `GET /api/v1/inputs/nextdns`

Status of the NextDNS stream input: `enabled`, `connected`, `events_seen`,
`probes_recorded`, `last_event_at`, `last_error`.

### `GET /health`

Liveness probe.

## Storage

SQLite by default; set `PHP2SHELL_DATABASE_URL` to a PostgreSQL URL (e.g.
`postgresql://php2shell:secret@localhost:5432/php2shell`) to store the same
tables on a Postgres server instead. Table `checks(host, status, php_version,
source, origin, checked_at)` holds every verdict, `stream_state(key, value)`
the NextDNS resume cursor, and
`host_registry(host, original_status, original_checked_at, current_status,
current_checked_at)` the recheck script's first-seen tracking. Timestamps are
stored as UTC `TEXT` (`YYYY-MM-DD HH:MM:SS`) so queries behave identically on
both backends. Only hostname-level data is persisted — never full URLs or
raw headers.

### Migrations (Alembic)

Schema versions live in `backend/alembic/` and are managed with Alembic.
App startup and `python -m app.recheck` automatically run `alembic upgrade
head`, so nothing needs to be applied by hand. The baseline revision `0001`
is idempotent: databases created before Alembic was introduced are adopted in
place (missing tables/columns/indexes — notably `checks.origin` — are added,
existing data untouched).

Manual control from `backend/`:

```bash
alembic upgrade head            # apply pending migrations
alembic current                 # show applied revision
alembic revision --autogenerate -m "add widgets table"   # create a new revision
```

The URL used by CLI commands resolves the same way as the app:
`PHP2SHELL_DATABASE_URL` → `PHP2SHELL_DB` → the SQLite default in
`alembic.ini`.

## Tests

```bash
pytest
```

- `tests/test_detection.py` — header parsing and the full verdict matrix.
- `tests/test_api.py` — endpoints, persistence, and the HTML pages, using a
  throwaway database per test.
- `tests/test_storage.py` — backend selection (`PHP2SHELL_DATABASE_URL`
  precedence, Postgres URL normalisation), migration stamping, and adoption
  of pre-Alembic databases.
