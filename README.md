[![Coverage Status](https://coveralls.io/repos/github/adsabs/api_gateway/badge.svg?branch=main)](https://coveralls.io/github/adsabs/api_gateway?branch=main)

# api_gateway

SciX API Gateway, the core API module for SciX.

## Supported toolchain

The gateway supports CPython 3.12 only (`>=3.12,<3.13`); CI and the container use Python 3.12.15. Flit is the sole package build backend, with its exact backend version declared in `pyproject.toml`; `setup.py`, wheel, and ppsetuptools are not gateway build paths.

Install the environment from the reviewed lock with uv 0.12.13:

```bash
uv sync --frozen
# Or, for tests and development tools:
uv sync --frozen --extra dev
uv pip check --python .venv/bin/python
```

The PostgreSQL driver is declared once as the Python 3.12-compatible `psycopg2-binary` runtime dependency. Do not install a second `psycopg2` variant imperatively.

Setuptools 80.9.0 is a runtime-only compatibility dependency because the legacy Flask-Security-Too 5.3.3/passlib stack imports `pkg_resources`. It is not a build backend: gateway builds remain isolated to the exact Flit backend declared under `[build-system]`.

`adsmutils` v2 is sourced from the upstream ADS repository through the commit-addressed archive `https://github.com/adsabs/ADSMicroserviceUtils/archive/8b20e6ea2cbea75bc3ccfa952bd9b5360bd82075.tar.gz`, the reviewed Python 3.12 source identity. `uv.lock` records and verifies the archive artifact hash, so synchronization does not require Git. The application factory prevents adsmutils from creating a second Flask-SQLAlchemy extension or reprocessing environment values through its legacy loader. Reviewers must verify any proposed commit and archive-hash change against upstream history; a branch or tag archive is not an acceptable replacement.

## Configuration

The application validates configuration before telemetry, extensions, or routes are initialized. A startup error lists invalid configuration key names in deterministic order; it never includes configured secret values. The same startup contract applies to the WSGI entry point, CLI, Alembic environment, migration helpers, and administrative scripts.

`apigateway/config.py` is the sole source of gateway defaults and environment parsing; explicit application-factory arguments take final precedence. The legacy `local_config.py` loading path is intentionally unsupported. Environment values are parsed without logging their names or values, so secrets are not exposed and comma-separated host and origin lists retain their configured types.

### Required secrets

The following settings have no tracked or runtime fallback:

- `SECRET_KEY`
- `SECURITY_SERVICE_SECRET_KEY`
- `SECURITY_SERVICE_VERIFY_PASSWORD_SALT`
- `SECURITY_SERVICE_VERIFY_EMAIL_SALT`
- `GOOGLE_RECAPTCHA_PRIVATE_KEY`

Each setting accepts either its direct environment variable or the corresponding `_FILE` variable (for example, `SECRET_KEY_FILE`), never both. Secret files are read with a 16 KiB limit. Exactly one terminal LF or CRLF written by secret-mount tooling is removed; all other bytes and whitespace are significant. Files must be readable when the process starts.

The Flask key, serializer key, password-token salt, and email-token salt must each contain at least 32 decoded bytes. Known placeholders are rejected, and the serializer key and two purpose salts must all be distinct. The reCAPTCHA secret must be nonempty and cannot be a placeholder.

`SECRET_KEY_ENCODING` is mandatory in meaning and defaults to the explicit `utf-8` mode:

- `utf-8`: `SECRET_KEY` must be text and its UTF-8 bytes are used;
- `hex`: `SECRET_KEY` must be valid hexadecimal text and its decoded bytes are used;
- `raw`: the value must already be bytes, normally supplied through `SECRET_KEY_FILE`.

There is no automatic hexadecimal detection. Deployments migrating a hexadecimal key must set `SECRET_KEY_ENCODING=hex` explicitly.

Generate independent random values for every signing setting. If any old public/default value was effective, rotate both Flask and SecurityService keys and both salts, invalidate all browser sessions, and purge or invalidate pending verification, email-change, and password-reset state. Rotation intentionally invalidates existing signed links and sessions.

### Hosts, browser policy, and TLS

`TRUSTED_HOSTS` is a comma-separated list of exact request authorities, with an explicit port where one is expected. Wildcards, suffix matching, URLs, userinfo, paths, malformed authorities, and unlisted hosts are rejected before route handlers execute.

`SITE_HOST_MAPPING` is a JSON object whose keys exactly match `TRUSTED_HOSTS` and whose values are `ADS` or `SCIX`, for example:

```text
TRUSTED_HOSTS=gateway.example.org,scix-gateway.example.org
SITE_HOST_MAPPING={"gateway.example.org":"ADS","scix-gateway.example.org":"SCIX"}
```

This mapping is the only source of ADS/SciX request-site selection. A hostname containing `scixplorer`, or ending in `shadow`, receives no special behavior.

`CORS_DOMAINS` is a comma-separated, nonempty list of exact HTTPS origins. HTTP origins, paths, credentials, query strings, and fragments are rejected. Credentialed CORS is enabled only for this list.

The secure defaults are:

```text
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_COOKIE_SAMESITE=Lax
HTTPS_ENFORCEMENT=true
TRUSTED_PROXY_HOPS=0
```

`SameSite=None` is accepted only with `SESSION_COOKIE_SECURE=true`. Talisman explicitly enforces HTTPS and HSTS. Direct production HTTP is not supported.

`HTTPS_ENFORCEMENT=false` is an explicit deployment option only when a TLS edge guarantees HTTPS to clients and the application listener is unreachable directly. It is never a public-HTTP mode. Tests may use it only through the factory escape described below.

When TLS terminates at a trusted reverse proxy, set `TRUSTED_PROXY_HOPS` to the exact number of trusted proxy hops. Only `X-Forwarded-Proto` is consumed; unrelated forwarded host, address, port, and prefix fields are not trusted. The edge must overwrite that header and the backend listener must not be publicly reachable. Leave `TRUSTED_PROXY_HOPS=0` when the application receives TLS directly.

### Test-only contract

Network bypasses are unavailable through normal runtime configuration. Tests that need them must call:

```python
create_app(
    TESTING=True,
    RECAPTCHA_TEST_BYPASS=True,
    MAIL_TEST_BYPASS=True,
    HTTPS_ENFORCEMENT=False,
    # Strong, distinct signing values and exact host/CORS settings are still required.
    allow_insecure_test_config=True,
)
```

`TESTING=True` alone never bypasses reCAPTCHA, mail, HTTPS, secret, host, or CORS validation. The factory-only argument is rejected without `TESTING=True`. Production code must configure a real reCAPTCHA secret.

## Running the application

Configure all required secrets, hosts, CORS origins, CAPTCHA, and transport settings before starting a local container environment:

```bash
docker compose up
```

The API is exposed at `http://localhost:5000`. The gateway container runs Gunicorn as numeric non-root user 10001 with root-owned application files, a read-only root filesystem, and no writable source bind mount. Compose provides a UID-compatible tmpfs only for `/app/logs`, where adsmutils writes runtime logs. Database migrations run before Gunicorn starts.

For local execution without Docker:

```bash
uv sync --frozen
uv run --frozen alembic upgrade head
uv run --frozen gunicorn --bind=127.0.0.1:8181 wsgi:application
```

`wsgi.py` exposes the production application object without enabling the Werkzeug reloader or debugger. Gunicorn 26.2.0 is the reviewed Python 3.12-compatible production server.

Choose Gunicorn worker and thread counts for the deployment's CPU and memory limits. Put the listener behind the configured TLS edge (or bind it directly with a TLS-capable server); the gateway must not be exposed as a public plaintext listener.

## Tests and CI

```bash
uv sync --frozen --extra dev
uv pip check --python .venv/bin/python
uv run --frozen --extra dev alembic upgrade head
uv run --frozen --extra dev pytest
```

The Python test workflow runs inside the same reviewed, digest-pinned Python 3.12.15 image as the application, on a fixed Ubuntu runner generation. Checkout and uv setup use immutable reviewed action commits, the uv 0.12.13 download is checksum-verified, repository permissions are read-only, and checkout credentials are disabled. CI performs only a frozen `uv.lock` synchronization. Coveralls receives a token only for a push to `adsabs/api_gateway`'s `main` branch; pull-request code never reaches that step.

The direct advisory upgrades include Flask-CORS 6.0.0, kafka-python 2.3.2, OpenTelemetry SDK/exporter 1.45.0 with instrumentation 0.66b0, pytest 9.0.3, and Black 26.3.1. CI and the container use uv instead of invoking vulnerable pip installation paths.

## Reproducible dependency lock

`uv.lock` is the reviewed Python 3.12 transitive dependency and artifact-hash lock. CI and the container reject stale metadata and do not resolve dependencies live. To regenerate it after an intentional `pyproject.toml` change, use uv 0.12.13 from a clean checkout:

```bash
uv lock --python 3.12.15
uv lock --check
uv sync --frozen --extra dev
uv pip check --python .venv/bin/python
```

Review the complete lock diff, all source URLs and artifact hashes, including the commit-addressed and hash-locked `adsmutils` archive, before committing a regenerated lock. Lock entries must never be handwritten or inferred.

The Python 3.12.15 slim-bookworm, uv 0.12.13, PostgreSQL 17.10 bookworm, and Redis 8.2.9 bookworm multi-architecture image manifests were resolved and reviewed in this PR. Docker, Compose, and CI pin the applicable images by digest. Deployment owners must retain those platform manifests and generate an image SBOM for each release.

## Reviewed dependency and email-domain policy updates

Dependabot opens monthly pull requests for direct Python dependencies and pinned GitHub Actions. Auto-merge is intentionally not configured: every update requires normal code review and CI. `disposable-email-domains` is isolated into its own update group because changing its data changes registration policy.

For every `disposable-email-domains` update, the pull-request description must record:

1. the old and new exact package versions and links to the PyPI release and upstream source/release;
2. the old and new total domain counts;
3. the exact added and removed counts (`new - old` and `old - new`), with the changed domain lists attached or linked;
4. explicit reviewer justification for every removed domain and a false-positive review of additions; and
5. results for accepted-domain, upstream-blocked-domain, case-normalization, and local-curated-denylist tests.

The package's exported `blocklist` is the upstream policy source. `apigateway/disallowed_email_domain_list.conf` is the ADS-maintained supplement; it is reviewed separately and must not be overwritten by an upstream refresh. Entries are normalized by trimming whitespace, removing a terminal dot, and applying lowercase before comparison. A policy pull request with unexplained count drift, missing provenance, or test regressions must not merge.

## Database versioning

Database versioning is managed using Alembic and uses the same fail-closed application configuration as the WSGI process. Configure all required secrets, hosts, CORS origins, CAPTCHA, and transport settings before invoking it:

```bash
alembic upgrade <revision>
alembic downgrade <revision>
alembic revision --autogenerate -m "revision description"
```

### Migration rollback compatibility

The `8e0d08daa203` OAuth schema migration validates data before replacing either
schema. Upgrade is blocked when legacy tokens have missing access tokens,
expiration timestamps, or client relationships. Downgrade is blocked when
current clients cannot satisfy the legacy required fields, metadata format, and
unique client ID constraints; when relationships cannot be mapped; or when
non-null refresh tokens are duplicated. Copy counts, relationships, and token
expiration are checked again before source tables are dropped. A failure rolls
back the Alembic transaction and reports only counts and a bounded sample of
database row IDs, never credential values.

Before rolling back across this revision, take a database backup and first
downgrade from the current head so the later index revisions are removed in
order. If validation fails:

1. Use the reported row IDs to review the affected rows without copying
   credentials into tickets or logs.
2. Repair the missing required values, invalid client metadata, duplicate
   client/refresh identifiers, or orphaned relationship in the still-current
   schema. Explicitly delete a row only under the deployment's data-retention
   procedure; the migration will not discard or invent credential data.
3. Rerun the same Alembic command. Do not manually drop the source tables.

The historical `26889be04d70` seed now has the migration-owned identity
`anonymous@ads`; rollback no longer reads the application's current bootstrap
configuration. Installations that originally applied that revision with a
custom bootstrap email have no stored ownership marker. Before crossing the
revision in reverse, identify the original seed from deployment records and
either rename that reviewed row to `anonymous@ads` before downgrade (after
resolving any collision), or leave it for reviewed manual deletion after
downgrade. The migration intentionally does not guess from current
configuration.

## Log and telemetry data contract

Application request logs are allowlisted to fixed outcome text plus the HTTP
method, the matched Flask route template, and (for failures) the exception
class. Unmatched requests use the literal route `<unmatched>`. Logs must not
contain concrete paths or query strings, request or response bodies, account
tokens, email addresses, cookies, authorization values, user-agent strings,
client IP addresses, or exception messages.

Exported HTTP spans follow the same boundary. Span names use
`METHOD <route-template>`; method, status, and route template remain available,
while URL, query, identity, and captured-header attributes are replaced before
export. Ingress proxies and WSGI access loggers operate outside this policy and
must also be configured not to record raw request targets, query strings, or
headers.

Alembic resolves the configured database URI without printing it. Operators
must rotate deployed database and API credentials that may have appeared in
historical startup, application, ingress, or CI logs. Restrict access to those
logs and expire retained copies according to the incident-response and
retention policies after rotation.
