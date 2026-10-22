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

`adsmutils` v2 is sourced from the upstream ADS repository through the commit-addressed archive `https://github.com/adsabs/ADSMicroserviceUtils/archive/8b20e6ea2cbea75bc3ccfa952bd9b5360bd82075.tar.gz`, the reviewed Python 3.12 source identity. `uv.lock` records and verifies the archive artifact hash, so synchronization does not require Git. The application factory preserves file, environment, and explicit configuration precedence while preventing adsmutils from creating a second Flask-SQLAlchemy extension. Reviewers must verify any proposed commit and archive-hash change against upstream history; a branch or tag archive is not an acceptable replacement.

## Running the application

For a local container environment:

```bash
docker compose up
```

The API is exposed at `http://localhost:5000`. The gateway container runs Gunicorn as numeric non-root user 10001 with root-owned application files, a read-only root filesystem, and no writable source bind mount. Compose provides a UID-compatible tmpfs only for `/app/apigateway/logs`, where adsmutils writes runtime logs. Database migrations run before Gunicorn starts.

For local execution without Docker:

```bash
uv sync --frozen
uv run --frozen alembic upgrade head
uv run --frozen gunicorn --bind=127.0.0.1:8181 wsgi:application
```

`wsgi.py` exposes the production application object without enabling the Werkzeug reloader or debugger. Gunicorn 26.2.0 is the reviewed Python 3.12-compatible production server.

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

Database versioning is managed using Alembic:

```bash
alembic upgrade <revision>
alembic downgrade <revision>
alembic revision --autogenerate -m "revision description"
```
