[![Coverage Status](https://coveralls.io/repos/github/adsabs/api_gateway/badge.svg?branch=main)](https://coveralls.io/github/adsabs/api_gateway?branch=main)

# api_gateway

SciX API Gateway, the core API module for SciX.

## Supported toolchain

The gateway supports CPython 3.12 only (`>=3.12,<3.13`); CI and the container use Python 3.12.15. Flit is the sole package build backend, with its exact backend version declared in `pyproject.toml`; `setup.py`, wheel, and ppsetuptools are not gateway build paths.

## Secure discovery, proxy, cache, and mail boundaries

Proxy discovery is disabled by default. `PROXY_SERVICE_WEBSERVICES` is now a
mapping of service names to records; the former `{url: deploy_path}` format and
the former backend-controlled resource properties are intentionally
incompatible. A deployment record must contain an HTTPS `base_url`, canonical
`deploy_path`, purpose-specific `discovery_hmac_key`, and local `policy`.
Discovery documents have the fixed schema
`{"version": 1, "routes": [{"path": "/route", "methods": ["GET"]}]}`.
Authorization, scopes, methods, CSRF handling, rate limits, and cache
eligibility are always bounded by local policy and cannot be supplied by
discovery. Registration rejects collisions with static or dynamic local
routes, including the implicit `HEAD` method provided by every `GET` route.

The discovery signer sends `X-Discovery-Timestamp` and
`X-Discovery-Signature: v1=<hex HMAC-SHA256>`, where the signed bytes are
`<timestamp> + "\\n" + <exact response body>`. Rotate this key with a
coordinated signer and gateway configuration rollout; it must not be reused for
sessions or any other purpose. `discovery_cache: true` explicitly permits
startup fallback, but the cached body, timestamp, and signature are verified
again and become unusable after
`PROXY_SERVICE_DISCOVERY_MAX_AGE_SECONDS`. Redirected, stale, oversized,
unsigned, malformed, or non-HTTPS discovery fails application startup.

Proxy origins use HTTPS certificate and hostname verification. Configure
`PROXY_SERVICE_TLS_CA_BUNDLE` (or a per-service `tls_ca_bundle`) with the
internal CA file when system trust is insufficient. Client certificate and key
settings must be provided together. The proxy has separate connect/read
inactivity timeouts plus one monotonic whole-response deadline. A request-local
transport wrapper recomputes the remaining time before every socket receive,
including proxy `CONNECT`, upstream status/header parsing, HTTP chunk framing,
and body reads; pooled connections receive a fresh deadline before reuse.
The transport adapter depends on Requests adapter integration and urllib3's
private connection and pool extension APIs. `requests==2.34.2` and
`urllib3==2.8.0` are therefore direct, exact dependencies and form the tested
pair; update them together only after rerunning the deadline transport tests.
Request/wire/decoded byte ceilings, header count/byte ceilings, and explicit
request/response header allowlists also apply. It accepts compressed
responses only when the complete gzip or deflate representation is valid;
concatenated gzip members share one decoded-byte ceiling. It never forwards
browser cookies, authorization, caller Host, forwarding fields, proxy
authorization, or hop-by-hop headers, and it never follows upstream redirects.

Only locally declared unauthenticated public `GET` routes may be cached, with a
TTL of 1–300 seconds and finite local grammars. `query_parameters` maps each
permitted name to its exact finite value set; query names are single-valued,
count/length bounded, and repeated, unknown, undeclared, or noncanonical raw
query encodings bypass the cache. `representation_headers` declares exact,
case-preserving values for every forwarded representation header (an empty
value list permits only absence). Requests whose `Connection` field would
remove a keyed header also bypass the cache. Arbitrary language, media-type,
and content-type variants therefore bypass both reads and writes. Credentials,
identity, bodies, ranges, request `no-cache`/`no-store`, unsupported cache
directives, and zero `max-age` also bypass caching.

Partial, streaming, private, `no-store`, `no-cache`, expired, zero-age,
`Set-Cookie`, and unsupported `Vary` responses are not stored. Corrected
initial age includes origin response delay as well as origin `Age` and `Date`;
`s-maxage`, `max-age`, and `Expires` bound freshness. Cache hits sample time
after retrieval, recompute current age, enforce request `max-age` and
`min-fresh`, and emit an updated `Age`. Objects above
`PROXY_SERVICE_MAX_CACHE_OBJECT_BYTES` remain bounded streams and are not
cached. Keys contain only exact canonical query pairs and exact finite
representation dimensions, plus service, method, path, and route generation.
Cache invalidation accepts only a route key (or `*`).

Production must use a Redis instance dedicated to this public response cache,
with an operator-selected finite `maxmemory` and eviction policy. Redis DB
numbers do not provide memory isolation. The repository Compose Redis is a
shared development dependency and is not a production cache topology.

Every proxy `deploy_path` must be a non-root, single-segment top-level prefix.
Before registration, each concrete discovered path and method is resolved
through Werkzeug's bound application matcher; any existing static or converter
match is rejected.

SMTP is disabled until `MAIL_SERVER` is set. When enabled it requires
`MAIL_SECURITY` to be `implicit_tls` or `starttls`, validates the server through
the system trust store or `MAIL_TLS_CA_FILE`, applies `MAIL_TIMEOUT_SECONDS`,
and requires `MAIL_USERNAME` and `MAIL_PASSWORD`. There is no plaintext or
unauthenticated downgrade. Provision discovery keys, CA files, proxy policy,
and SMTP credentials before deploying this release.

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
