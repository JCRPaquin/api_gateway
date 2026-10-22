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

### State-service credentials

Production database configuration is structured: `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, `DATABASE_USER` or `DATABASE_USER_FILE`, and `DATABASE_PASSWORD` or `DATABASE_PASSWORD_FILE`. Redis likewise uses `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER` or `REDIS_USER_FILE`, and `REDIS_PASSWORD` or `REDIS_PASSWORD_FILE`. User and password values have no fallback, direct and file forms are mutually exclusive, and missing, short, or known placeholder passwords stop startup. Preassembled `SQLALCHEMY_DATABASE_URI`, `REDIS_SERVICE_URL`, `LIMITER_SERVICE_STORAGE_URI`, and `CACHE_SERVICE_REDIS_URI` values are rejected outside the explicit test-only factory escape.

The application builds percent-safe URLs with SQLAlchemy's URL API. Storage and the limiter share authenticated Redis database 0; cache data uses authenticated database 1. In the shipped Compose deployment, only `_FILE` forms are used and every credential comes from an external secret mount.
State-service hosts must be canonical lowercase DNS names, canonical IPv4 literals, or canonical compressed IPv6 literals enclosed in brackets. Userinfo, authority delimiters, paths, queries, fragments, percent encoding, IPv6 zone identifiers, noncanonical addresses, and malformed brackets fail startup.


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

Choose worker and thread counts for the deployment's CPU and memory limits. Put the listener behind a configured TLS edge. `wsgi.py` cannot launch Werkzeug's development server or reloader.

### Compose deployment prerequisites
This topology is stacked on three security changes which **must land before it is deployed**:

1. `security/01-safe-observability`, which removes the complete database URI from Alembic output. Assume any database password used by an older migration was logged; rotate it and review or purge retained logs before starting this stack.
2. `security/redis-json-codec`, which removes executable Redis deserialization and cuts storage and cache over to versioned namespaces. Follow that change's namespace cleanup procedure; never make an old pickle-reading release share Redis with this deployment.
3. `security/ops-migration-integrity`, which removes the historical `create_app()` call from revision `26889be04d70`. A fresh-volume migration cannot remain database-only until that revision is configuration-independent.

The Compose file deliberately has no local secret files or secret-valued environment variables. Its secrets are all declared `external: true`; the deployment platform must provision them before `docker compose up`:

| External secret | Contents |
| --- | --- |
| `postgres_bootstrap_user` | PostgreSQL initialization/cutover administrator; mounted only by `db` |
| `postgres_bootstrap_password` | Bootstrap administrator password |
| `postgres_owner_user` | Dedicated database owner/migration role name |
| `postgres_owner_password` | Owner/migration password |
| `postgres_runtime_user` | Distinct non-owner web role name |
| `postgres_runtime_password` | Runtime role password |
| `redis_username` | Named Redis ACL user |
| `redis_password` | Redis ACL password |
| `gateway_flask_key` | Flask signing key |
| `gateway_security_key` | Serializer signing key |
| `gateway_password_salt` | Password-token purpose salt |
| `gateway_email_salt` | Email-token purpose salt |
| `gateway_recaptcha_key` | Production reCAPTCHA secret |
| `gateway_tls_certificate` | CA-issued full certificate chain in PEM form |
| `gateway_tls_private_key` | Matching TLS private key in PEM form |

Generate every password, key, and salt independently in a protected operator environment. Database/Redis role names and their passwords must contain only letters, digits, underscores, and hyphens; passwords should be at least 32 random characters. Hexadecimal output from `openssl rand -hex 32` meets that contract. Pipe generated values directly into the platform secret manager, for example `openssl rand -hex 32 | docker secret create <name> -` on a platform that supplies Docker external secrets. Do not write values under the checkout, put them in `.env`, pass them in a Compose command, or paste them into shell history. Obtain the reCAPTCHA secret and TLS materials from their respective providers; the repository intentionally contains no development certificate or fallback secret.

The nonsecret request policy remains deployment-specific and is required when rendering Compose:

```bash
export TRUSTED_HOSTS=gateway.example.org
export SITE_HOST_MAPPING='{"gateway.example.org":"ADS"}'
export CORS_DOMAINS=https://ui.example.org
```

The TLS edge is the only service with a host publication (`443`). It overwrites `X-Forwarded-Proto`, while the gateway has no host port and trusts exactly that one proxy hop. PostgreSQL and Redis are attached only to the `internal: true` backend network and have no host ports. Do not add host publications for troubleshooting; use an authenticated, audited administrative container on the backend network.

### First database volume and startup

For a new, empty `./data/db` directory, the PostgreSQL image creates a bootstrap administrator from its external secrets and runs `deployment/init-runtime-role.sh`. The script creates distinct owner/migration and runtime logins, transfers database and managed-schema ownership to the non-superuser migration owner, and normalizes both roles to `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`. It removes every membership edge to or from the bootstrap, owner, and runtime roles, including PostgreSQL 17 grants recorded under other grantors, and clears the owner/runtime global and per-database role settings. PostgreSQL 17 parameter `SET` and `ALTER SYSTEM` grants are reduced to an empty cluster-wide allowlist, including grants to `PUBLIC` or unrelated roles. Managed database, `public` schema, relation, column, routine, and type ACLs are rebuilt so only the owner and the runtime allowlist remain. The runtime receives database `CONNECT`, schema `USAGE`, table DML, sequence access, and matching owner default privileges; `PUBLIC` and unrelated roles receive none of those managed privileges. Owner and bootstrap default privileges also deny `PUBLIC` execution of future routines. The bootstrap credential is never mounted into the migration or gateway service.

Start the stack only after all external secrets and the three nonsecret policy variables are available:

```bash
docker compose up -d
docker compose ps
```

PostgreSQL and the authenticated Redis ACL must become healthy before the database-only migration service starts. Migration loads only the structured owner database settings; it does not create the Flask application, mount Redis/signing/CAPTCHA secrets, or depend on Redis. Connection failures use a fixed six-attempt capped exponential backoff and the one-shot service has a bounded `on-failure:3` restart. The long-lived gateway starts only after that service exits successfully. Its command executes Gunicorn directly and never invokes Alembic.

### Existing-volume role cutover

`POSTGRES_USER_FILE`, `POSTGRES_PASSWORD_FILE`, and `/docker-entrypoint-initdb.d` are used automatically only when PostgreSQL initializes an empty volume. Changing those secrets does not modify an existing role or grant on an existing `./data/db`.

For retained data:

1. Take and validate a database backup, stop the old web processes, and record the current administrative/database-owner identity through a trusted connection. Provision that identity as the bootstrap secret for the cutover; it is not an application or migration credential.
2. Provision distinct owner/migration and runtime role secrets. Recreate the `db` container so it mounts the current external secrets, then run `docker compose exec db /docker-entrypoint-initdb.d/010-runtime-role.sh`.
3. The script creates or corrects both non-superuser roles; removes memberships both to and from the bootstrap, owner, and runtime roles; resets every owner/runtime role setting, including database-specific settings; and removes all entries from the PostgreSQL 17 parameter-privilege allowlist. It rejects a runtime-owned extension so an administrator must transfer or drop that extension before rerunning, and accepts other installed extensions only when the configured bootstrap or migration role owns them. It then transfers all non-extension database and managed-`public` ownership to the migration owner, verifies every managed object has that owner, and verifies the runtime owns no database, schema, relation, routine, type, or extension anywhere in the connected database. Extension members remain under their trusted non-runtime bootstrap or migration extension owner. The script fails rather than modifying any direct runtime grant or default ACL outside `public`; inspect and remove such grants through the trusted administrator before rerunning.
4. For the managed database and schema, the script first removes retained database, schema, relation, column, routine, type, and owner/bootstrap default ACLs from `PUBLIC`, runtime, and unrelated roles. This includes `PUBLIC` or direct execution grants on retained `SECURITY DEFINER` routines. It then reapplies only runtime `CONNECT`, `public` schema `USAGE`, managed table DML, managed sequence access, and matching owner defaults. Global owner/bootstrap defaults revoke `PUBLIC` execution on future routines. Run `docker compose run --rm migrate` and inspect its nonsecret completion status.
5. Start the gateway only after migration succeeds. Disable login for any superseded legacy identity after verifying it owns no objects and no client uses it. Confirm that neither state service has a host publication.

Never point the gateway at the owner secret as a temporary cutover shortcut. If the existing volume cannot meet the ownership checks, stop and repair ownership with the trusted administrator rather than broadening the runtime grants. Disposable development data may instead be stopped, backed up if needed, removed explicitly by the operator, and recreated as a first volume; deployment scripts never delete it.

### Health, rotation, firewall, and rollback

The Redis healthcheck first requires an unauthenticated `PING` to fail and then requires an authenticated `PONG` from the named ACL user. Its ACL can address only `gateway:storage:v1:*`, `gateway:cache:v1:*`, and `LIMITS:*`, and permits only the storage/cache/limiter commands documented by the `security/redis-json-codec` prerequisite. Administrative commands, flushes, monitor, persistence controls, client management, pub/sub, arbitrary `EVAL`, and script management other than required `SCRIPT LOAD` are unavailable. The PostgreSQL healthcheck gates migration on server readiness. After startup, verify the public status endpoint through the real certificate, for example `curl https://gateway.example.org/v1/accounts/status`, and confirm that `docker compose exec redis redis-cli ping` returns `NOAUTH`. Inspect database role attributes, both directions of role membership, `pg_db_role_setting`, `pg_parameter_acl`, extension ownership, all routine/type ownership, relation and column ACLs, routine ACLs, and default ACLs through a trusted administrative session. The parameter ACL must contain no `SET` or `ALTER SYSTEM` grant. The runtime role must not own objects, create schema objects, create databases or roles, own/manage/drop extensions, inherit or `SET ROLE` to another role, be reachable through another role's membership, execute managed routines, or retain privileges outside `public`; `PUBLIC` must not retain managed database/schema privileges or execute managed routines.

Host and cloud firewalls should admit only TCP 443 from intended clients. Deny public and host-LAN access to 8181, 5432, and 6379 in addition to relying on the absence of Compose publications. Administrative access belongs on a restricted management path, not a temporary state-service port.

Rotate one credential class at a time:

- **Bootstrap database:** use this credential only through the isolated `db` initialization/cutover path. Update its external secret, recreate only `db`, run the cutover script through the local trusted connection, then remove any superseded administrator login after ownership verification. Neither migration nor gateway receives this secret.
- **Runtime database:** quiesce gateway traffic, update the external runtime password, rerun the database initialization/grant script through the trusted local connection, recreate the gateway container, and verify DML plus denied DDL before resuming traffic.
- **Owner database:** update the owner secret, run the initialization script through the bootstrap-only local connection to apply it, recreate the migration service, and verify an Alembic status command emits no URI. The gateway does not receive this secret.
- **Redis:** stop gateway traffic, replace the external ACL password, recreate Redis and the gateway, and verify both the negative unauthenticated and positive authenticated health checks. Treat Redis data as disposable according to the JSON-codec namespace runbook.
- **Signing, CAPTCHA, and TLS:** update the corresponding external secret and recreate only its consumers. Signing-key rotation invalidates the state described under Required secrets.

For rollback, stop the gateway first, run any reviewed schema downgrade with the owner-only migration service, and then deploy the prior compatible application while retaining private networks and authentication. Do not roll back to in-process web migrations, a published plaintext gateway, an unauthenticated Redis instance, an owner-powered web process, or a release that reads legacy pickle data. If credentials may have reached earlier Alembic logs, rotate them again; reverting code cannot retract a disclosed value.

## Development

CPython 3.12 and uv 0.12.13 are required. For local execution without Docker, install the locked runtime environment and configure the required database settings before invoking Alembic or Gunicorn:

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

The Python 3.12.15 slim-bookworm, uv 0.12.13, PostgreSQL 17.10 bookworm, Redis 8.2.9 bookworm, and Nginx 1.27 Alpine multi-architecture image manifests were resolved and reviewed in this PR. Docker, Compose, and CI pin the applicable images by digest. Deployment owners must retain those platform manifests and generate an image SBOM for each release.

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

Alembic uses a database-only, fail-closed loader for `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_NAME`, and owner `DATABASE_USER[_FILE]`/`DATABASE_PASSWORD[_FILE]`. It does not create the Flask application or require Redis, signing, CAPTCHA, host, CORS, or transport configuration, and it emits no URI or secret.

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
### Redis serialization rollout and rollback

Gateway-owned Redis data uses isolated namespaces. Storage data in DB 0 is written under
`gateway:storage:v1:` and response cache data in DB 1 is written under
`gateway:cache:v1:`. Values outside these namespaces, including values written by older
pickle-based releases, are never deserialized or migrated.

Use the following rollout order:

1. Confirm that every configured resource-document endpoint is reachable; resource
   documents and adaptive timing data are disposable and will be repopulated.
2. Deploy the new release to every gateway instance, then drain and stop all old
   instances.
3. Remove old gateway storage keys from DB 0 using `SCAN` to identify the old key
   pattern and `UNLINK` to delete keys. Delete by key name only; never `GET`, copy, or
   otherwise read an old value. Do not flush DB 0 because Flask-Limiter shares it.
4. After all old instances have drained, flush DB 1 only. DB 1 is dedicated to
   disposable response-cache data.

Never dual-read or deserialize legacy pickle values. A rollback to a pickle-reading
release is prohibited unless both DB 0 gateway-owned storage keys and all of DB 1 have
first been cleaned, and Redis has been isolated and authenticated. Prefer rolling
forward with the new namespaces; a cold cache and reset adaptive timing state are the
expected deployment impact.
