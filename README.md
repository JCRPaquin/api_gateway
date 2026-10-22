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

## Public input and notification safety

The gateway enforces a 1 MiB global request limit. Account requests are limited
to 16 KiB and feedback requests to 256 KiB. Form parsing is limited to 64 KiB
of in-memory data and 32 parts. Oversized requests return JSON HTTP 413 before
CAPTCHA, database, diff, template, or notification work. JSON syntax errors,
decoder recursion exhaustion, and configured integer-digit-limit failures
return HTTP 400 before schema or CAPTCHA work, even when the byte body is below
its route limit. Feedback also has schema limits for nesting, collection sizes,
strings, records, rendered output, attachments, Slack payloads, and final MIME
size; adjust these only after reviewing the corresponding downstream work
bounds.

Registration, password-reset requests, and verification resends return HTTP 202
with the same account-independent message after a durable notification event is
accepted. Queue capacity or database failure returns the account-independent
HTTP 503 response `Notification service unavailable` with `Retry-After: 60`.
Disposable-domain policy entries and submitted domains are compared using
trimmed, trailing-dot-free lowercase IDNA ASCII.

New-account creation, its purpose-bound registration action, and the durable
verification delivery row are committed atomically. Verification resends are
deliberately two-stage: the account-independent request is committed first,
then a worker locks the eligible unconfirmed user, replaces that user's prior
registration action, and commits the requeued delivery. Password reset uses the
same two-stage pattern. Delivery events contain only the action's random stable
delivery ID and selected UI environment. A later claim locks and reloads that
exact committed action before deriving its signed bearer in memory.
Concurrent PostgreSQL registrations for the same previously absent canonical
email are resolved at the typed email unique constraint. The losing transaction
is rolled back before the committed winner is locked and reloaded, and the
loser queues the same durable registration-attempt notice as any other
existing-account request. Both callers receive the identical HTTP 202 response.
Only the typed email-constraint conflict is recovered; unrelated database or
outbox failures continue to return the generic HTTP 503 response.
Account-action rows contain only the bearer digest, target and state binding,
expiry, and delivery identity; active or terminal outbox JSON never contains a
bearer or bearer URL.

Apply migrations through the current head `7d1c4a9e2b31` and run one or more workers:

```bash
apigateway notifications work
```

Workers claim one row at a time with lease ownership and `FOR UPDATE SKIP
LOCKED` on PostgreSQL, retry transient failures up to
`MAIL_OUTBOX_MAX_ATTEMPTS`, and retain scrubbed terminal metadata for bounded
operator inspection. Generation and delivery are serialized per account, and
delivery holds the current action lock through SMTP acceptance.
Generation-specific dedupe IDs plus action replacement cause stale
registration, email-change, and password-reset delivery retries to be
suppressed rather than send a superseded link. A
crash after an action commit leaves its delivery event claimable; no SMTP call
has occurred. Delivery is **at least once**, not exactly once: a crash after
SMTP accepts a message but before the terminal-state commit may send the same
still-current committed action again after lease recovery. It can never send
an action superseded in the meantime.

Email-change initiation locks the authenticated user and commits the
target-bound action, verification delivery, and old-address notification in
one transaction. Registration verification and email change delivery derive
their bearers only from the committed exact action. Forced resets triggered
when a user logs in with a password that no longer meets policy use the same
account-action row and durable delivery event. Their action replacement and
outbox enqueue share the login transaction; account-action mail is never sent
directly by a request handler.

Password-reset generation, delivery, and redemption use the same
`User`-then-action lock order. The password mutation and deletion of the exact
action identified by the bearer share one transaction and one final commit. A
failure before that commit rolls both changes back. On PostgreSQL, a concurrent
replay waits on the user row and then fails when the consumed action is
revalidated; SQLite does not provide equivalent row-lock concurrency. A newer
generation is never
deleted by redemption, and delivery of a consumed or superseded action is
suppressed when its exact action row is absent.


Terminal rows contain neither message payloads nor dedupe keys. Run
`apigateway notifications cleanup` periodically to delete one bounded batch
beyond the configured sent/suppressed and dead retention windows. Active row
count and serialized payload bytes are both quota-controlled. Do not describe
an enqueued message as sent.

Mail delivery is enabled only with an authenticated TLS transport. Configure
`MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, and either
`MAIL_USE_STARTTLS` or `MAIL_USE_SSL`. Connect and SMTP command deadlines are
controlled by `MAIL_CONNECT_TIMEOUT_SECONDS` and
`MAIL_COMMAND_TIMEOUT_SECONDS`. Slack notifications also use the durable worker.
Slack destination, username, icon, timeout, and payload bound are server
configuration; feedback callers cannot override them, and caller text is sent
with markup disabled and Slack metacharacters escaped.

Adaptive rate-limit charging reserves one unit at admission and applies any
additional cost only after a successful handler completes. Rolling estimators
are isolated by the effective limiter identity and scope, expire after
`LIMITER_SERVICE_ESTIMATOR_TTL_SECONDS`, use only prior completed samples, and
clamp accounted work with `LIMITER_SERVICE_MAX_ACCOUNTED_SECONDS`. Total request
cost is capped by `LIMITER_SERVICE_MAX_COST`. Explicit `cost=` callbacks opt out
of adaptive charging.

## Account-action tokens and account verification

Registration verification, email changes, and password recovery use one-time,
purpose-bound account-action capabilities. Only a SHA-256 digest of each signed
token is stored. Every token is bound to its numeric subject, exact canonical
target email, purpose, current password hash, normalized current email, active
flag, and confirmation state. A later account-state change invalidates the
pending action. The default lifetime is 24 hours and can be changed with
`SECURITY_SERVICE_ACCOUNT_ACTION_TOKEN_EXPIRES` (seconds). Email copy does not
hard-code that default.

The password-recovery API accepts credentials only in JSON request bodies:

- `POST /accounts/user/reset-password` accepts `email` and
  `g-recaptcha-response`. Its success response is identical when an account is
  missing, unverified, or the anonymous bootstrap account.
- `POST /accounts/user/reset-password/verify` accepts `token` and performs a
  read-only validity check.
- `PUT /accounts/user/reset-password` accepts `token`, `password1`, and
  `password2`, then consumes the token.

Reset links put the bearer token in the UI URL fragment. The fragment is not
sent in an HTTP request target; the UI submits it to the gateway in a
CSRF-protected JSON request.

Registration and email-change verification use one body-only API resource:

- CSRF-protected `POST /accounts/verify` accepts JSON `{"token": "..."}` and
  performs read-only validity and flow inspection. It never confirms an
  account, changes an email, consumes an action, or changes the logged-in user.
- CSRF-protected `PUT /accounts/verify` accepts the same bounded JSON body,
  locks the subject and exact action, revalidates the target and account state,
  applies only the authorized registration confirmation or canonical email
  target, deletes that exact action, and commits once. Login occurs only after
  the commit.
- There is no GET verification credential route. The removed
  `/accounts/verify/<token>` path is not parsed and returns 404/405.
- `PUT /accounts/user/<email>/verify` is the separate, account-independent
  verification-resend resource. An email path value is never interpreted as a
  verification bearer.

Email links carry the bearer only in the UI fragment, which browsers do not
send in the HTTP request target. The UI must extract and remove the fragment,
then send the bearer in the JSON body of `POST /accounts/verify` for inspection
and `PUT /accounts/verify` only after explicit confirmation. API access and
exception logs therefore see only the constant `/accounts/verify` target; the
application does not log request bodies.

Deploying revision `d4c3b2a1908f` drops `email_change_request`, makes action
targets mandatory, and intentionally invalidates every registration and
email-change link from the generic legacy-token workflow. Users must request
new links. Downgrading recreates the legacy table empty and cannot restore old
links.

The former credential-bearing reset paths are removed. Deploying revision
`b8f2a6d41c73` drops the legacy `password_change_request` table, so all reset
links issued before the deployment are intentionally invalidated and users
must request new links. Downgrading recreates that table empty; it does not
restore old links.

Reset consumption locks the target user before its action row and commits the
OAuth token/client revocation, password hash, session-identifier rotation, and
account-action deletion together. A failed transaction preserves all five
pieces of prior state. On success, old browser sessions and bearer tokens are
both invalid.
SQLite tests cover transaction outcomes but do not prove row-lock or
unique-conflict serialization. Concurrent verification consumers and
same-address registration creators must run against PostgreSQL with independent
sessions.

Responses from reset, login, change-password, change-email, verification,
CSRF, bootstrap, and personal-token endpoints carry `Cache-Control: no-store`
and `Pragma: no-cache`, including error responses.

## OAuth credential issuance

OAuth credentials are issued only by the `AuthService` policy transaction. It
locks the explicit owner row, resolves defaults before checking the owner's
allowed scopes, applies quota and database-cap policy, rotates the client/token,
and commits or rolls back the complete operation. Owner quota `None` uses
`AUTH_SERVICE_DEFAULT_OWNER_QUOTA`, `0` suspends issuance, `-1` is unlimited,
and every other negative value is invalid. Client capacity is the maximum of
its positive finite base multiplier and all applicable per-route capacities.
Per-route keys are exact registered Flask endpoint names; regular expressions,
unknown endpoints, zero, negative, NaN, and infinity are rejected.

Credential-changing requests are CSRF-protected POSTs:

- `POST /accounts/bootstrap` creates or rotates a session-bound browser
  credential. Anonymous credentials use the configured bootstrap defaults,
  expire within 24 hours, are bound to a non-secret browser identifier, and
  are subject to per-source, global Redis, and finite database limits.
- `POST /accounts/user/token` creates or rotates the logged-in user's personal
  credential, with a maximum relative lifetime of 30 days.
- The corresponding GET endpoints return metadata only. They never return an
  access token or any other secret. Bearer-only requests cannot inspect or
  rotate browser or personal credentials.

Issuance responses return the raw access token once and carry
`Cache-Control: no-store` and `Pragma: no-cache`. No refresh token or client
secret is issued. The database stores only a version-1 HMAC-SHA-256 digest,
the digest version, and its key ID.

Configure `ACCESS_TOKEN_HMAC_KEYS` as a JSON object mapping stable key IDs to
independent random values of at least 32 bytes, and set
`ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID` to one key in that object. To rotate, deploy
the new key in the map first, make it active, allow the previous key only for
the longest remaining token lifetime, then remove it. Removing a prior key
immediately rejects credentials signed by it. Key material must not be reused
for Flask sessions, account actions, or any other signing purpose.

`PERSONAL_TOKEN_EXPIRES` defaults to 30 days and cannot exceed 30 days;
`BOOTSTRAP_TOKEN_EXPIRES` defaults to 24 hours and cannot exceed 24 hours.
`ANONYMOUS_CREDENTIAL_DATABASE_CAP`,
`ANONYMOUS_ISSUANCE_SOURCE_LIMIT`, and
`ANONYMOUS_ISSUANCE_GLOBAL_LIMIT` must all be finite positive settings.

The operator generator uses the same transaction and requires an explicit
output channel. `--output -` writes only the raw token to stdout; a path creates
a new mode-0600 file containing only that token. It cannot create users or
bypass scope, quota, route, or expiry policy.

Deploy in this order: configure the complete HMAC key ring on application and
operator jobs; stop old issuers; give the migration job only its dedicated
PostgreSQL URI; upgrade Alembic through `e5f6a7b8c9d0` to the single head
`7d1c4a9e2b31`; then start the new application. The OAuth migration
intentionally deletes every legacy plaintext access token, drops
refresh-token/client-secret storage, deletes unbound legacy anonymous clients,
and clears legacy route multiplier maps that may contain regular expressions.
Users and operators must issue new credentials. Downgrade does not recreate or
recover secrets.

Anonymous issuance admission is authoritative in Redis: one Lua operation
increments the source and global fixed-window counters together. A limit
exhaustion returns HTTP 429; any Redis failure returns HTTP 503 and never falls
back to process-local counters. Production `REDIS_SERVICE_URL` and
`LIMITER_SERVICE_STORAGE_URI` must use `redis://` or `rediss://`.

The gateway rejects query parameters named `access_token`, `token`,
`refresh_token`, or `client_secret`, case-insensitively, before proxy
forwarding. Proxy and Gunicorn access logs record endpoint/path information
without complete URLs or query strings.

Alembic reads only the dedicated, validated PostgreSQL
`SQLALCHEMY_DATABASE_URI`; migration jobs do not initialize the Flask
application or require its unrelated signing and mail configuration. The OAuth
migration downgrade first deletes keyed token digests, then restores nullable
legacy compatibility columns empty so older schema downgrades can run without
recreating credential values.

## Operational cleanup and recoverable operator delivery

Bearer authentication persists a throttled UTC `last_activity` update before the
protected request runs. `OAUTH2_ACTIVITY_WRITE_INTERVAL` controls the write
interval and defaults to five minutes. Revision `7d1c4a9e2b31` backfills active
clients at deployment, so client cleanup must not start until that revision and
the activity-recording code are both deployed.

Cleanup commands require interactive confirmation unless `--yes` is supplied.
Use the same selection arguments with `--dry-run` before unattended deletion:

```bash
apigateway cleanup clients --timedelta days=90 --ratelimit 1 --dry-run
apigateway cleanup clients --timedelta days=90 --ratelimit 1 --yes
apigateway cleanup users --timedelta hours=24 --yes
apigateway cleanup tokens --yes
```

Retention accepts one positive finite unit/value pair such as `hours=24` or
`days=90`; client rate-limit thresholds must be finite and nonnegative. Cleanup
selects at most 1,000 IDs per transaction and rechecks every predicate during
deletion. Expired-token cleanup deletes child rows only and leaves
pending-delivery rows for explicit recovery. Client cleanup preserves clients
with active or pending credentials. Stale-user cleanup does not delete the
anonymous bootstrap owner or any user that still owns OAuth clients.

`scripts/generate_oauth_client.py` continues to use the centralized issuance
policy. `--user-email` must be an email address; it is canonicalized and
resolved to exactly one existing user before the immutable owner identifier is
passed to issuance. A `fs_uniquifier` is not accepted as email input.
`--output -` writes only the newly issued raw bearer to stdout. A file path
creates a mode-`0600` file containing only the raw bearer; stdout then contains
non-secret delivery status. The database stores only the keyed HMAC digest and
safe delivery metadata, never the raw bearer, refresh tokens, or client secrets.

For file delivery, the generator serializes each normalized destination with a
non-secret, mode-`0600` `.oauth-lock-*` entry, then writes and fsyncs a
same-directory pending file before the issuance transaction commits. The
committed token is marked pending with its normalized destination path.
Publication uses an atomic hard link, verifies the inode, mode, ownership, link
count, and digest, fsyncs the directory, and only then clears pending state.
Rerunning the same canonical-owner request recovers a crash after commit or
publication, including a successful issuance commit whose acknowledgement was
lost. Once a pending raw file has been durably prepared, any issuance error
retains that file. If a later authoritative query finds the matching pending
row, the retry completes delivery. If no row is visible, the retry fails closed
and leaves the file untouched because an unresolved backend transaction may
still commit. Manual remediation may remove the pending file only after
verifying both that no matching digest or pending row exists and that no
backend transaction can still commit. Pre-prepare failures create no durable
pending bearer. A different request, path, conflicting content, symlink,
nonregular file, unsafe mode, or extra link also fails closed.
