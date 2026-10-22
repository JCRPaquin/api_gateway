import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[2]
COMPOSE_FILE = ROOT / "docker-compose.yaml"
DEPLOYMENT = ROOT / "deployment"
ALEMBIC_ENV = ROOT / "migrations" / "env.py"


def _compose_model():
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker Compose is not installed")
    available = subprocess.run(
        [docker, "compose", "version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if available.returncode != 0:
        pytest.skip("Docker Compose is not available")

    environment = os.environ.copy()
    environment.update(
        {
            "TRUSTED_HOSTS": "gateway.example.org",
            "SITE_HOST_MAPPING": '{"gateway.example.org":"ADS"}',
            "CORS_DOMAINS": "https://ui.example.org",
        }
    )
    rendered = subprocess.run(
        [docker, "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        cwd=str(ROOT),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert rendered.returncode == 0, rendered.stderr
    return json.loads(rendered.stdout)


def _secret_sources(service):
    sources = set()
    for secret in service.get("secrets", []):
        if isinstance(secret, str):
            sources.add(secret)
        else:
            sources.add(secret["source"])
    return sources


def test_compose_source_contains_no_state_credential_or_uri_literals():
    source = COMPOSE_FILE.read_text()
    lowered = source.lower()

    assert "postgresql://" not in lowered
    assert "redis://" not in lowered
    assert "POSTGRES_PASSWORD:" not in source
    assert "DATABASE_PASSWORD:" not in source
    assert "REDIS_PASSWORD:" not in source
    assert "password: password" not in lowered
    assert "alembic upgrade" not in source
    assert "5000:8181" not in source
    assert "5432:5432" not in source
    assert "6379:6379" not in source


def test_state_scripts_enforce_authentication_grants_and_bounded_retry():
    redis_entrypoint = (DEPLOYMENT / "redis-entrypoint.sh").read_text()
    redis_healthcheck = (DEPLOYMENT / "redis-healthcheck.sh").read_text()
    database_init = (DEPLOYMENT / "init-runtime-role.sh").read_text()
    migrations = (DEPLOYMENT / "run-migrations.sh").read_text()

    assert "user default off" in redis_entrypoint
    assert "--aclfile" in redis_entrypoint
    assert "redis_password" not in redis_entrypoint.split("exec redis-server", 1)[1]
    assert "redis-cli -h 127.0.0.1 ping" in redis_healthcheck
    assert "REDISCLI_AUTH" in redis_healthcheck
    assert "--user" in redis_healthcheck

    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE" in database_init
    assert "GRANT CONNECT ON DATABASE" in database_init
    assert "GRANT USAGE ON SCHEMA public" in database_init
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I" in database_init
    assert "GRANT USAGE, SELECT, UPDATE ON SEQUENCE %I.%I" in database_init
    assert "ALTER DEFAULT PRIVILEGES" in database_init
    assert "GRANT CREATE" not in database_init
    assert "export GATEWAY_" not in database_init
    assert "--set=runtime_password" not in database_init
    assert "REVOKE ALL PRIVILEGES ON %s %I.%I" in database_init
    assert "REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I" in database_init
    assert "REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s)" in database_init
    assert "runtime_privilege_outside_managed_schema" in database_init
    assert "ALTER TABLE %I.%I OWNER TO %I" in database_init
    assert "ALTER DATABASE %I OWNER TO %I" in database_init
    assert "unsafe_role_attributes" in database_init
    assert "unsafe_managed_acl" in database_init
    assert "unsafe_default_acl" in database_init
    assert "ALTER ROLE %I RESET ALL" in database_init
    assert "rolconfig IS NULL" in database_init
    assert "pg_db_role_setting" in database_init

    assert "max_attempts=" in migrations
    assert "attempt" in migrations
    assert "delay" in migrations
    assert "alembic upgrade head" in migrations


def test_retained_roles_settings_and_acls_are_reduced_before_allowlisted_grants():
    database_init = (DEPLOYMENT / "init-runtime-role.sh").read_text()
    outside_check = database_init.index("runtime_privilege_outside_managed_schema")
    membership_revoke = database_init.index(
        "REVOKE %I FROM %I GRANTED BY %I CASCADE"
    )
    database_revoke = database_init.index(
        "REVOKE ALL PRIVILEGES ON DATABASE %I FROM %s"
    )
    relation_revoke = database_init.index(
        "REVOKE ALL PRIVILEGES ON %s %I.%I FROM %s"
    )
    relation_grant = database_init.index(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I"
    )
    revoke_defaults = database_init.index(
        "REVOKE ALL PRIVILEGES ON %s FROM %s"
    )
    grant_defaults = database_init.index(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I"
    )

    assert membership_revoke < outside_check < database_revoke
    assert database_revoke < relation_revoke < relation_grant
    assert revoke_defaults < grant_defaults


def test_role_memberships_and_database_settings_cover_retained_cluster_state():
    database_init = (DEPLOYMENT / "init-runtime-role.sh").read_text()

    assert "membership.roleid" in database_init
    assert "membership.member" in database_init
    assert "membership.grantor" in database_init
    assert (
        "granted.rolname IN (:'bootstrap_user', :'owner_user', :'runtime_user')"
        in database_init
    )
    assert (
        "member.rolname IN (:'bootstrap_user', :'owner_user', :'runtime_user')"
        in database_init
    )
    assert "ALTER ROLE %I IN DATABASE %I RESET ALL" in database_init
    assert "settings.setrole IN (owner.oid, runtime.oid)" in database_init
    assert (
        "membership.roleid IN (bootstrap.oid, owner.oid, runtime.oid)"
        in database_init
    )
    assert (
        "membership.member IN (bootstrap.oid, owner.oid, runtime.oid)"
        in database_init
    )


def test_parameter_privileges_and_runtime_extension_ownership_are_rejected():
    database_init = (DEPLOYMENT / "init-runtime-role.sh").read_text()
    extension_check = database_init.index("runtime_owned_extension")
    parameter_revoke = database_init.index(
        "REVOKE ALL PRIVILEGES ON PARAMETER %I FROM %s CASCADE"
    )
    ownership_transfer = database_init.index("ALTER DATABASE %I OWNER TO %I")
    final_ownership_start = database_init.index(
        "SELECT FROM pg_database database JOIN pg_roles role "
        "ON role.oid = database.datdba"
    )
    final_ownership_end = database_init.index("AS runtime_is_privileged")
    final_ownership_check = database_init[
        final_ownership_start:final_ownership_end
    ]
    assert extension_check < parameter_revoke < ownership_transfer
    assert "pg_parameter_acl parameter_acl" in database_init
    assert "aclexplode(parameter_acl.paracl)" in database_init
    assert "privilege.grantee = 0" in database_init
    assert "THEN 'PUBLIC'" in database_init
    assert "privilege.privilege_type IN ('SET', 'ALTER SYSTEM')" in database_init
    assert "unsafe_parameter_acl" in database_init
    assert "pg_extension ext" in database_init
    assert "untrusted_extension_owner" in database_init
    assert "owner.rolname NOT IN (:'bootstrap_user', :'owner_user')" in database_init
    assert "owner.oid = ext.extowner" in database_init
    assert "pg_proc routine" in final_ownership_check
    assert "routine.proowner" in final_ownership_check
    assert "pg_type managed_type" in final_ownership_check
    assert "managed_type.typowner" in final_ownership_check
    assert "pg_extension ext" in final_ownership_check
    assert "ext.extowner" in final_ownership_check


def test_managed_acl_cleanup_covers_columns_public_and_all_retained_routines():
    database_init = (DEPLOYMENT / "init-runtime-role.sh").read_text()
    routine_revoke = database_init.index(
        "REVOKE ALL PRIVILEGES ON ROUTINE %I.%I(%s)"
    )
    routine_cleanup_end = database_init.index("\\gexec", routine_revoke)
    routine_cleanup = database_init[routine_revoke:routine_cleanup_end]

    assert "attribute.attacl" in database_init
    assert "privilege.grantee = 0" in database_init
    assert "THEN 'PUBLIC'" in database_init
    assert "GRANTED BY %I CASCADE" in database_init
    assert "REVOKE ALL PRIVILEGES ON DATABASE %I FROM %s" in database_init
    assert "REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %s" in database_init
    assert "FROM pg_proc routine" in routine_cleanup
    assert "routine.proacl" in routine_cleanup
    assert "prosecdef" not in routine_cleanup
    assert "dependency.classid = 'pg_proc'::regclass" in routine_cleanup
    assert (
        "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
        in database_init
    )
    assert "(:'owner_user'), (:'bootstrap_user')" in database_init
    assert "privilege.privilege_type = 'EXECUTE'" in database_init


def test_rendered_compose_is_private_and_dependency_ordered():
    model = _compose_model()
    services = model["services"]

    publishing = {name for name, service in services.items() if service.get("ports")}
    assert publishing == {"tls-edge"}
    assert {str(port["published"]) for port in services["tls-edge"]["ports"]} == {"443"}

    assert set(services["db"]["networks"]) == {"backend"}
    assert set(services["redis"]["networks"]) == {"backend"}
    assert set(services["migrate"]["networks"]) == {"backend"}
    assert set(services["apigateway"]["networks"]) == {"frontend", "backend"}
    assert set(services["tls-edge"]["networks"]) == {"frontend"}
    assert model["networks"]["backend"]["internal"] is True

    api_dependencies = services["apigateway"]["depends_on"]
    assert api_dependencies["db"]["condition"] == "service_healthy"
    assert api_dependencies["redis"]["condition"] == "service_healthy"
    assert api_dependencies["migrate"]["condition"] == "service_completed_successfully"
    assert services["redis"]["healthcheck"]["test"] == [
        "CMD",
        "/usr/local/bin/gateway-redis-healthcheck.sh",
    ]
    assert "pg_isready" in " ".join(services["db"]["healthcheck"]["test"])
    assert services["migrate"]["depends_on"]["db"]["condition"] == "service_healthy"
    assert "redis" not in services["migrate"]["depends_on"]

    api_command = " ".join(services["apigateway"]["command"])
    assert "gunicorn" in api_command
    assert "alembic" not in api_command
    assert services["migrate"]["command"] == ["/app/deployment/run-migrations.sh"]


def test_rendered_compose_uses_only_external_secret_mounts():
    model = _compose_model()
    services = model["services"]

    assert model["secrets"]
    assert all(secret.get("external") is True for secret in model["secrets"].values())
    assert {
        "postgres_runtime_user",
        "postgres_runtime_password",
        "redis_username",
        "redis_password",
    }.issubset(_secret_sources(services["apigateway"]))
    assert {
        "postgres_owner_user",
        "postgres_owner_password",
    }.issubset(_secret_sources(services["migrate"]))
    assert _secret_sources(services["migrate"]) == {
        "postgres_owner_user",
        "postgres_owner_password",
    }
    assert {
        "postgres_bootstrap_user",
        "postgres_bootstrap_password",
        "postgres_owner_user",
        "postgres_owner_password",
        "postgres_runtime_user",
        "postgres_runtime_password",
    }.issubset(_secret_sources(services["db"]))
    assert services["db"]["environment"]["POSTGRES_USER_FILE"].endswith(
        "/postgres_bootstrap_user"
    )
    assert services["db"]["environment"]["POSTGRES_PASSWORD_FILE"].endswith(
        "/postgres_bootstrap_password"
    )
    assert services["migrate"]["environment"]["DATABASE_USER_FILE"].endswith(
        "/postgres_owner_user"
    )
    assert services["migrate"]["environment"]["DATABASE_PASSWORD_FILE"].endswith(
        "/postgres_owner_password"
    )
    assert "postgres_bootstrap_user" not in _secret_sources(services["migrate"])
    assert "postgres_bootstrap_password" not in _secret_sources(services["migrate"])
    assert "postgres_bootstrap_user" not in _secret_sources(services["apigateway"])
    assert "postgres_bootstrap_password" not in _secret_sources(services["apigateway"])
    assert "redis_username" not in _secret_sources(services["migrate"])
    assert "gateway_flask_key" not in _secret_sources(services["migrate"])
    for service_name in ("apigateway", "migrate", "db", "redis"):
        environment = services[service_name].get("environment", {})
        assert "DATABASE_PASSWORD" not in environment
        assert "POSTGRES_PASSWORD" not in environment
        assert "REDIS_PASSWORD" not in environment

    assert {"redis_username", "redis_password"}.issubset(
        _secret_sources(services["redis"])
    )

    for service in services.values():
        command = service.get("command", [])
        command_text = command if isinstance(command, str) else " ".join(command)
        assert "postgres_owner_password" not in command_text
        assert "postgres_runtime_password" not in command_text
        assert "redis_password" not in command_text


def test_alembic_uses_database_only_loader_without_logging_secrets():
    source = ALEMBIC_ENV.read_text()

    assert "load_migration_database_url" in source
    assert "create_app" not in source
    assert "print(" not in source


def test_redis_entrypoint_keeps_password_out_of_server_arguments(tmp_path):
    secret_dir = tmp_path / "secrets"
    runtime_dir = tmp_path / "runtime"
    binary_dir = tmp_path / "bin"
    secret_dir.mkdir()
    runtime_dir.mkdir()
    binary_dir.mkdir()
    password = "redis_test_password_32_characters"
    (secret_dir / "redis_username").write_text("gateway_test")
    (secret_dir / "redis_password").write_text(password)
    arguments_file = tmp_path / "redis-arguments"
    fake_server = binary_dir / "redis-server"
    fake_server.write_text(
        '#!/bin/sh\nprintf "%s\\\\n" "$@" >"$REDIS_ARGUMENTS_OUTPUT"\n'
    )
    fake_server.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "GATEWAY_SECRET_DIR": str(secret_dir),
            "GATEWAY_RUNTIME_DIR": str(runtime_dir),
            "REDIS_ARGUMENTS_OUTPUT": str(arguments_file),
            "PATH": "{}:{}".format(binary_dir, environment["PATH"]),
        }
    )

    completed = subprocess.run(
        [str(DEPLOYMENT / "redis-entrypoint.sh")],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    arguments = arguments_file.read_text()
    assert password not in arguments
    assert "--aclfile" in arguments
    acl_file = runtime_dir / "gateway-redis.acl"
    assert stat.S_IMODE(acl_file.stat().st_mode) == 0o600
    acl = acl_file.read_text()
    assert "user default off" in acl
    tokens = set(acl.split())
    assert {
        "-@all",
        "~gateway:storage:v1:*",
        "~gateway:cache:v1:*",
        "~LIMITS:*",
        "+ping",
        "+select",
        "+get",
        "+set",
        "+del",
        "+exists",
        "+incr",
        "+expire",
        "+evalsha",
        "+script|load",
    }.issubset(tokens)
    assert {
        "+@all",
        "~*",
        "+flushdb",
        "+flushall",
        "+acl",
        "+config",
        "+monitor",
        "+save",
        "+bgsave",
        "+client",
        "+publish",
        "+subscribe",
        "+eval",
        "+script|flush",
        "+script|kill",
    }.isdisjoint(tokens)


@pytest.mark.parametrize(
    "succeed_on,expected_returncode",
    [(3, 0), (99, 1)],
)
def test_migration_retry_is_bounded(tmp_path, succeed_on, expected_returncode):
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    attempts_file = tmp_path / "attempts"
    fake_alembic = binary_dir / "alembic"
    fake_alembic.write_text(
        """#!/bin/sh
count=0
if [ -f "$MIGRATION_ATTEMPTS_FILE" ]; then
    count=$(cat "$MIGRATION_ATTEMPTS_FILE")
fi
count=$((count + 1))
printf '%s' "$count" >"$MIGRATION_ATTEMPTS_FILE"
[ "$count" -ge "$MIGRATION_SUCCEED_ON" ]
"""
    )
    fake_alembic.chmod(0o755)
    fake_sleep = binary_dir / "sleep"
    fake_sleep.write_text("#!/bin/sh\nexit 0\n")
    fake_sleep.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "MIGRATION_ATTEMPTS_FILE": str(attempts_file),
            "MIGRATION_MAX_ATTEMPTS": "3",
            "MIGRATION_SUCCEED_ON": str(succeed_on),
            "PATH": "{}:{}".format(binary_dir, environment["PATH"]),
        }
    )

    completed = subprocess.run(
        [str(DEPLOYMENT / "run-migrations.sh")],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert completed.returncode == expected_returncode
    assert attempts_file.read_text() == "3"
