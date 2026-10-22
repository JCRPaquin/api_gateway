import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import request
from sqlalchemy.engine import make_url
from werkzeug.exceptions import BadRequest

from apigateway import config as gateway_config
from apigateway.config import (
    DEBUG,
    HTTPS_ENFORCEMENT,
    canonical_authority,
    canonical_service_host,
    load_migration_database_url,
    validate_runtime_config,
)
from apigateway.exceptions import ConfigurationError
from apigateway.utils import get_request_site, verify_recaptcha


def valid_runtime_config(**overrides):
    config = {
        "TESTING": False,
        "SECRET_KEY": "flask-production-signing-key-32-bytes-minimum",
        "SECRET_KEY_FILE": None,
        "SECRET_KEY_ENCODING": "utf-8",
        "SECURITY_SERVICE_SECRET_KEY": "serializer-production-key-32-bytes-minimum",
        "SECURITY_SERVICE_SECRET_KEY_FILE": None,
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT": (
            "password-production-purpose-salt-32-bytes-minimum"
        ),
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT_FILE": None,
        "SECURITY_SERVICE_VERIFY_EMAIL_SALT": (
            "email-production-purpose-salt-32-bytes-minimum"
        ),
        "SECURITY_SERVICE_VERIFY_EMAIL_SALT_FILE": None,
        "GOOGLE_RECAPTCHA_PRIVATE_KEY": "real-recaptcha-private-key",
        "GOOGLE_RECAPTCHA_PRIVATE_KEY_FILE": None,
        "RECAPTCHA_TEST_BYPASS": False,
        "MAIL_TEST_BYPASS": False,
        "TRUSTED_HOSTS": ["gateway.example"],
        "SITE_HOST_MAPPING": {"gateway.example": "ADS"},
        "CORS_DOMAINS": ["https://ui.example"],
        "SESSION_COOKIE_SECURE": True,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "HTTPS_ENFORCEMENT": True,
        "TRUSTED_PROXY_HOPS": 0,
        "SQLALCHEMY_DATABASE_URI": None,
        "DATABASE_HOST": "db.internal",
        "DATABASE_PORT": 5432,
        "DATABASE_NAME": "gateway",
        "DATABASE_USER": "gateway_runtime",
        "DATABASE_USER_FILE": None,
        "DATABASE_PASSWORD": "database-production-password-32-bytes",
        "DATABASE_PASSWORD_FILE": None,
        "REDIS_HOST": "redis.internal",
        "REDIS_PORT": 6379,
        "REDIS_USER": "gateway",
        "REDIS_USER_FILE": None,
        "REDIS_PASSWORD": "redis-production-password-32-bytes",
        "REDIS_PASSWORD_FILE": None,
        "REDIS_SERVICE_URL": None,
        "LIMITER_SERVICE_STORAGE_URI": None,
        "CACHE_SERVICE_REDIS_URI": None,
    }
    config.update(overrides)
    return config


def assert_invalid(config, *keys, allow_insecure_test_config=False):
    with pytest.raises(ConfigurationError) as error:
        validate_runtime_config(
            config,
            allow_insecure_test_config=allow_insecure_test_config,
        )
    for key in keys:
        assert key in error.value.invalid_keys
    assert list(error.value.invalid_keys) == sorted(set(error.value.invalid_keys))
    return str(error.value)


@pytest.mark.parametrize(
    "key",
    [
        "SECRET_KEY",
        "SECURITY_SERVICE_SECRET_KEY",
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT",
        "SECURITY_SERVICE_VERIFY_EMAIL_SALT",
        "GOOGLE_RECAPTCHA_PRIVATE_KEY",
    ],
)
def test_required_secrets_have_no_shipped_fallback(key):
    config = valid_runtime_config()
    secret_value = config[key]
    config[key] = None
    message = assert_invalid(config, key)
    assert secret_value not in message


def test_direct_and_file_secret_are_mutually_exclusive(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("f" * 40)
    config = valid_runtime_config(SECRET_KEY_FILE=str(secret_file))
    assert_invalid(config, "SECRET_KEY", "SECRET_KEY_FILE")


def test_secret_file_is_bounded(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_bytes(b"f" * (16 * 1024 + 1))
    config = valid_runtime_config(SECRET_KEY=None, SECRET_KEY_FILE=str(secret_file))
    assert_invalid(config, "SECRET_KEY_FILE")


def test_secret_file_removes_only_one_terminal_newline(tmp_path):
    secret_file = tmp_path / "serializer"
    secret_file.write_bytes((b"f" * 40) + b"\n\n")
    config = valid_runtime_config(
        SECURITY_SERVICE_SECRET_KEY=None,
        SECURITY_SERVICE_SECRET_KEY_FILE=str(secret_file),
    )
    validate_runtime_config(config)
    assert config["SECURITY_SERVICE_SECRET_KEY"] == ("f" * 40) + "\n"


def test_state_credentials_are_read_from_secret_files(tmp_path):
    database_user = tmp_path / "database-user"
    database_password = tmp_path / "database-password"
    redis_user = tmp_path / "redis-user"
    redis_password = tmp_path / "redis-password"
    database_user.write_text("runtime_role\n")
    database_password.write_text("database/file-password:@-32-bytes\n")
    redis_user.write_text("gateway_app\n")
    redis_password.write_text("redis-file-password-32-bytes\n")
    config = valid_runtime_config(
        DATABASE_USER=None,
        DATABASE_USER_FILE=str(database_user),
        DATABASE_PASSWORD=None,
        DATABASE_PASSWORD_FILE=str(database_password),
        REDIS_USER=None,
        REDIS_USER_FILE=str(redis_user),
        REDIS_PASSWORD=None,
        REDIS_PASSWORD_FILE=str(redis_password),
    )

    validate_runtime_config(config)

    database_url = make_url(config["SQLALCHEMY_DATABASE_URI"])
    redis_url = make_url(config["REDIS_SERVICE_URL"])
    assert database_url.username == "runtime_role"
    assert database_url.password == "database/file-password:@-32-bytes"
    assert redis_url.username == "gateway_app"
    assert redis_url.password == "redis-file-password-32-bytes"


def test_state_direct_and_file_credentials_are_mutually_exclusive(tmp_path):
    password_file = tmp_path / "database-password"
    password_file.write_text("database-file-password-32-bytes")
    config = valid_runtime_config(DATABASE_PASSWORD_FILE=str(password_file))

    assert_invalid(config, "DATABASE_PASSWORD", "DATABASE_PASSWORD_FILE")


def test_state_urls_percent_encode_credentials():
    database_user = "runtime/user"
    database_password = "database:@/ percent?#-password-32-bytes"
    redis_user = "gateway/user"
    redis_password = "redis:@/ percent?#-password-32-bytes"
    config = valid_runtime_config(
        DATABASE_USER=database_user,
        DATABASE_PASSWORD=database_password,
        REDIS_USER=redis_user,
        REDIS_PASSWORD=redis_password,
    )

    validate_runtime_config(config)

    database_url = config["SQLALCHEMY_DATABASE_URI"]
    redis_url = config["REDIS_SERVICE_URL"]
    assert make_url(database_url).username == database_user
    assert make_url(database_url).password == database_password
    assert make_url(redis_url).username == redis_user
    assert make_url(redis_url).password == redis_password
    assert database_password not in database_url
    assert redis_password not in redis_url


def test_redis_storage_and_limiter_use_db_zero_and_cache_uses_db_one():
    config = valid_runtime_config()
    validate_runtime_config(config)

    assert make_url(config["REDIS_SERVICE_URL"]).database == "0"
    assert make_url(config["LIMITER_SERVICE_STORAGE_URI"]).database == "0"
    assert make_url(config["CACHE_SERVICE_REDIS_URI"]).database == "1"
    assert config["REDIS_SERVICE_URL"] == config["LIMITER_SERVICE_STORAGE_URI"]


@pytest.mark.parametrize(
    "key",
    ["DATABASE_USER", "DATABASE_PASSWORD", "REDIS_USER", "REDIS_PASSWORD"],
)
def test_missing_state_credentials_fail_closed(key):
    config = valid_runtime_config(**{key: None})
    assert_invalid(config, key)


@pytest.mark.parametrize("key", ["DATABASE_PASSWORD", "REDIS_PASSWORD"])
def test_known_state_password_fallbacks_are_rejected(key):
    config = valid_runtime_config(**{key: "password"})
    message = assert_invalid(config, key)
    assert message == "Invalid application configuration: {}".format(key)


def test_preassembled_state_urls_are_production_invalid():
    config = valid_runtime_config(
        SQLALCHEMY_DATABASE_URI="postgresql://known:known@db/gateway",
        REDIS_SERVICE_URL="redis://known:known@redis/0",
        LIMITER_SERVICE_STORAGE_URI="redis://known:known@redis/0",
        CACHE_SERVICE_REDIS_URI="redis://known:known@redis/1",
    )
    message = assert_invalid(
        config,
        "SQLALCHEMY_DATABASE_URI",
        "REDIS_SERVICE_URL",
        "LIMITER_SERVICE_STORAGE_URI",
        "CACHE_SERVICE_REDIS_URI",
    )
    assert "known" not in message


def test_no_state_service_uri_has_a_shipped_credential_fallback():
    assert gateway_config.SQLALCHEMY_DATABASE_URI is None
    assert gateway_config.REDIS_SERVICE_URL is None
    assert gateway_config.LIMITER_SERVICE_STORAGE_URI is None
    assert gateway_config.CACHE_SERVICE_REDIS_URI is None


@pytest.mark.parametrize(
    "value,encoding,expected_key",
    [
        ("not-hex", "hex", "SECRET_KEY"),
        (b"f" * 40, "utf-8", "SECRET_KEY"),
        ("f" * 40, "raw", "SECRET_KEY"),
        ("f" * 40, "base64", "SECRET_KEY_ENCODING"),
        ("short", "utf-8", "SECRET_KEY"),
    ],
)
def test_secret_key_encoding_is_explicit_and_type_safe(value, encoding, expected_key):
    config = valid_runtime_config(SECRET_KEY=value, SECRET_KEY_ENCODING=encoding)
    message = assert_invalid(config, expected_key)
    assert "not-hex" not in message


def test_utf8_hex_looking_secret_is_not_heuristically_decoded():
    value = "ab" * 32
    config = valid_runtime_config(SECRET_KEY=value, SECRET_KEY_ENCODING="utf-8")
    validate_runtime_config(config)
    assert config["SECRET_KEY"] == value.encode("utf-8")


def test_explicit_hex_secret_is_decoded():
    value = "ab" * 32
    config = valid_runtime_config(SECRET_KEY=value, SECRET_KEY_ENCODING="hex")
    validate_runtime_config(config)
    assert config["SECRET_KEY"] == bytes.fromhex(value)


def test_serializer_key_and_purpose_salts_must_be_distinct():
    repeated = "repeated-purpose-secret-material-32-bytes"
    config = valid_runtime_config(
        SECURITY_SERVICE_SECRET_KEY=repeated,
        SECURITY_SERVICE_VERIFY_PASSWORD_SALT=repeated,
    )
    message = assert_invalid(
        config,
        "SECURITY_SERVICE_SECRET_KEY",
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT",
    )
    assert "SECURITY_SERVICE_VERIFY_EMAIL_SALT" not in message
    assert repeated not in message


def test_public_defaults_cannot_start_the_application():
    config = valid_runtime_config(
        SECRET_KEY="736563726574",
        SECURITY_SERVICE_SECRET_KEY="secret",
        SECURITY_SERVICE_VERIFY_PASSWORD_SALT="secret",
        SECURITY_SERVICE_VERIFY_EMAIL_SALT="secret",
        GOOGLE_RECAPTCHA_PRIVATE_KEY="MY_PRIVATE_KEY",
    )
    message = assert_invalid(
        config,
        "SECRET_KEY",
        "SECURITY_SERVICE_SECRET_KEY",
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT",
        "SECURITY_SERVICE_VERIFY_EMAIL_SALT",
        "GOOGLE_RECAPTCHA_PRIVATE_KEY",
    )
    assert "736563726574" not in message
    assert "MY_PRIVATE_KEY" not in message


def test_debug_defaults_off():
    assert DEBUG is False


def test_testing_alone_does_not_enable_recaptcha_bypass():
    config = valid_runtime_config(
        TESTING=True,
        GOOGLE_RECAPTCHA_PRIVATE_KEY=None,
        RECAPTCHA_TEST_BYPASS=True,
    )
    assert_invalid(
        config,
        "GOOGLE_RECAPTCHA_PRIVATE_KEY",
        "RECAPTCHA_TEST_BYPASS",
    )


def test_factory_test_escape_requires_testing_and_explicit_bypass():
    config = valid_runtime_config(
        TESTING=True,
        GOOGLE_RECAPTCHA_PRIVATE_KEY=None,
        RECAPTCHA_TEST_BYPASS=True,
        MAIL_TEST_BYPASS=True,
        HTTPS_ENFORCEMENT=False,
    )
    validate_runtime_config(config, allow_insecure_test_config=True)


@pytest.mark.parametrize(
    "host",
    [
        "",
        "https://gateway.example",
        "user@gateway.example",
        "gateway.example/path",
        "gateway.example,attacker.example",
        "gateway.example.",
        "gateway.example:",
    ],
)
def test_malformed_authorities_are_rejected(host):
    with pytest.raises(ValueError):
        canonical_authority(host)


@pytest.mark.parametrize(
    "configured,expected",
    [
        ("db.internal", "db.internal"),
        ("127.0.0.1", "127.0.0.1"),
        ("[2001:db8::1]", "2001:db8::1"),
    ],
)
def test_service_hosts_are_canonical(configured, expected):
    assert canonical_service_host(configured) == expected


@pytest.mark.parametrize(
    "configured",
    [
        "user@db.internal",
        "db.internal/path",
        "db.internal?query",
        "db.internal#fragment",
        "db%2einternal",
        "2001:db8::1",
        "[2001:0db8::1]",
        "[fe80::1%eth0]",
        "[2001:db8::1",
        "2001:db8::1]",
        "DB.internal",
        "db.internal.",
        "127.00.0.1",
    ],
)
def test_service_hosts_reject_authority_confusion(configured):
    with pytest.raises(ValueError):
        canonical_service_host(configured)


@pytest.mark.parametrize("key", ["DATABASE_HOST", "REDIS_HOST"])
def test_runtime_config_rejects_noncanonical_state_hosts(key):
    config = valid_runtime_config(**{key: "user@state.internal/path"})
    assert_invalid(config, key)


def test_migration_loader_reads_only_structured_database_secrets(tmp_path, capsys):
    owner_user = tmp_path / "owner-user"
    owner_password = tmp_path / "owner-password"
    owner_user.write_text("gateway_owner\n")
    owner_password.write_text("owner-file-password-32-bytes\n")
    environment = {
        "DATABASE_HOST": "[2001:db8::1]",
        "DATABASE_PORT": "5432",
        "DATABASE_NAME": "gateway",
        "DATABASE_USER_FILE": str(owner_user),
        "DATABASE_PASSWORD_FILE": str(owner_password),
    }

    url = load_migration_database_url(environment)

    parsed = make_url(url)
    assert parsed.host == "2001:db8::1"
    assert parsed.username == "gateway_owner"
    assert parsed.password == "owner-file-password-32-bytes"
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_site_mapping_must_exactly_cover_trusted_hosts():
    config = valid_runtime_config(
        TRUSTED_HOSTS=["gateway.example"],
        SITE_HOST_MAPPING={"gateway.example.attacker": "ADS"},
    )
    assert_invalid(config, "SITE_HOST_MAPPING")


def test_cors_origins_must_be_https():
    config = valid_runtime_config(CORS_DOMAINS=["http://ui.example"])
    assert_invalid(config, "CORS_DOMAINS")


def test_samesite_none_requires_secure_cookie():
    config = valid_runtime_config(
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_SECURE=False,
    )
    assert_invalid(config, "SESSION_COOKIE_SAMESITE", "SESSION_COOKIE_SECURE")


def test_https_enforcement_defaults_on_and_is_explicitly_configurable():
    assert HTTPS_ENFORCEMENT is True
    validate_runtime_config(valid_runtime_config(HTTPS_ENFORCEMENT=False))


def test_testing_cannot_disable_https_without_factory_escape():
    config = valid_runtime_config(TESTING=True, HTTPS_ENFORCEMENT=False)
    assert_invalid(config, "HTTPS_ENFORCEMENT")


@pytest.mark.parametrize("hops", [True, -1, "1"])
def test_trusted_proxy_hops_are_explicit_nonnegative_integers(hops):
    config = valid_runtime_config(TRUSTED_PROXY_HOPS=hops)
    assert_invalid(config, "TRUSTED_PROXY_HOPS")


def test_attacker_shadow_host_is_rejected_before_route(app):
    response = app.test_client().get(
        "/accounts/status",
        base_url="https://attacker-shadow",
        headers={"Host": "attacker-shadow"},
    )
    assert response.status_code == 400


def test_suffix_confusion_cannot_select_scix(app):
    with app.test_request_context(headers={"Host": "scixplorer.org.attacker"}):
        with pytest.raises(BadRequest):
            get_request_site()


def test_testing_without_explicit_bypass_calls_recaptcha(app, monkeypatch):
    monkeypatch.setitem(app.config, "RECAPTCHA_TEST_BYPASS", False)
    failed_response = MagicMock()
    failed_response.json.return_value = {"success": False}
    with patch("apigateway.utils.requests.post", return_value=failed_response) as post:
        with app.test_request_context(
            json={"g-recaptcha-response": "response"},
            headers={"Host": "attacker-shadow"},
        ):
            assert verify_recaptcha(request) is False
    post.assert_called_once()


def test_cookie_and_cors_runtime_policy(app):
    client = app.test_client()
    response = client.get(
        "/not-found",
        base_url="https://localhost",
        headers={"Host": "localhost", "Origin": "https://ui.adsabs.harvard.edu"},
    )
    cookie = response.headers.get("Set-Cookie", "")
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert response.headers.get("Access-Control-Allow-Origin") == (
        "https://ui.adsabs.harvard.edu"
    )

    response = client.get(
        "/not-found",
        base_url="https://localhost",
        headers={"Host": "localhost", "Origin": "http://ui.adsabs.harvard.edu"},
    )
    assert "Access-Control-Allow-Origin" not in response.headers


def test_wsgi_has_no_executable_development_server():
    source = Path(__file__).parents[2].joinpath("wsgi.py").read_text()
    tree = ast.parse(source)
    assert "run_simple" not in source
    assert not any(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and "__main__" in ast.dump(node.test)
        for node in ast.walk(tree)
    )
