import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.exceptions import BadRequest
from apigateway.config import (
    DEBUG,
    HTTPS_ENFORCEMENT,
    canonical_authority,
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
        "SECURITY_SERVICE_ACCOUNT_ACTION_TOKEN_EXPIRES": 24 * 60 * 60,
        "ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID": "current",
        "ACCESS_TOKEN_HMAC_KEYS": {
            "current": "oauth-access-token-key-32-bytes-minimum"
        },
        "BOOTSTRAP_TOKEN_EXPIRES": 24 * 60 * 60,
        "PERSONAL_TOKEN_EXPIRES": 30 * 24 * 60 * 60,
        "AUTH_SERVICE_DEFAULT_OWNER_QUOTA": 2.0,
        "ANONYMOUS_CREDENTIAL_DATABASE_CAP": 10000,
        "ANONYMOUS_ISSUANCE_SOURCE_LIMIT": "10/3600 second",
        "ANONYMOUS_ISSUANCE_GLOBAL_LIMIT": "1000/3600 second",
        "REDIS_SERVICE_URL": "redis://redis.example:6379/0",
        "LIMITER_SERVICE_STORAGE_URI": "rediss://redis.example:6379/1",
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

@pytest.mark.parametrize("expires", [True, 0, -1, "86400"])
def test_account_action_expiry_is_a_positive_integer(expires):
    config = valid_runtime_config(
        SECURITY_SERVICE_ACCOUNT_ACTION_TOKEN_EXPIRES=expires
    )
    assert_invalid(config, "SECURITY_SERVICE_ACCOUNT_ACTION_TOKEN_EXPIRES")


@pytest.mark.parametrize(
    "keys,active,invalid",
    [
        (None, None, ("ACCESS_TOKEN_HMAC_KEYS", "ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID")),
        ({}, "current", ("ACCESS_TOKEN_HMAC_KEYS", "ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID")),
        (
            {"current": "short"},
            "current",
            ("ACCESS_TOKEN_HMAC_KEYS", "ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID"),
        ),
        (
            {"bad id": "oauth-access-token-key-32-bytes-minimum"},
            "bad id",
            ("ACCESS_TOKEN_HMAC_KEYS", "ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID"),
        ),
        (
            {"current": "oauth-access-token-key-32-bytes-minimum"},
            "missing",
            ("ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID",),
        ),
    ],
)
def test_access_token_hmac_keyring_fails_closed(keys, active, invalid):
    config = valid_runtime_config(
        ACCESS_TOKEN_HMAC_KEYS=keys,
        ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID=active,
    )
    assert_invalid(config, *invalid)


@pytest.mark.parametrize(
    "key,value",
    [
        ("BOOTSTRAP_TOKEN_EXPIRES", 86401),
        ("PERSONAL_TOKEN_EXPIRES", 30 * 86400 + 1),
        ("ANONYMOUS_CREDENTIAL_DATABASE_CAP", 0),
        ("ANONYMOUS_ISSUANCE_SOURCE_LIMIT", "inf/second"),
        ("ANONYMOUS_ISSUANCE_GLOBAL_LIMIT", "0/1 second"),
    ],
)
def test_oauth_issuance_configuration_is_bounded(key, value):
    config = valid_runtime_config(**{key: value})
    assert_invalid(config, key)


@pytest.mark.parametrize(
    "collision_key",
    [
        "SECRET_KEY",
        "SECURITY_SERVICE_SECRET_KEY",
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT",
        "SECURITY_SERVICE_VERIFY_EMAIL_SALT",
    ],
)
def test_access_token_hmac_keys_cannot_reuse_other_signing_material(collision_key):
    config = valid_runtime_config()
    config["ACCESS_TOKEN_HMAC_KEYS"] = {"current": config[collision_key]}
    assert_invalid(config, "ACCESS_TOKEN_HMAC_KEYS")


@pytest.mark.parametrize(
    "key",
    ["REDIS_SERVICE_URL", "LIMITER_SERVICE_STORAGE_URI"],
)
@pytest.mark.parametrize("value", ["memory://", "http://redis.example", "", None])
def test_authoritative_redis_configuration_rejects_non_redis_backends(key, value):
    config = valid_runtime_config(**{key: value})
    assert_invalid(config, key)
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
            assert verify_recaptcha("response") is False
    post.assert_called_once()


def test_cookie_and_cors_runtime_policy(app, monkeypatch):
    monkeypatch.setitem(app.config, "SESSION_COOKIE_SECURE", True)
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
