import json
import os
import re
from os import environ
from urllib.parse import urlsplit

from apigateway.exceptions import ConfigurationError


def _environment_list(name):
    value = environ.get(name)
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]

def _environment_bool(name, default):
    value = environ.get(name)
    if value is None:
        return default
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


def _environment_int(name, default):
    value = environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return value


def _environment_mapping(name):
    value = environ.get(name)
    if value is None:
        return None
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        # Runtime validation reports the key consistently with all other errors.
        return value


# General
DEBUG = False

# Public request bounds
MAX_CONTENT_LENGTH = 1_048_576
ACCOUNT_MAX_REQUEST_BYTES = 16_384
FEEDBACK_MAX_REQUEST_BYTES = 262_144
MAX_FORM_MEMORY_SIZE = 65_536
MAX_FORM_PARTS = 32


# Mail
MAIL_ENABLED = True
MAIL_DEFAULT_SENDER = "no-reply@adslabs.org"
MAIL_SERVER = "localhost"
MAIL_PORT = 25
MAIL_CONNECT_TIMEOUT_SECONDS = 5
MAIL_COMMAND_TIMEOUT_SECONDS = 10
MAIL_MAX_MESSAGE_BYTES = 1_048_576
MAIL_USE_SSL = False
MAIL_USE_STARTTLS = True
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_OUTBOX_MAX_PENDING = 10_000
MAIL_OUTBOX_CLAIM_BATCH = 50
MAIL_OUTBOX_POLL_SECONDS = 1
MAIL_OUTBOX_MAX_ATTEMPTS = 5
MAIL_OUTBOX_RETRY_DELAYS_SECONDS = [60, 300, 1_800, 7_200]
MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES = 33_554_432
MAIL_OUTBOX_LEASE_SECONDS = 120
MAIL_OUTBOX_TERMINAL_RETENTION_SECONDS = 604_800
MAIL_OUTBOX_DEAD_RETENTION_SECONDS = 86_400
MAIL_OUTBOX_CLEANUP_BATCH = 1_000
VERIFY_URL = "https://ui.adsabs.harvard.edu/#user/account/verify"
SCIX_VERIFY_URL = "https://scixplorer.org/#user/account/verify"
SCIX_HOST_DOMAIN = "https://scixplorer.org"
ADS_HOST_DOMAIN = "https://ui.adsabs.harvard.edu"
BLOCK_DISPOSABLE_EMAIL_DOMAINS = True
# Feedback
FEEDBACK_FORMS_ORIGIN = "user_submission"
BBB_FEEDBACK_ORIGIN = "bbb_feedback"
FEEDBACK_ALLOWED_ORIGINS = [FEEDBACK_FORMS_ORIGIN, BBB_FEEDBACK_ORIGIN]

FEEDBACK_TEMPLATES = {
    "Missing References": {"file": "missing_references.txt"},
    "Associated Articles": {"file": "associated_articles.txt"},
    "Updated Record": {"file": "updated_record.txt", "update": True},
    "New Record": {"file": "new_record.txt", "new": True},
    "Bumblebee Feedback": {"file": "bumblebee_feedback.txt"},
}


FEEDBACK_EMAIL = "adshelp@cfa.harvard.edu"
FEEDBACK_EMAIL_SUBJECT_OVERRIDE = {
    "Missing References": "adsabs@cfa.harvard.edu",
}

FEEDBACK_SLACK_END_POINT = "https://hooks.slack.com/services/TOKEN/TOKEN"
FEEDBACK_SLACK_CHANNEL = "#feedback"
FEEDBACK_SLACK_USERNAME = "TownCrier"
FEEDBACK_SLACK_EMOJI = ":interrobang:"
FORM_SLACK_EMOJI = ":inbox_tray:"
FEEDBACK_SLACK_TIMEOUT_SECONDS = 5
FEEDBACK_SLACK_MAX_PAYLOAD_BYTES = 65_536

# CORS
CORS_HEADERS = [
    "Content-Type",
    "X-BB-Api-Client-Version",
    "Authorization",
    "Accept",
]

CORS_DOMAINS = _environment_list("CORS_DOMAINS")

CORS_METHODS = ["GET", "OPTIONS", "POST"]


# Logging
LOGGING_LEVEL = "DEBUG"
LOG_STDOUT = False

# Database
SQLALCHEMY_DATABASE_URI = "postgresql://user:password@db:5432/gateway"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = environ.get("SECRET_KEY")
SECRET_KEY_FILE = environ.get("SECRET_KEY_FILE")
SECRET_KEY_ENCODING = environ.get("SECRET_KEY_ENCODING", "utf-8")

# Auth
OAUTH2_CLIENT_ID_SALT_LEN = 40
OAUTH2_CLIENT_SECRET_SALT_LEN = 40
GOOGLE_RECAPTCHA_ENDPOINT = "https://www.google.com/recaptcha/api/siteverify"
GOOGLE_RECAPTCHA_PRIVATE_KEY = environ.get("GOOGLE_RECAPTCHA_PRIVATE_KEY")
GOOGLE_RECAPTCHA_PRIVATE_KEY_FILE = environ.get("GOOGLE_RECAPTCHA_PRIVATE_KEY_FILE")
RECAPTCHA_TEST_BYPASS = False
MAIL_TEST_BYPASS = False

# Session and browser transport policy
PERMANENT_SESSION_LIFETIME = 3600 * 24 * 365.25  # 1 year in seconds
SESSION_REFRESH_EACH_REQUEST = True
ANONYMOUS_BOOTSTRAP_USER_EMAIL = "anonymous@ads"
BOOTSTRAP_CLIENT_NAME = "BB client"
SESSION_COOKIE_PATH = "/v1"
SESSION_COOKIE_SECURE = _environment_bool("SESSION_COOKIE_SECURE", True)
SESSION_COOKIE_HTTPONLY = _environment_bool("SESSION_COOKIE_HTTPONLY", True)
SESSION_COOKIE_SAMESITE = environ.get("SESSION_COOKIE_SAMESITE", "Lax")
PREFERRED_URL_SCHEME = "https"
HTTPS_ENFORCEMENT = _environment_bool("HTTPS_ENFORCEMENT", True)
TRUSTED_PROXY_HOPS = _environment_int("TRUSTED_PROXY_HOPS", 0)

# Request authority and ADS/SciX site selection
TRUSTED_HOSTS = _environment_list("TRUSTED_HOSTS")
SITE_HOST_MAPPING = _environment_mapping("SITE_HOST_MAPPING")
# Proxy service
PROXY_SERVICE_RESOURCE_ENDPOINT = "/resources"
PROXY_SERVICE_WEBSERVICES = {"http://192.168.1.187:8181": "/scan"}
PROXY_SERVICE_ALLOWED_HEADERS = ["Content-Type", "Content-Disposition"]

# Limiter service
LIMITER_SERVICE_SCALING_COST_ENABLED = True
LIMITER_SERVICE_SCALING_COST_THRESHOLD = 100
LIMITER_SERVICE_MAX_COST = 10
LIMITER_SERVICE_MAX_ACCOUNTED_SECONDS = 60
LIMITER_SERVICE_ESTIMATOR_TTL_SECONDS = 600
LIMITER_SERVICE_STORAGE_URI = "redis://redis:6379/0"
LIMITER_SERVICE_STRATEGY = "fixed-window"
LIMITER_SERVICE_GROUPS = {
    "example": {
        "counts": 1,
        "per_second": 3600 * 10,
        "patterns": ["/scan/metadata/*"],
    }
}

# Redis service
REDIS_SERVICE_URL = "redis://redis:6379/0"


# Cache service
CACHE_SERVICE_CACHE_TYPE = "RedisCache"
CACHE_SERVICE_REDIS_URI = (
    # NOTE: Do not use the same redis DB as other services
    "redis://redis:6379/1"
)

# Security service
SECURITY_SERVICE_SECRET_KEY = environ.get("SECURITY_SERVICE_SECRET_KEY")
SECURITY_SERVICE_SECRET_KEY_FILE = environ.get("SECURITY_SERVICE_SECRET_KEY_FILE")
SECURITY_SERVICE_PASSWORD_HASH = "pbkdf2_sha512"
SECURITY_SERVICE_VERIFY_PASSWORD_SALT = environ.get(
    "SECURITY_SERVICE_VERIFY_PASSWORD_SALT"
)
SECURITY_SERVICE_VERIFY_PASSWORD_SALT_FILE = environ.get(
    "SECURITY_SERVICE_VERIFY_PASSWORD_SALT_FILE"
)
SECURITY_SERVICE_VERIFY_EMAIL_SALT = environ.get(
    "SECURITY_SERVICE_VERIFY_EMAIL_SALT"
)
SECURITY_SERVICE_VERIFY_EMAIL_SALT_FILE = environ.get(
    "SECURITY_SERVICE_VERIFY_EMAIL_SALT_FILE"
)

BOOTSTRAP_SCOPES = []
USER_DEFAULT_SCOPES = ["user", "api"]
USER_API_DEFAULT_SCOPES = ["api"]

# Kafka producer service
KAFKA_PRODUCER_SERVICE_BOOTSTRAP_SERVERS = ["localhost:9092"]
KAFKA_PRODUCER_SERVICE_REQUEST_TOPIC = "gatewayRequests"
KAFKA_PRODUCER_SERVICE_REQUEST_TIMEOUT_MS = 500

OTEL_ENABLE_METRICS = False
ENABLE_OTEL = 'CONSOLE'
OTEL_SERVICE_NAME = "api-gateway"
OTEL_TRACES_ENDPOINT = "http://localhost:4318/v1/traces"
OTEL_METRICS_ENDPOINT = "http://localhost:4318/v1/metrics"


_MAX_SECRET_FILE_BYTES = 16 * 1024
_SIGNING_CONFIG_KEYS = (
    "SECRET_KEY",
    "SECURITY_SERVICE_SECRET_KEY",
    "SECURITY_SERVICE_VERIFY_PASSWORD_SALT",
    "SECURITY_SERVICE_VERIFY_EMAIL_SALT",
)
_KNOWN_PLACEHOLDERS = {
    b"changeme",
    b"default",
    b"my_private_key",
    b"password",
    b"placeholder",
    b"replace-me",
    b"secret",
}
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _read_secret_file(path):
    if not isinstance(path, (str, os.PathLike)) or not os.fspath(path):
        raise ValueError
    with open(path, "rb") as secret_file:
        value = secret_file.read(_MAX_SECRET_FILE_BYTES + 1)
    if len(value) > _MAX_SECRET_FILE_BYTES:
        raise ValueError
    if value.endswith(b"\r\n"):
        return value[:-2]
    if value.endswith(b"\n"):
        return value[:-1]
    return value


def _resolve_secret(config, key, invalid):
    file_key = "{}_FILE".format(key)
    direct_value = config.get(key)
    file_value = config.get(file_key)
    if direct_value is not None and file_value is not None:
        invalid.extend((key, file_key))
        return None, False
    if file_value is not None:
        try:
            return _read_secret_file(file_value), True
        except (OSError, TypeError, ValueError):
            invalid.append(file_key)
            return None, True
    if direct_value is None:
        invalid.append(key)
        return None, False
    return direct_value, False


def _as_secret_bytes(value):
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise TypeError


def _validate_signing_value(value, key, invalid):
    try:
        decoded = _as_secret_bytes(value)
    except (TypeError, UnicodeError):
        invalid.append(key)
        return None
    if (
        len(decoded) < 32
        or decoded.lower() in _KNOWN_PLACEHOLDERS
        or decoded.lower() == b"736563726574"
    ):
        invalid.append(key)
        return None
    return decoded


def _decode_flask_secret(value, from_file, encoding, invalid):
    if encoding not in {"utf-8", "hex", "raw"}:
        invalid.append("SECRET_KEY_ENCODING")
        return None
    try:
        if encoding == "raw":
            if not isinstance(value, bytes):
                raise TypeError
            decoded = value
        else:
            if from_file:
                value = value.decode("utf-8")
            if not isinstance(value, str):
                raise TypeError
            decoded = value.encode("utf-8") if encoding == "utf-8" else bytes.fromhex(value)
    except (TypeError, UnicodeError, ValueError):
        invalid.append("SECRET_KEY")
        return None
    return _validate_signing_value(decoded, "SECRET_KEY", invalid)


def canonical_authority(value):
    """Return a canonical exact Host authority, or raise ``ValueError``."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(character in value for character in "/?#@\\,%")
        or any(character.isspace() for character in value)
    ):
        raise ValueError
    try:
        parsed = urlsplit("http://{}".format(value))
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or hostname.endswith(".")
    ):
        raise ValueError
    hostname = hostname.lower()
    if ":" in hostname:
        authority = "[{}]".format(hostname)
    else:
        if len(hostname) > 253 or any(
            not _HOST_LABEL.fullmatch(label) for label in hostname.split(".")
        ):
            raise ValueError
        authority = hostname
    if port is not None:
        authority = "{}:{}".format(authority, port)
    if value.lower() != authority:
        raise ValueError
    return authority


def _validate_origins(value, invalid):
    if not isinstance(value, (list, tuple)) or not value:
        invalid.append("CORS_DOMAINS")
        return
    for origin in value:
        if not isinstance(origin, str):
            invalid.append("CORS_DOMAINS")
            return
        try:
            parsed = urlsplit(origin)
            canonical_authority(parsed.netloc)
        except (TypeError, ValueError):
            invalid.append("CORS_DOMAINS")
            return
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            invalid.append("CORS_DOMAINS")
            return


def _validate_authorities(config, invalid):
    configured_hosts = config.get("TRUSTED_HOSTS")
    if not isinstance(configured_hosts, (list, tuple)) or not configured_hosts:
        invalid.append("TRUSTED_HOSTS")
        trusted_hosts = set()
    else:
        trusted_hosts = set()
        for configured_host in configured_hosts:
            try:
                authority = canonical_authority(configured_host)
            except ValueError:
                invalid.append("TRUSTED_HOSTS")
                continue
            if authority in trusted_hosts:
                invalid.append("TRUSTED_HOSTS")
            trusted_hosts.add(authority)

    configured_mapping = config.get("SITE_HOST_MAPPING")
    mapping = {}
    if not isinstance(configured_mapping, dict) or not configured_mapping:
        invalid.append("SITE_HOST_MAPPING")
    else:
        for configured_host, site in configured_mapping.items():
            try:
                authority = canonical_authority(configured_host)
            except ValueError:
                invalid.append("SITE_HOST_MAPPING")
                continue
            if site not in {"ADS", "SCIX"} or authority in mapping:
                invalid.append("SITE_HOST_MAPPING")
                continue
            mapping[authority] = site
        if set(mapping) != trusted_hosts:
            invalid.append("SITE_HOST_MAPPING")

    config["TRUSTED_HOSTS"] = tuple(sorted(trusted_hosts))
    config["SITE_HOST_MAPPING"] = mapping


def _validate_boolean(config, key, invalid):
    value = config.get(key)
    if not isinstance(value, bool):
        invalid.append(key)
        return None
    return value


def validate_runtime_config(config, allow_insecure_test_config=False):
    """Resolve secret files and reject unsafe startup configuration."""
    invalid = []
    testing = config.get("TESTING") is True
    insecure_test_mode = testing and allow_insecure_test_config is True
    if allow_insecure_test_config is not False and not insecure_test_mode:
        invalid.append("TESTING")

    resolved = {}
    source_is_file = {}
    for key in _SIGNING_CONFIG_KEYS:
        resolved[key], source_is_file[key] = _resolve_secret(config, key, invalid)

    if config.get("SECRET_KEY_ENCODING") not in {"utf-8", "hex", "raw"}:
        invalid.append("SECRET_KEY_ENCODING")

    if resolved["SECRET_KEY"] is not None:
        config["SECRET_KEY"] = _decode_flask_secret(
            resolved["SECRET_KEY"],
            source_is_file["SECRET_KEY"],
            config.get("SECRET_KEY_ENCODING"),
            invalid,
        )

    security_values = {}
    for key in _SIGNING_CONFIG_KEYS[1:]:
        value = resolved[key]
        if value is None:
            continue
        if source_is_file[key]:
            try:
                value = value.decode("utf-8")
            except UnicodeError:
                invalid.append(key)
                continue
        decoded = _validate_signing_value(value, key, invalid)
        if decoded is not None:
            security_values[key] = decoded
            config[key] = value
    duplicated_values = {
        value
        for value in security_values.values()
        if list(security_values.values()).count(value) > 1
    }
    for key, value in security_values.items():
        if value in duplicated_values:
            invalid.append(key)

    recaptcha, recaptcha_is_file = _resolve_secret(
        config, "GOOGLE_RECAPTCHA_PRIVATE_KEY", invalid
    )
    recaptcha_bypass = _validate_boolean(config, "RECAPTCHA_TEST_BYPASS", invalid)
    if recaptcha_bypass and not insecure_test_mode:
        invalid.append("RECAPTCHA_TEST_BYPASS")
    if recaptcha is None and recaptcha_bypass and insecure_test_mode:
        invalid[:] = [
            key for key in invalid if key != "GOOGLE_RECAPTCHA_PRIVATE_KEY"
        ]
    elif recaptcha is not None:
        if recaptcha_is_file:
            try:
                recaptcha = recaptcha.decode("utf-8")
            except UnicodeError:
                invalid.append("GOOGLE_RECAPTCHA_PRIVATE_KEY")
                recaptcha = None
        if not isinstance(recaptcha, str) or not recaptcha.strip():
            invalid.append("GOOGLE_RECAPTCHA_PRIVATE_KEY")
        elif recaptcha.lower() in {"my_private_key", "secret", "changeme", "placeholder"}:
            invalid.append("GOOGLE_RECAPTCHA_PRIVATE_KEY")
        else:
            config["GOOGLE_RECAPTCHA_PRIVATE_KEY"] = recaptcha

    mail_bypass = _validate_boolean(config, "MAIL_TEST_BYPASS", invalid)
    if mail_bypass and not insecure_test_mode:
        invalid.append("MAIL_TEST_BYPASS")

    _validate_authorities(config, invalid)
    _validate_origins(config.get("CORS_DOMAINS"), invalid)

    secure_cookie = _validate_boolean(config, "SESSION_COOKIE_SECURE", invalid)
    _validate_boolean(config, "SESSION_COOKIE_HTTPONLY", invalid)
    same_site = config.get("SESSION_COOKIE_SAMESITE")
    if same_site not in {"Lax", "Strict", "None"}:
        invalid.append("SESSION_COOKIE_SAMESITE")
    elif same_site == "None" and secure_cookie is not True:
        invalid.extend(("SESSION_COOKIE_SAMESITE", "SESSION_COOKIE_SECURE"))

    enforce_https = _validate_boolean(config, "HTTPS_ENFORCEMENT", invalid)
    if enforce_https is False and testing and not insecure_test_mode:
        invalid.append("HTTPS_ENFORCEMENT")

    trusted_proxy_hops = config.get("TRUSTED_PROXY_HOPS")
    if (
        isinstance(trusted_proxy_hops, bool)
        or not isinstance(trusted_proxy_hops, int)
        or trusted_proxy_hops < 0
    ):
        invalid.append("TRUSTED_PROXY_HOPS")

    if invalid:
        raise ConfigurationError(invalid)