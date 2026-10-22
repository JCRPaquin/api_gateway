from os import environ

# General
DEBUG = True

# Mail
MAIL_DEFAULT_SENDER = "no-reply@adslabs.org"
MAIL_SERVER = None
MAIL_PORT = 465
MAIL_SECURITY = "implicit_tls"
MAIL_TIMEOUT_SECONDS = 10
MAIL_TLS_CA_FILE = None
MAIL_USERNAME = environ.get("MAIL_USERNAME")
MAIL_PASSWORD = environ.get("MAIL_PASSWORD")
MAIL_REQUIRE_AUTH = True
VERIFY_URL = "https://ui.adsabs.harvard.edu/#user/account/verify"
SCIX_VERIFY_URL = "https://scixplorer.org/#user/account/verify"
SCIX_HOST_DOMAIN = "https://scixplorer.org"
ADS_HOST_DOMAIN = "https://ui.adsabs.harvard.edu"
BLOCK_DISPOSABLE_EMAIL_DOMAINS = True

# Feeback
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
FEEDBACK_SLACK_EMOJI = ":interrobang:"
FORM_SLACK_EMOJI = ":inbox_tray:"

# CORS
CORS_HEADERS = [
    "Content-Type",
    "X-BB-Api-Client-Version",
    "Authorization",
    "Accept",
]

CORS_DOMAINS = [
    "http://localhost:8000",
    "http://localhost:5000",
    "http://adslabs.org",
]

CORS_METHODS = ["GET", "OPTIONS", "POST"]


# Logging
LOGGING_LEVEL = "DEBUG"
LOG_STDOUT = False

# Database
SQLALCHEMY_DATABASE_URI = "postgresql://user:password@db:5432/gateway"
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = environ.get("PROXY_SECRET_KEY", "736563726574")

# Auth
OAUTH2_CLIENT_ID_SALT_LEN = 40
OAUTH2_CLIENT_SECRET_SALT_LEN = 40
GOOGLE_RECAPTCHA_ENDPOINT = "https://www.google.com/recaptcha/api/siteverify"
GOOGLE_RECAPTCHA_PRIVATE_KEY = "MY_PRIVATE_KEY"

# Session
PERMANENT_SESSION_LIFETIME = 3600 * 24 * 365.25  # 1 year in seconds
SESSION_REFRESH_EACH_REQUEST = True
ANONYMOUS_BOOTSTRAP_USER_EMAIL = "anonymous@ads"
BOOTSTRAP_CLIENT_NAME = "BB client"
SESSION_COOKIE_PATH = "/v1"

# Proxy discovery is opt-in. Each named service must configure an HTTPS origin,
# a purpose-specific discovery HMAC key, and complete local route policy.
PROXY_SERVICE_WEBSERVICES = {}
PROXY_SERVICE_DISCOVERY_CONNECT_TIMEOUT_SECONDS = 3
PROXY_SERVICE_DISCOVERY_READ_TIMEOUT_SECONDS = 5
PROXY_SERVICE_DISCOVERY_TOTAL_TIMEOUT_SECONDS = 10
PROXY_SERVICE_DISCOVERY_MAX_BYTES = 262_144
PROXY_SERVICE_DISCOVERY_MAX_AGE_SECONDS = 300
PROXY_SERVICE_DISCOVERY_MAX_ROUTES = 256
PROXY_SERVICE_DISCOVERY_MAX_JSON_DEPTH = 8
PROXY_SERVICE_DISCOVERY_MAX_JSON_ENTRIES = 2048
PROXY_SERVICE_DISCOVERY_MAX_FIELDS = 1024

PROXY_SERVICE_TLS_CA_BUNDLE = True
PROXY_SERVICE_TLS_CLIENT_CERT = None
PROXY_SERVICE_TLS_CLIENT_KEY = None
PROXY_SERVICE_CONNECT_TIMEOUT_SECONDS = 3
PROXY_SERVICE_READ_TIMEOUT_SECONDS = 15
PROXY_SERVICE_TOTAL_TIMEOUT_SECONDS = 60
PROXY_SERVICE_MAX_RETRIES = 0
PROXY_SERVICE_POOL_CONNECTIONS = 20
PROXY_SERVICE_POOL_MAXSIZE = 100
PROXY_SERVICE_MAX_REQUEST_BYTES = 2 * 1024 * 1024
PROXY_SERVICE_MAX_RESPONSE_WIRE_BYTES = 16 * 1024 * 1024
PROXY_SERVICE_MAX_RESPONSE_DECODED_BYTES = 64 * 1024 * 1024
PROXY_SERVICE_MAX_CACHE_OBJECT_BYTES = 1024 * 1024
PROXY_SERVICE_STREAM_CHUNK_BYTES = 64 * 1024
PROXY_SERVICE_MAX_HEADER_COUNT = 64
PROXY_SERVICE_MAX_CACHE_QUERY_PARAMETERS = 8
PROXY_SERVICE_MAX_CACHE_QUERY_VALUE_BYTES = 128
PROXY_SERVICE_MAX_CACHE_QUERY_VALUES = 32
PROXY_SERVICE_MAX_CACHE_HEADER_VALUES = 16
PROXY_SERVICE_MAX_CACHE_HEADER_VALUE_BYTES = 256
PROXY_SERVICE_MAX_HEADER_BYTES = 16 * 1024
PROXY_SERVICE_REQUEST_HEADERS = ["Accept", "Accept-Language", "Content-Type"]
PROXY_SERVICE_RESPONSE_HEADERS = [
    "Content-Type",
    "Content-Disposition",
    "Cache-Control",
    "Age",
    "Expires",
    "ETag",
    "Date",
    "Last-Modified",
    "Vary",
    "Location",
]

# Limiter service
LIMITER_SERVICE_SCALING_COST_ENABLED = True
LIMITER_SERVICE_SCALING_COST_THRESHOLD = 100
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
# The bundled URI is development-only. Production must use a dedicated Redis
# instance with finite maxmemory and an eviction policy; DB numbers are not
# memory isolation.
CACHE_SERVICE_REDIS_URI = "redis://redis:6379/1"

# Security service
SECURITY_SERVICE_SECRET_KEY = environ.get("ADSWS_SECRET_KEY", "secret")
SECURITY_SERVICE_PASSWORD_HASH = "pbkdf2_sha512"
SECURITY_SERVICE_VERIFY_PASSWORD_SALT = environ.get(
    "ADSWS_PASSWORD_SALT", SECURITY_SERVICE_SECRET_KEY
)
SECURITY_SERVICE_VERIFY_EMAIL_SALT = environ.get(
    "ADSWS_VERIFY_EMAIL_SALT", SECURITY_SERVICE_SECRET_KEY
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