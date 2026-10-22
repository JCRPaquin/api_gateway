import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

from apigateway import extensions
from apigateway.app import sanitize_telemetry_request
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)


def test_create_app_uses_gateway_database_extension(app):
    assert app.db is extensions.db
    assert app.config["SQLALCHEMY_DATABASE_URI"] == os.environ.get(
        "TEST_DATABASE_URI", "sqlite:///:memory:"
    )


def test_environment_boot_config_is_typed_without_logging_secrets():
    secrets = {
        "SECRET_KEY": "subprocess-flask-signing-key-32-bytes-minimum",
        "SECURITY_SERVICE_SECRET_KEY": (
            "subprocess-serializer-key-32-bytes-minimum"
        ),
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT": (
            "subprocess-password-salt-32-bytes-minimum"
        ),
        "SECURITY_SERVICE_VERIFY_EMAIL_SALT": (
            "subprocess-email-salt-32-bytes-minimum"
        ),
        "GOOGLE_RECAPTCHA_PRIVATE_KEY": "subprocess-real-recaptcha-key",
        "ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID": "subprocess-v1",
        "ACCESS_TOKEN_HMAC_KEYS": json.dumps(
            {"subprocess-v1": "subprocess-oauth-hmac-key-32-bytes-minimum"}
        ),
    }
    environment = os.environ.copy()
    for key in (
        "SECRET_KEY_FILE",
        "SECURITY_SERVICE_SECRET_KEY_FILE",
        "SECURITY_SERVICE_VERIFY_PASSWORD_SALT_FILE",
        "SECURITY_SERVICE_VERIFY_EMAIL_SALT_FILE",
        "GOOGLE_RECAPTCHA_PRIVATE_KEY_FILE",
    ):
        environment.pop(key, None)
    environment.update(
        secrets,
        TRUSTED_HOSTS="gateway.example,scix-gateway.example",
        SITE_HOST_MAPPING=json.dumps(
            {
                "gateway.example": "ADS",
                "scix-gateway.example": "SCIX",
            }
        ),
        CORS_DOMAINS="https://ui.example,https://scix-ui.example",
    )
    script = textwrap.dedent(
        """
        import json
        import logging

        logging.basicConfig(level=logging.INFO)

        from apigateway.app import create_app

        app = create_app(
            SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
            ENABLE_OTEL=False,
            PROXY_SERVICE_WEBSERVICES={},
        )
        print(json.dumps({
            "trusted_hosts": app.config["TRUSTED_HOSTS"],
            "site_host_mapping": app.config["SITE_HOST_MAPPING"],
            "cors_domains": app.config["CORS_DOMAINS"],
        }, sort_keys=True))
        """
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[2],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )

    assert json.loads(completed.stdout) == {
        "cors_domains": ["https://ui.example", "https://scix-ui.example"],
        "site_host_mapping": {
            "gateway.example": "ADS",
            "scix-gateway.example": "SCIX",
        },
        "trusted_hosts": ["gateway.example", "scix-gateway.example"],
    }
    process_output = completed.stdout + completed.stderr
    for secret in secrets.values():
        assert secret not in process_output


def test_request_telemetry_omits_query_credentials(app):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    instrumentor = FlaskInstrumentor()
    instrumentor.instrument_app(
        app,
        tracer_provider=provider,
        request_hook=sanitize_telemetry_request,
    )
    canary = "telemetry-query-credential-canary"
    try:
        response = app.test_client().get(
            "/accounts/status?access_token={}".format(canary),
            base_url="https://localhost",
        )
        assert response.status_code == 400
    finally:
        instrumentor.uninstrument_app(app)

    serialized = "\n".join(span.to_json() for span in exporter.get_finished_spans())
    assert canary not in serialized
    assert "access_token" not in serialized
