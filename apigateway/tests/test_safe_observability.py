import json
import logging
from unittest.mock import MagicMock, patch

import pytest
import requests
from flask import Flask, Response
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from apigateway.logging_utils import REDACTED, sanitize_request_span, sanitize_response_span
from apigateway.migration_utils import get_app_config
from apigateway.utils import ProxyView, send_email
from apigateway.views import UserFeedbackView


@pytest.fixture(scope="module", autouse=True)
def observability_proxy_route(app):
    proxy_view = ProxyView.as_view(
        "observability_proxy",
        deploy_path="/observability-proxy",
        remote_base_url="https://upstream.example",
    )
    app.add_url_rule(
        "/observability-proxy/<path:proxy_path>",
        view_func=proxy_view,
        methods=["GET"],
    )


class _FormattedLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(self.format(record))


@pytest.fixture
def capture_logger():
    attached = []

    def capture(logger):
        handler = _FormattedLogHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(
            logging.Formatter("%(levelname)s %(name)s %(message)s")
        )
        attached.append((logger, handler, logger.level, logger.disabled))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.disabled = False
        return handler.messages

    yield capture

    for logger, handler, level, disabled in reversed(attached):
        logger.removeHandler(handler)
        logger.setLevel(level)
        logger.disabled = disabled


def _messages(messages):
    return "\n".join(messages)


def _span_text(span):
    return json.dumps(
        {
            "name": span.name,
            "attributes": dict(span.attributes),
            "events": [
                {"name": event.name, "attributes": dict(event.attributes or {})}
                for event in span.events
            ],
        },
        default=str,
        sort_keys=True,
    )


def test_exception_logs_use_route_template_without_exception_message(
    app, capture_logger
):
    token_canary = "GW_TOKEN_CANARY_exception"
    message_canary = "GW_EXCEPTION_MESSAGE_CANARY"
    captured = capture_logger(app.logger)

    with app.test_request_context(
        "/accounts/verify/{}".format(token_canary), method="GET"
    ):
        exception = RuntimeError(message_canary)
        app.log_exception((RuntimeError, exception, None))

    messages = _messages(captured)
    assert token_canary not in messages
    assert message_canary not in messages
    assert "method=GET" in messages
    assert "route=/accounts/verify/<string:token>" in messages
    assert "exception=RuntimeError" in messages
    assert messages.count("Unhandled request exception") == 1


def test_unmatched_exception_log_does_not_use_concrete_path(app, capture_logger):
    path_canary = "GW_UNMATCHED_PATH_CANARY"
    captured = capture_logger(app.logger)

    with app.test_request_context("/missing/{}".format(path_canary), method="POST"):
        exception = LookupError(path_canary)
        app.log_exception((LookupError, exception, None))

    messages = _messages(captured)
    assert path_canary not in messages
    assert "method=POST" in messages
    assert "route=<unmatched>" in messages
    assert "exception=LookupError" in messages
    assert messages.count("Unhandled request exception") == 1


def test_invalid_token_log_does_not_contain_token_or_exception_message(
    app, capture_logger
):
    token_canary = "GW_TOKEN_CANARY_invalid"
    captured = capture_logger(app.security_service._logger)

    with app.test_request_context(
        "/accounts/verify/{}".format(token_canary), method="GET"
    ):
        with pytest.raises(ValueError, match="unknown verification token"):
            app.security_service.verify_email_token(token_canary)

    messages = _messages(captured)
    assert token_canary not in messages
    assert "Verification token rejected" in messages
    assert "method=GET" in messages
    assert "route=/accounts/verify/<string:token>" in messages
    assert "exception=" in messages
    assert messages.count("Verification token rejected") == 1


def test_testing_mail_suppression_does_not_log_recipient_or_url(
    app, capture_logger
):
    email_canary = "GW_EMAIL_CANARY@example.invalid"
    token_canary = "GW_MAIL_TOKEN_CANARY"
    template = MagicMock()
    captured = capture_logger(app.logger)

    with app.test_request_context(
        "/accounts/verify/{}".format(token_canary), method="GET"
    ):
        send_email(
            "sender@example.invalid",
            email_canary,
            template,
            verification_url="https://ui.example/#/verify/{}".format(token_canary),
        )

    messages = _messages(captured)
    assert email_canary not in messages
    assert token_canary not in messages
    assert "Email delivery suppressed outcome=testing" in messages
    assert "method=GET" in messages
    assert "route=/accounts/verify/<string:token>" in messages
    assert messages.count("Email delivery suppressed outcome=testing") == 1


def test_feedback_payload_is_not_logged(app, capture_logger):
    canaries = (
        "GW_FEEDBACK_BODY_CANARY",
        "GW_FEEDBACK_EMAIL_CANARY@example.invalid",
        "GW_CAPTCHA_CANARY",
        "GW_FEEDBACK_NESTED_CANARY",
    )
    payload = {
        "_subject": canaries[0],
        "email": canaries[1],
        "comments": canaries[0],
        "g-recaptcha-response": canaries[2],
        "origin": "untrusted-origin",
        "records": [{"value": canaries[3]}],
    }
    captured = capture_logger(app.logger)

    response = app.test_client().post("/feedback", json=payload)

    assert response.status_code == 400
    messages = _messages(captured)
    for canary in canaries:
        assert canary not in messages
    assert "Feedback received method=POST route=/feedback" in messages
    assert messages.count("Feedback received method=POST route=/feedback") == 1
    assert (
        messages.count(
            "reCAPTCHA verification suppressed method=POST route=/feedback"
        )
        == 1
    )


def test_feedback_delivery_exception_logs_only_exception_class(
    app, capture_logger
):
    email_canary = "GW_FEEDBACK_FAILURE_EMAIL_CANARY@example.invalid"
    exception_canary = "GW_FEEDBACK_FAILURE_EXCEPTION_CANARY"
    feedback_view = UserFeedbackView()
    captured = capture_logger(app.logger)

    with app.test_request_context("/feedback", method="POST"):
        with patch(
            "apigateway.views.send_feedback_email",
            side_effect=RuntimeError(exception_canary),
        ):
            delivered = feedback_view._send_email(
                {"name": "Canary submitter"},
                email_canary,
                "Canary subject",
                "Canary body",
                [],
            )

    assert delivered is False
    messages = _messages(captured)
    assert email_canary not in messages
    assert exception_canary not in messages
    assert "Feedback email failed method=POST route=/feedback" in messages
    assert "exception=RuntimeError" in messages
    assert messages.count("Feedback email failed") == 1


@pytest.mark.parametrize(
    "request_exception, expected_status, expected_outcome",
    [
        (None, 200, "Proxy request started"),
        (requests.exceptions.Timeout(), 504, "outcome=gateway_timeout"),
    ],
)
def test_proxy_logs_route_template_without_path_or_query(
    app, capture_logger, request_exception, expected_status, expected_outcome
):
    path_canary = "GW_PROXY_PATH_CANARY"
    query_canary = "GW_QUERY_SECRET_CANARY"
    upstream_response = MagicMock(
        content=b"ok",
        status_code=200,
        headers={"test_allowed_header": "value"},
    )
    captured = capture_logger(app.logger)

    with patch("requests.Session") as session_class:
        if request_exception is None:
            session_class.return_value.get.return_value = upstream_response
        else:
            session_class.return_value.get.side_effect = request_exception

        response = app.test_client().get(
            "/observability-proxy/{}?access_token={}".format(
                path_canary, query_canary
            )
        )

    assert response.status_code == expected_status
    messages = _messages(captured)
    assert path_canary not in messages
    assert query_canary not in messages
    assert expected_outcome in messages
    assert "method=GET" in messages
    assert "route=/observability-proxy/<path:proxy_path>" in messages
    assert messages.count("Proxy request started") == 1
    assert messages.count(expected_outcome) == 1


@pytest.fixture
def instrumented_app(monkeypatch):
    monkeypatch.setenv(
        "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST",
        "authorization,cookie,user-agent,x-canary",
    )
    monkeypatch.setenv(
        "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE",
        "set-cookie,x-canary-response",
    )

    traced_app = Flask("safe-observability-traces")

    @traced_app.route("/proxy/<path:proxy_path>", methods=["POST"])
    def traced_proxy(proxy_path):
        response = Response("ok", status=202)
        response.headers["Set-Cookie"] = "session=GW_RESPONSE_COOKIE_CANARY"
        response.headers["X-Canary-Response"] = "GW_RESPONSE_HEADER_CANARY"
        return response

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    FlaskInstrumentor.instrument_app(
        traced_app,
        tracer_provider=provider,
        request_hook=sanitize_request_span,
        response_hook=sanitize_response_span,
    )

    yield traced_app, exporter

    FlaskInstrumentor.uninstrument_app(traced_app)
    provider.shutdown()


def test_exported_span_preserves_method_status_and_template_without_canaries(
    instrumented_app,
):
    traced_app, exporter = instrumented_app
    canaries = (
        "GW_SPAN_PATH_CANARY",
        "GW_SPAN_QUERY_CANARY",
        "GW_SPAN_AUTH_CANARY",
        "GW_SPAN_COOKIE_CANARY",
        "GW_SPAN_AGENT_CANARY",
        "GW_SPAN_BODY_EMAIL_CANARY@example.invalid",
        "GW_RESPONSE_COOKIE_CANARY",
        "GW_RESPONSE_HEADER_CANARY",
        "GW_SPAN_IP_CANARY",
        "gw-span-host-canary.example",
    )

    response = traced_app.test_client().post(
        "/proxy/{}?access_token={}".format(canaries[0], canaries[1]),
        base_url="http://{}".format(canaries[9]),
        data=canaries[5],
        headers={
            "Authorization": "Bearer {}".format(canaries[2]),
            "Cookie": "session={}".format(canaries[3]),
            "User-Agent": canaries[4],
            "X-Canary": canaries[2],
        },
        environ_overrides={"REMOTE_ADDR": canaries[8]},
    )

    assert response.status_code == 202
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    serialized = _span_text(span)
    for canary in canaries:
        assert canary not in serialized

    attributes = span.attributes
    assert span.name == "POST /proxy/<path:proxy_path>"
    assert attributes["http.route"] == "/proxy/<path:proxy_path>"
    assert attributes["http.target"] == "/proxy/<path:proxy_path>"
    assert attributes["url.path"] == "/proxy/<path:proxy_path>"
    assert attributes["url.query"] == ""
    assert attributes.get("http.method", attributes.get("http.request.method")) == "POST"
    assert attributes.get(
        "http.status_code", attributes.get("http.response.status_code")
    ) == 202
    assert attributes["http.request.header.authorization"] == REDACTED
    assert all(
        value == REDACTED
        for key, value in attributes.items()
        if ".header." in key
    )


def test_unmatched_span_uses_fixed_route_without_raw_target(instrumented_app):
    traced_app, exporter = instrumented_app
    exporter.clear()
    path_canary = "GW_SPAN_UNMATCHED_CANARY"
    query_canary = "GW_SPAN_UNMATCHED_QUERY_CANARY"

    response = traced_app.test_client().get(
        "/missing/{}?token={}".format(path_canary, query_canary)
    )

    assert response.status_code == 404
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert path_canary not in _span_text(span)
    assert query_canary not in _span_text(span)
    assert span.name == "GET <unmatched>"
    assert span.attributes["http.route"] == "<unmatched>"
    assert span.attributes.get(
        "http.status_code", span.attributes.get("http.response.status_code")
    ) == 404


def test_migration_config_resolution_returns_uri_without_output(capsys):
    uri_canary = "postgresql://user:GW_DATABASE_PASSWORD_CANARY@db/gateway"
    config_app = Flask("migration-config-test")
    config_app.config["SQLALCHEMY_DATABASE_URI"] = uri_canary

    resolved = get_app_config(
        "SQLALCHEMY_DATABASE_URI", app_factory=lambda: config_app
    )
    captured = capsys.readouterr()

    assert resolved == uri_canary
    assert captured.out == ""
    assert captured.err == ""
