"""Allowlisted request context for logs and HTTP server spans."""

from typing import Tuple

from flask import has_request_context, request


UNMATCHED_ROUTE = "<unmatched>"
UNKNOWN_METHOD = "<unknown>"
REDACTED = "[REDACTED]"

_URL_ATTRIBUTES = (
    "http.target",
    "http.url",
    "url.full",
    "url.path",
    "url.query",
)
_IDENTITY_ATTRIBUTES = (
    "http.host",
    "http.user_agent",
    "http.client_ip",
    "user_agent.original",
    "client.address",
    "net.peer.ip",
    "net.host.name",
    "net.peer.name",
    "net.sock.peer.addr",
    "network.peer.address",
    "net.sock.host.addr",
    "server.address",
    "http.server_name",
)


def route_template() -> str:
    """Return the matched Flask rule without falling back to a concrete URL."""
    if not has_request_context() or request.url_rule is None:
        return UNMATCHED_ROUTE
    return request.url_rule.rule


def request_method() -> str:
    """Return the HTTP method without reading any other request data."""
    if not has_request_context():
        return UNKNOWN_METHOD
    return request.method.upper()


def request_log_fields() -> Tuple[str, str]:
    """Return the only request-derived fields allowed in ordinary logs."""
    return request_method(), route_template()


def exception_log_fields(exception: BaseException) -> Tuple[str, str, str]:
    """Return safe request fields plus an exception class, never its message."""
    return request_method(), route_template(), type(exception).__name__


def _sanitize_span(span) -> None:
    if span is None or not span.is_recording():
        return

    method, route = request_log_fields()
    span.update_name("{} {}".format(method, route))
    span.set_attribute("http.route", route)

    for attribute in _URL_ATTRIBUTES:
        span.set_attribute(attribute, "" if attribute == "url.query" else route)

    for attribute in _IDENTITY_ATTRIBUTES:
        span.set_attribute(attribute, REDACTED)

    # Header capture is deployment-configurable. Redact every captured header,
    # including names introduced by future semantic-convention versions.
    attributes = getattr(span, "attributes", {})
    for attribute in tuple(attributes):
        if ".header." in attribute:
            span.set_attribute(attribute, REDACTED)


def sanitize_request_span(span, environ) -> None:
    """OpenTelemetry request hook that removes raw request-target attributes."""
    _sanitize_span(span)


def sanitize_response_span(span, status, response_headers) -> None:
    """OpenTelemetry response hook that applies the final matched route rule."""
    _sanitize_span(span)
