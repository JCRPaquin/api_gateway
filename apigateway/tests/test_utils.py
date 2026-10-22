import gc
import socket
import ssl
from unittest.mock import MagicMock, patch

import pytest

from apigateway.email_templates import WelcomeVerificationEmail
from apigateway.utils import (
    _DeadlineSocket,
    _smtp_connection,
    send_email,
    send_feedback_email,
)


@pytest.fixture
def smtp_config(app, monkeypatch):
    values = {
        "MAIL_SERVER": "smtp.internal.example",
        "MAIL_PORT": 465,
        "MAIL_SECURITY": "implicit_tls",
        "MAIL_TIMEOUT_SECONDS": 7,
        "MAIL_TLS_CA_FILE": "/run/secrets/mail-ca.pem",
        "MAIL_USERNAME": "gateway",
        "MAIL_PASSWORD": "secret",
        "MAIL_REQUIRE_AUTH": True,
    }
    for key, value in values.items():
        monkeypatch.setitem(app.config, key, value)
    return values


def test_implicit_tls_uses_ca_timeout_and_authentication(app, smtp_config):
    context = MagicMock()
    connection = MagicMock()
    with app.app_context(), patch(
        "apigateway.utils.ssl.create_default_context", return_value=context
    ) as create_context, patch(
        "apigateway.utils.smtplib.SMTP_SSL", return_value=connection
    ) as smtp_ssl:
        assert _smtp_connection() is connection

    create_context.assert_called_once_with(cafile="/run/secrets/mail-ca.pem")
    smtp_ssl.assert_called_once_with(
        "smtp.internal.example", 465, timeout=7, context=context
    )
    connection.login.assert_called_once_with("gateway", "secret")


def test_starttls_negotiates_before_authentication(app, smtp_config, monkeypatch):
    monkeypatch.setitem(app.config, "MAIL_SECURITY", "starttls")
    monkeypatch.setitem(app.config, "MAIL_PORT", 587)
    context = MagicMock()
    connection = MagicMock()
    with app.app_context(), patch(
        "apigateway.utils.ssl.create_default_context", return_value=context
    ), patch("apigateway.utils.smtplib.SMTP", return_value=connection) as smtp:
        assert _smtp_connection() is connection

    smtp.assert_called_once_with("smtp.internal.example", 587, timeout=7)
    assert connection.ehlo.call_count == 2
    connection.starttls.assert_called_once_with(context=context)
    connection.login.assert_called_once_with("gateway", "secret")


@pytest.mark.parametrize(
    "updates",
    [
        {"MAIL_SERVER": None},
        {"MAIL_SECURITY": "plaintext"},
        {"MAIL_USERNAME": None},
        {"MAIL_PASSWORD": None},
        {"MAIL_REQUIRE_AUTH": False},
    ],
)
def test_smtp_configuration_fails_closed(app, smtp_config, monkeypatch, updates):
    for key, value in updates.items():
        monkeypatch.setitem(app.config, key, value)
    with app.app_context(), pytest.raises(RuntimeError):
        _smtp_connection()


def test_both_email_paths_use_shared_tls_sender(app, smtp_config, monkeypatch):
    monkeypatch.setitem(app.config, "TESTING", False)
    send = MagicMock()
    with app.test_request_context("/mail", headers={"Host": "gateway.example"}), patch(
        "apigateway.utils._send_message", send
    ):
        send_email(
            "sender@example.com",
            "recipient@example.com",
            WelcomeVerificationEmail,
        )
        send_feedback_email(
            "Submitter",
            "submitter@example.com",
            "Missing References",
            "Feedback body",
        )
    assert send.call_count == 2


class _CloseCountingSocket:
    def __init__(self, sock):
        self.socket = sock
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        self.socket.close()

    def __getattr__(self, name):
        return getattr(self.socket, name)


def test_deadline_socket_close_waits_for_every_file_handle():
    local, remote = socket.socketpair()
    tracked = _CloseCountingSocket(local)
    wrapped = _DeadlineSocket(tracked, None)
    unbuffered = wrapped.makefile("rb", buffering=0)
    buffered = wrapped.makefile("rb")

    try:
        wrapped.close()
        wrapped.close()
        assert tracked.close_calls == 0
        assert local.fileno() >= 0

        remote.sendall(b"ok")
        assert unbuffered.read(1) == b"o"
        unbuffered.close()
        unbuffered.close()
        assert tracked.close_calls == 0

        with buffered:
            assert buffered.read(1) == b"k"
        assert tracked.close_calls == 1
        assert local.fileno() == -1

        wrapped.close()
        assert tracked.close_calls == 1
    finally:
        unbuffered.close()
        buffered.close()
        wrapped.close()
        remote.close()


def test_deadline_socket_file_gc_performs_pending_close():
    local, remote = socket.socketpair()
    tracked = _CloseCountingSocket(local)
    wrapped = _DeadlineSocket(tracked, None)
    response_file = wrapped.makefile("rb", buffering=0)

    try:
        wrapped.close()
        assert tracked.close_calls == 0
        del response_file
        gc.collect()
        assert tracked.close_calls == 1
        assert local.fileno() == -1
    finally:
        wrapped.close()
        remote.close()


def test_deadline_socket_defers_real_ssl_socket_close():
    local, remote = socket.socketpair()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_socket = context.wrap_socket(
        local,
        server_hostname="localhost",
        do_handshake_on_connect=False,
    )
    wrapped = _DeadlineSocket(tls_socket, None)
    response_file = wrapped.makefile("rb")

    try:
        wrapped.close()
        assert tls_socket.fileno() >= 0
        with response_file:
            pass
        assert tls_socket.fileno() == -1
    finally:
        response_file.close()
        wrapped.close()
        remote.close()
