import io
import json
import os
import smtplib
import socket
import ssl
import time
import zlib
from contextvars import ContextVar
from email.message import EmailMessage
from functools import wraps
from http.client import HTTPException
from itertools import chain
from urllib.parse import urlsplit, urlunsplit

import jsondiff as jd
import requests
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6749.errors import UnsupportedTokenTypeError
from disposable_email_domains import blocklist
from flask import Request, Response, current_app, g, request, stream_with_context
from flask.views import View
from flask_login import current_user
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import HTTPError, ReadTimeoutError
from urllib3.poolmanager import PoolManager, ProxyManager
from urllib3.util import Timeout
from urllib3.util.retry import Retry

from apigateway import extensions
from apigateway.email_templates import (
    AccountRegistrationAttemptEmail,
    EmailTemplate,
    PasswordResetEmail,
    WelcomeVerificationEmail,
)
from apigateway.exceptions import Oauth2HttpError


def require_non_anonymous_bootstrap_user(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if current_user.is_anonymous_bootstrap_user:
            return current_app.login_manager.unauthorized()

        return func(*args, **kwargs)

    return decorated_view


def _smtp_connection():
    """Create an authenticated, certificate-validating SMTP connection."""
    host = current_app.config.get("MAIL_SERVER")
    port = current_app.config.get("MAIL_PORT", 465)
    security = current_app.config.get("MAIL_SECURITY", "implicit_tls")
    timeout = current_app.config.get("MAIL_TIMEOUT_SECONDS", 10)
    username = current_app.config.get("MAIL_USERNAME")
    password = current_app.config.get("MAIL_PASSWORD")
    require_auth = current_app.config.get("MAIL_REQUIRE_AUTH", True)

    if not host:
        raise RuntimeError("MAIL_SERVER is required when email is enabled")
    if security not in {"implicit_tls", "starttls"}:
        raise RuntimeError("MAIL_SECURITY must be implicit_tls or starttls")
    if not require_auth or not username or not password:
        raise RuntimeError("Authenticated SMTP credentials are required")
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError("MAIL_PORT must be a valid TCP port")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise RuntimeError("MAIL_TIMEOUT_SECONDS must be a positive number")

    context = ssl.create_default_context(
        cafile=current_app.config.get("MAIL_TLS_CA_FILE") or None
    )
    if security == "implicit_tls":
        connection = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    else:
        connection = smtplib.SMTP(host, port, timeout=timeout)
        try:
            connection.ehlo()
            connection.starttls(context=context)
            connection.ehlo()
        except Exception:
            connection.close()
            raise

    try:
        connection.login(username, password)
    except Exception:
        connection.close()
        raise
    return connection


def _send_message(message: EmailMessage):
    with _smtp_connection() as connection:
        connection.send_message(message)


def send_email(
    sender: str,
    recipient: str,
    template: EmailTemplate,
    verification_url: str = "",
    ui_env: str = "ADS",
    ui_url: str = "https://ui.adsabs.harvard.edu",
):
    current_app.logger.info("Preparing account email")

    if current_app.config.get("TESTING", False):
        current_app.logger.warning("Email was not sent because TESTING is enabled")
        return

    if request.headers.get("Host", "").endswith("shadow"):
        current_app.logger.info("Email was not sent on a shadow host")
        return

    message = EmailMessage()
    message["Subject"] = template.subject.format(ui_env=ui_env)
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        template.msg_plain.format(
            endpoint=verification_url, ui_env=ui_env, ui_url=ui_url
        )
    )
    message.add_alternative(
        template.msg_html.format(
            endpoint=verification_url,
            email_address=recipient,
            ui_url=ui_url,
            ui_env=ui_env,
        ),
        subtype="html",
    )
    _send_message(message)


def send_feedback_email(
    submitter_name: str,
    submitter_email: str,
    subject: str,
    body: str,
    attachments: list = None,
):
    current_app.logger.info("Preparing feedback email")

    if current_app.config.get("TESTING", False) or request.headers.get(
        "Host", ""
    ).endswith("shadow"):
        current_app.logger.warning("Feedback email was not sent in this environment")
        return

    default_email = current_app.config["FEEDBACK_EMAIL"]
    recipient = current_app.config["FEEDBACK_EMAIL_SUBJECT_OVERRIDE"].get(
        subject, default_email
    )

    message = EmailMessage()
    message["Subject"] = f"{subject} from {submitter_name} ({submitter_email})"
    message["From"] = f"ADS Administration <{default_email}>"
    message["To"] = recipient
    message["reply-to"] = f"{submitter_name} <{submitter_email}>"
    message.set_content(body)

    if attachments:
        for attachment in attachments:
            message.add_attachment(
                json.dumps(attachment[1]).encode("utf-8"),
                filename=attachment[0].strip(".txt") + str(".json"),
                maintype="application",
                subtype="json",
            )

    _send_message(message)


def verify_recaptcha(request: Request, endpoint: str = None):
    """
    Verify a Google reCAPTCHA based on the data contained in the request.

    Args:
        request (Request): The request object containing the reCAPTCHA response.
        endpoint (str, optional): The Google reCAPTCHA endpoint. Defaults to the value of
                                  GOOGLE_RECAPTCHA_ENDPOINT in the app configuration.

    Returns:
        bool: True if reCAPTCHA verification is successful, False otherwise.
    """
    current_app.logger.info("From verify recaptcha: Host header: {}".format(request.headers.get("Host", "No Host Specified")))
    # Skip reCAPTCHA verification if in debug mode
    if current_app.config.get("TESTING", False) or request.headers.get("Host", "").endswith("shadow"):
        current_app.logger.warning("reCAPTCHA is NOT verified during testing")
        return True

    endpoint = endpoint or current_app.config["GOOGLE_RECAPTCHA_ENDPOINT"]
    data = get_json_body(request)
    payload = {
        "secret": current_app.config["GOOGLE_RECAPTCHA_PRIVATE_KEY"],
        "remoteip": request.remote_addr,
        "response": data.get("g-recaptcha-response"),
    }

    try:
        response = requests.post(endpoint, data=payload, timeout=60)
        response.raise_for_status()
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.HTTPError,
    ):
        return False

    return response.json().get("success", False)


def get_json_body(request: Request):
    """
    Attempt to coerce json data from the request, falling
    back to the raw data if json could not be coerced.
    """
    try:
        return request.get_json(force=True)
    except Exception:
        return request.values


class ProxyLimitError(Exception):
    """Raised when a bounded proxy stream crosses a configured ceiling."""


class ProxyTimeoutError(Exception):
    """Raised when a proxy response crosses its absolute deadline."""


_ACTIVE_PROXY_DEADLINE = ContextVar("active_proxy_deadline", default=None)


class _AbsoluteDeadlineTimeout(Timeout):
    """urllib3 timeout configuration carrying one request's wall-clock deadline."""

    def __init__(self, deadline, *, total=None, connect=None, read=None):
        super().__init__(total=total, connect=connect, read=read)
        self.deadline = deadline

    def clone(self):
        return type(self)(
            self.deadline,
            total=self.total,
            connect=self._connect,
            read=self._read,
        )

    def _limit_to_deadline(self, timeout):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProxyTimeoutError
        if isinstance(timeout, (int, float)):
            return min(timeout, remaining)
        return remaining

    @property
    def connect_timeout(self):
        return self._limit_to_deadline(super().connect_timeout)

    @property
    def read_timeout(self):
        return self._limit_to_deadline(super().read_timeout)


class _DeadlineSocket:
    """Socket facade enforcing receive deadlines and makefile ownership."""

    def __init__(self, sock, deadline):
        self._socket = sock
        self.deadline = deadline
        self._io_refs = 0
        self._closed = False
        self._socket_closed = False

    def set_deadline(self, deadline):
        self.deadline = deadline

    def _before_receive(self):
        if self.deadline is None:
            return
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("proxy response deadline exceeded")
        current_timeout = self._socket.gettimeout()
        if current_timeout is None:
            current_timeout = remaining
        self._socket.settimeout(min(current_timeout, remaining))

    def recv(self, *args, **kwargs):
        self._before_receive()
        return self._socket.recv(*args, **kwargs)

    def recv_into(self, *args, **kwargs):
        self._before_receive()
        return self._socket.recv_into(*args, **kwargs)

    def recvfrom(self, *args, **kwargs):
        self._before_receive()
        return self._socket.recvfrom(*args, **kwargs)

    def recvfrom_into(self, *args, **kwargs):
        self._before_receive()
        return self._socket.recvfrom_into(*args, **kwargs)

    def recvmsg(self, *args, **kwargs):
        self._before_receive()
        return self._socket.recvmsg(*args, **kwargs)

    def recvmsg_into(self, *args, **kwargs):
        self._before_receive()
        return self._socket.recvmsg_into(*args, **kwargs)

    def read(self, *args, **kwargs):
        self._before_receive()
        return self._socket.read(*args, **kwargs)

    def makefile(
        self,
        mode="r",
        buffering=None,
        *,
        encoding=None,
        errors=None,
        newline=None,
    ):
        if not set(mode) <= {"r", "w", "b"}:
            raise ValueError(f"invalid mode {mode!r}")
        writing = "w" in mode
        reading = "r" in mode or not writing
        binary = "b" in mode
        raw_mode = "rw" if reading and writing else "r" if reading else "w"
        raw = socket.SocketIO(self, raw_mode)
        self._io_refs += 1
        if buffering is None:
            buffering = -1
        if buffering < 0:
            buffering = io.DEFAULT_BUFFER_SIZE
        if buffering == 0:
            if not binary:
                raise ValueError("unbuffered streams must be binary")
            return raw
        if reading and writing:
            buffer = io.BufferedRWPair(raw, raw, buffering)
        elif reading:
            buffer = io.BufferedReader(raw, buffering)
        else:
            buffer = io.BufferedWriter(raw, buffering)
        if binary:
            return buffer
        return io.TextIOWrapper(
            buffer,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )

    def close(self):
        self._closed = True
        if self._io_refs == 0:
            self._close_socket()

    def _close_socket(self):
        if self._socket_closed:
            return
        self._socket_closed = True
        self._socket.close()

    def _decref_socketios(self):
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed and self._io_refs == 0:
            self._close_socket()

    _decref_socket = _decref_socketios

    def __getattr__(self, name):
        return getattr(self._socket, name)


class _DeadlineConnectionMixin:
    def set_absolute_deadline(self, deadline):
        self._absolute_deadline = deadline
        sock = getattr(self, "sock", None)
        if isinstance(sock, _DeadlineSocket):
            sock.set_deadline(deadline)

    def _new_conn(self):
        sock = super()._new_conn()
        return _DeadlineSocket(sock, getattr(self, "_absolute_deadline", None))

    def connect(self):
        super().connect()
        deadline = getattr(self, "_absolute_deadline", None)
        if isinstance(self.sock, _DeadlineSocket):
            self.sock.set_deadline(deadline)
        else:
            self.sock = _DeadlineSocket(self.sock, deadline)


class _DeadlineHTTPConnection(_DeadlineConnectionMixin, HTTPConnection):
    pass


class _DeadlineHTTPSConnection(_DeadlineConnectionMixin, HTTPSConnection):
    pass


class _DeadlineConnectionPoolMixin:
    def _make_request(self, conn, method, url, *args, **kwargs):
        conn.set_absolute_deadline(_ACTIVE_PROXY_DEADLINE.get())
        return super()._make_request(conn, method, url, *args, **kwargs)


class _DeadlineHTTPConnectionPool(_DeadlineConnectionPoolMixin, HTTPConnectionPool):
    ConnectionCls = _DeadlineHTTPConnection


class _DeadlineHTTPSConnectionPool(_DeadlineConnectionPoolMixin, HTTPSConnectionPool):
    ConnectionCls = _DeadlineHTTPSConnection


class _DeadlinePoolManager(PoolManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = dict(self.pool_classes_by_scheme)
        self.pool_classes_by_scheme.update(
            {
                "http": _DeadlineHTTPConnectionPool,
                "https": _DeadlineHTTPSConnectionPool,
            }
        )


class _DeadlineProxyManager(ProxyManager):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = dict(self.pool_classes_by_scheme)
        self.pool_classes_by_scheme.update(
            {
                "http": _DeadlineHTTPConnectionPool,
                "https": _DeadlineHTTPSConnectionPool,
            }
        )


class _DeadlineHTTPAdapter(requests.adapters.HTTPAdapter):
    """Requests adapter whose pools enforce per-request receive deadlines."""

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = _DeadlinePoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        if proxy.lower().startswith("socks"):
            return super().proxy_manager_for(proxy, **proxy_kwargs)
        if proxy not in self.proxy_manager:
            self.proxy_manager[proxy] = _DeadlineProxyManager(
                proxy_url=proxy,
                num_pools=self._pool_connections,
                maxsize=self._pool_maxsize,
                block=self._pool_block,
                proxy_headers=self.proxy_headers(proxy),
                **proxy_kwargs,
            )
        return self.proxy_manager[proxy]

    def send(self, request, stream=False, timeout=None, **kwargs):
        token = _ACTIVE_PROXY_DEADLINE.set(
            getattr(timeout, "deadline", None)
        )
        try:
            return super().send(
                request,
                stream=stream,
                timeout=timeout,
                **kwargs,
            )
        finally:
            _ACTIVE_PROXY_DEADLINE.reset(token)


class ProxyView(View):
    """Proxy one locally governed route to a configured HTTPS origin."""

    _HOP_HEADERS = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
    _CREDENTIAL_HEADERS = {
        "authorization",
        "cookie",
        "host",
        "forwarded",
        "proxy-authorization",
    }

    def __init__(
        self,
        deploy_path: str,
        remote_base_url: str,
        remote_path: str,
        methods: list,
        authorization: bool = True,
        cache_complete_response: bool = False,
        tls_ca_bundle=None,
    ):
        super().__init__()
        self._deploy_path = deploy_path
        self._remote_path = remote_path
        self._methods = frozenset(methods)
        self._authorization = authorization
        self._cache_complete_response = cache_complete_response
        self._origin = self._validate_origin(remote_base_url)
        self._session = requests.Session()
        self._session.trust_env = False

        self._connect_timeout = current_app.config.get(
            "PROXY_SERVICE_CONNECT_TIMEOUT_SECONDS", 3
        )
        self._read_timeout = current_app.config.get(
            "PROXY_SERVICE_READ_TIMEOUT_SECONDS", 15
        )
        self._total_timeout = current_app.config.get(
            "PROXY_SERVICE_TOTAL_TIMEOUT_SECONDS", 60
        )
        self._max_request_bytes = current_app.config.get(
            "PROXY_SERVICE_MAX_REQUEST_BYTES", 2 * 1024 * 1024
        )
        self._max_wire_bytes = current_app.config.get(
            "PROXY_SERVICE_MAX_RESPONSE_WIRE_BYTES", 16 * 1024 * 1024
        )
        self._max_output_bytes = current_app.config.get(
            "PROXY_SERVICE_MAX_RESPONSE_DECODED_BYTES", 64 * 1024 * 1024
        )
        self._chunk_bytes = current_app.config.get(
            "PROXY_SERVICE_STREAM_CHUNK_BYTES", 64 * 1024
        )
        self._max_header_count = current_app.config.get(
            "PROXY_SERVICE_MAX_HEADER_COUNT", 64
        )
        self._max_header_bytes = current_app.config.get(
            "PROXY_SERVICE_MAX_HEADER_BYTES", 16 * 1024
        )
        for name, value in {
            "connect timeout": self._connect_timeout,
            "read timeout": self._read_timeout,
            "total timeout": self._total_timeout,
        }.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise RuntimeError(f"Proxy {name} must be a positive number")
        for name, value in {
            "request byte limit": self._max_request_bytes,
            "wire byte limit": self._max_wire_bytes,
            "decoded byte limit": self._max_output_bytes,
            "stream chunk size": self._chunk_bytes,
            "header count": self._max_header_count,
            "header byte limit": self._max_header_bytes,
        }.items():
            if type(value) is not int or value <= 0:
                raise RuntimeError(f"Proxy {name} must be a positive integer")
        self._request_headers = {
            value.lower()
            for value in current_app.config.get(
                "PROXY_SERVICE_REQUEST_HEADERS",
                ["Accept", "Accept-Language", "Content-Type"],
            )
        }
        self._response_headers = {
            value.lower()
            for value in current_app.config.get(
                "PROXY_SERVICE_RESPONSE_HEADERS",
                [
                    "Content-Type",
                    "Content-Disposition",
                    "Cache-Control",
                    "ETag",
                    "Age",
                    "Expires",
                    "Date",
                    "Last-Modified",
                    "Vary",
                    "Location",
                ],
            )
        }
        retries = current_app.config.get("PROXY_SERVICE_MAX_RETRIES", 0)
        if type(retries) is not int or retries < 0:
            raise RuntimeError("Proxy retry count must be a nonnegative integer")
        retry_policy = Retry(
            total=retries,
            connect=retries,
            read=0,
            redirect=0,
            status=0,
            allowed_methods=frozenset(
                self._methods.intersection({"GET", "HEAD", "OPTIONS"})
            ),
            raise_on_redirect=False,
        )
        adapter = _DeadlineHTTPAdapter(
            pool_connections=current_app.config.get(
                "PROXY_SERVICE_POOL_CONNECTIONS", 20
            ),
            pool_maxsize=current_app.config.get(
                "PROXY_SERVICE_POOL_MAXSIZE", 100
            ),
            max_retries=retry_policy,
            pool_block=True,
        )
        self._session.mount("https://", adapter)

        client_cert = current_app.config.get("PROXY_SERVICE_TLS_CLIENT_CERT")
        client_key = current_app.config.get("PROXY_SERVICE_TLS_CLIENT_KEY")
        if bool(client_cert) != bool(client_key):
            raise RuntimeError("Proxy TLS client certificate and key must be configured together")
        self._client_cert = (client_cert, client_key) if client_cert else None
        self._verify = (
            tls_ca_bundle
            if tls_ca_bundle is not None
            else current_app.config.get("PROXY_SERVICE_TLS_CA_BUNDLE", True)
        )
        if not (
            self._verify is True
            or isinstance(self._verify, str)
            and bool(self._verify)
        ):
            raise RuntimeError(
                "Proxy TLS verification requires system trust or a CA bundle path"
            )

    def _validate_origin(self, base_url: str):
        parsed = urlsplit(base_url)
        if (
            not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise RuntimeError("Proxy origin must be an absolute origin without credentials or query")
        base_path = parsed.path.rstrip("/") or "/"
        if (
            "\\" in base_path
            or "%" in base_path
            or "//" in base_path
            or any(segment in {".", ".."} for segment in base_path.split("/"))
        ):
            raise RuntimeError("Proxy origin contains an ambiguous path")
        if parsed.scheme != "https":
            raise RuntimeError("Proxy origins must use HTTPS")
        return parsed

    def dispatch_request(self, **kwargs):
        extensions.db.session.remove()
        if request.method not in self._methods:
            return b"405 Method Not Allowed", 405
        return self._proxy_request()

    @staticmethod
    def _header_size(headers) -> int:
        return sum(len(str(name)) + len(str(value)) + 4 for name, value in headers)

    def _outbound_headers(self):
        items = list(request.headers.items())
        if (
            len(items) > self._max_header_count
            or self._header_size(items) > self._max_header_bytes
        ):
            raise ProxyLimitError("request headers")

        connection_tokens = {
            token.strip().lower()
            for token in request.headers.get("Connection", "").split(",")
            if token.strip()
        }
        forbidden = self._HOP_HEADERS | self._CREDENTIAL_HEADERS | connection_tokens
        headers = {}
        for name, value in items:
            lowered = name.lower()
            if lowered.startswith("x-forwarded-") or lowered in forbidden:
                continue
            if lowered in self._request_headers:
                headers[name] = value
        headers["Accept-Encoding"] = "gzip, deflate"

        content_encoding = request.headers.get("Content-Encoding", "identity").lower()
        if content_encoding not in {"", "identity"}:
            raise ProxyLimitError("encoded request body")

        if self._authorization:
            token = g.get("authlib_server_oauth2_token")
            principal = getattr(token, "user", None) if token is not None else None
            if principal is None and current_user.is_authenticated:
                principal = current_user
            if principal is not None:
                headers["X-api-uid"] = str(principal.id)
            modality = g.get("access_modality") if token is not None else None
            if modality:
                headers["X-Access-Modality"] = modality
        return headers

    def _request_body(self):
        if (
            request.content_length is not None
            and request.content_length > self._max_request_bytes
        ):
            raise ProxyLimitError("request body")
        body = request.stream.read(self._max_request_bytes + 1)
        if len(body) > self._max_request_bytes:
            raise ProxyLimitError("request body")
        return body

    def _construct_remote_url(self) -> str:
        base_path = self._origin.path.rstrip("/")
        path = base_path + ("" if self._remote_path == "/" else self._remote_path)
        if not path:
            path = "/"
        query = request.query_string.decode("ascii")
        return urlunsplit(
            (self._origin.scheme, self._origin.netloc, path, query, "")
        )

    def _filtered_response_headers(self, upstream):
        items = list(upstream.headers.items())
        if (
            len(items) > self._max_header_count
            or self._header_size(items) > self._max_header_bytes
        ):
            raise ProxyLimitError("response headers")
        headers = {}
        connection_tokens = {
            token.strip().lower()
            for token in upstream.headers.get("Connection", "").split(",")
            if token.strip()
        }
        forbidden = self._HOP_HEADERS | connection_tokens | {
            "content-length",
            "content-encoding",
            "set-cookie",
        }
        for name, value in items:
            lowered = name.lower()
            if lowered in self._response_headers and lowered not in forbidden:
                headers[name] = value
        return headers

    @staticmethod
    def _set_upstream_read_timeout(raw, timeout):
        # requests exposes no streamed-read timeout setter. Its urllib3 response
        # retains this socket for the lifetime of a streamed response.
        connection = getattr(raw, "_connection", None)
        sock = getattr(connection, "sock", None)
        if sock is None:
            http_response = getattr(raw, "_fp", None)
            buffered_reader = getattr(http_response, "fp", None)
            socket_io = getattr(buffered_reader, "raw", None)
            sock = getattr(socket_io, "_sock", None)
        if sock is None or not callable(getattr(sock, "settimeout", None)):
            raise ProxyLimitError("response transport")
        sock.settimeout(timeout)

    def _read_response_chunk(self, upstream, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProxyTimeoutError
        self._set_upstream_read_timeout(
            upstream.raw, min(self._read_timeout, remaining)
        )
        try:
            # read1 performs at most one underlying read instead of waiting to
            # fill the requested amount while a slow peer refreshes inactivity.
            read1 = getattr(upstream.raw, "read1", None)
            if not callable(read1):
                read1 = getattr(getattr(upstream.raw, "_fp", None), "read1", None)
            if not callable(read1):
                raise ProxyLimitError("response transport")
            chunk = read1(self._chunk_bytes)
        except (ReadTimeoutError, requests.exceptions.Timeout, TimeoutError) as error:
            raise ProxyTimeoutError from error
        except (
            HTTPError,
            HTTPException,
            requests.exceptions.RequestException,
            OSError,
        ) as error:
            raise ProxyLimitError("response transport") from error
        if time.monotonic() >= deadline:
            raise ProxyTimeoutError
        return chunk

    def _response_chunks(self, upstream, deadline):
        try:
            encoding = (
                upstream.headers.get("Content-Encoding", "identity").lower().strip()
            )
            if encoding in {"", "identity"}:
                decoder = None
                decoder_wbits = None
            elif encoding == "gzip":
                decoder_wbits = 16 + zlib.MAX_WBITS
                decoder = zlib.decompressobj(decoder_wbits)
            elif encoding == "deflate":
                decoder_wbits = zlib.MAX_WBITS
                decoder = zlib.decompressobj(decoder_wbits)
            else:
                raise ProxyLimitError("response content encoding")

            wire_count = 0
            output_count = 0
            while True:
                chunk = self._read_response_chunk(upstream, deadline)
                if not chunk:
                    break
                wire_count += len(chunk)
                if wire_count > self._max_wire_bytes:
                    raise ProxyLimitError("wire response body")
                if decoder is None:
                    output_count += len(chunk)
                    if output_count > self._max_output_bytes:
                        raise ProxyLimitError("decoded response body")
                    yield chunk
                    continue

                pending = chunk
                while pending:
                    if decoder.eof:
                        if encoding != "gzip":
                            raise ProxyLimitError("trailing compressed response body")
                        decoder = zlib.decompressobj(decoder_wbits)
                    remaining = self._max_output_bytes - output_count
                    decoded = decoder.decompress(
                        pending, min(self._chunk_bytes, remaining + 1)
                    )
                    if decoder.unconsumed_tail:
                        pending = decoder.unconsumed_tail
                    elif decoder.unused_data:
                        pending = decoder.unused_data
                    else:
                        pending = b""
                    output_count += len(decoded)
                    if output_count > self._max_output_bytes:
                        raise ProxyLimitError("decoded response body")
                    if time.monotonic() >= deadline:
                        raise ProxyTimeoutError
                    if decoded:
                        yield decoded

            if decoder is not None:
                decoded = decoder.flush(self._max_output_bytes - output_count + 1)
                output_count += len(decoded)
                if output_count > self._max_output_bytes:
                    raise ProxyLimitError("decoded response body")
                if not decoder.eof:
                    raise ProxyLimitError("incomplete compressed response body")
                if decoder.unused_data:
                    raise ProxyLimitError("trailing compressed response body")
                if time.monotonic() >= deadline:
                    raise ProxyTimeoutError
                if decoded:
                    yield decoded
        finally:
            upstream.close()
            self._session.close()

    @staticmethod
    def _streaming_response(chunks, status, headers, prefetched=()):
        stream = chain(prefetched, chunks)
        try:
            response = Response(
                stream_with_context(stream),
                status=status,
                headers=headers,
            )
        except Exception:
            chunks.close()
            raise
        response.call_on_close(chunks.close)
        return response

    def _proxy_request(self):
        started_at = time.monotonic()
        deadline = started_at + self._total_timeout
        upstream = None
        try:
            headers = self._outbound_headers()
            body = self._request_body()
            upstream = self._session.request(
                method=request.method,
                url=self._construct_remote_url(),
                headers=headers,
                data=body,
                timeout=_AbsoluteDeadlineTimeout(
                    deadline,
                    total=self._total_timeout,
                    connect=min(self._connect_timeout, self._total_timeout),
                    read=min(self._read_timeout, self._total_timeout),
                ),
                allow_redirects=False,
                stream=True,
                verify=self._verify,
                cert=self._client_cert,
            )
            if time.monotonic() >= deadline:
                upstream.close()
                self._session.close()
                return b"504 Gateway Timeout", 504
            content_length = upstream.headers.get("Content-Length")
            declared_length = None
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                    if declared_length < 0 or declared_length > self._max_wire_bytes:
                        upstream.close()
                        self._session.close()
                        return b"502 Bad Gateway", 502
                except ValueError:
                    upstream.close()
                    self._session.close()
                    return b"502 Bad Gateway", 502
            upstream.raw.decode_content = False
            response_headers = self._filtered_response_headers(upstream)
            chunks = self._response_chunks(upstream, deadline)
            cache_control = {
                token.strip().partition("=")[0].lower()
                for token in upstream.headers.get("Cache-Control", "").split(",")
                if token.strip()
            }
            vary = {
                token.strip().lower()
                for token in upstream.headers.get("Vary", "").split(",")
                if token.strip()
            }
            cache_forbidden = (
                "Set-Cookie" in upstream.headers
                or upstream.status_code != 200
                or "Content-Range" in upstream.headers
                or bool(
                    cache_control.intersection(
                        {"private", "no-store", "no-cache"}
                    )
                )
                or "*" in vary
                or not vary.issubset(self._request_headers)
            )
            capture_limit = g.get("proxy_cache_capture")
            if (
                self._cache_complete_response
                and type(capture_limit) is int
                and not cache_forbidden
            ):
                encoding = (
                    upstream.headers.get("Content-Encoding", "identity")
                    .lower()
                    .strip()
                )
                header_probe = Response(
                    b"",
                    status=upstream.status_code,
                    headers=response_headers,
                )
                header_bytes = sum(
                    len(str(name).encode("utf-8"))
                    + len(str(value).encode("utf-8"))
                    for name, value in header_probe.headers.items()
                )
                content_length_digits = len(
                    header_probe.headers.get("Content-Length", "")
                )
                header_bytes += max(
                    0,
                    len(str(capture_limit)) - content_length_digits,
                )
                capture_body_limit = capture_limit - header_bytes
                declared_oversized = (
                    capture_body_limit < 0
                    or encoding in {"", "identity"}
                    and declared_length is not None
                    and declared_length > capture_body_limit
                )
                if not declared_oversized:
                    captured = []
                    captured_bytes = 0
                    try:
                        for chunk in chunks:
                            if (
                                captured_bytes + len(chunk)
                                > capture_body_limit
                            ):
                                return self._streaming_response(
                                    chunks,
                                    upstream.status_code,
                                    response_headers,
                                    chain(captured, (chunk,)),
                                )
                            captured.append(chunk)
                            captured_bytes += len(chunk)
                    except ProxyTimeoutError:
                        return b"504 Gateway Timeout", 504
                    except (ProxyLimitError, zlib.error):
                        return b"502 Bad Gateway", 502
                    response = Response(
                        b"".join(captured),
                        status=upstream.status_code,
                        headers=response_headers,
                    )
                    response._proxy_cache_forbidden = False
                    return response
            # Prime at most one bounded output chunk so failures discovered before
            # the first downstream byte can still become a gateway response.
            try:
                first_chunk = next(chunks)
            except StopIteration:
                first_chunk = None
            except ProxyTimeoutError:
                return b"504 Gateway Timeout", 504
            except (ProxyLimitError, zlib.error):
                return b"502 Bad Gateway", 502
            prefetched = () if first_chunk is None else (first_chunk,)
            return self._streaming_response(
                chunks,
                upstream.status_code,
                response_headers,
                prefetched,
            )
        except ProxyTimeoutError:
            if upstream is not None:
                upstream.close()
            self._session.close()
            current_app.logger.info("Proxy upstream crossed its total deadline")
            return b"504 Gateway Timeout", 504
        except ProxyLimitError as error:
            if upstream is not None:
                upstream.close()
            self._session.close()
            boundary = str(error)
            if boundary == "request body":
                status, body = 413, b"413 Payload Too Large"
            elif boundary == "encoded request body":
                status, body = 415, b"Unsupported Media Type"
            elif boundary == "request headers":
                status, body = 431, b"Request Header Fields Too Large"
            else:
                status, body = 502, b"502 Bad Gateway"
            current_app.logger.info("Proxy request rejected by configured boundary")
            return body, status
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            self._session.close()
            current_app.logger.info("Proxy upstream timed out or was unavailable")
            return b"504 Gateway Timeout", 504


class GatewayResourceProtector(ResourceProtector):
    def raise_error_response(self, error):
        body = json.dumps(dict({"message": error.description}))
        if type(error)==UnsupportedTokenTypeError:
            current_app.logger.info("Token not recognized as a Bearer Token.")
            body="Unauthorized. If you are using the API, please confirm your Authorization header is of the form Bearer TOKEN and not Bearer:TOKEN"
            raise Oauth2HttpError(error.status_code, error.description, body, error.get_headers())
        raise Oauth2HttpError(error.status_code, error.description, body, error.get_headers())


def _format_changes(field, changes, updated):
    formatted_changes = []
    if isinstance(changes, dict):
        formatted_changes = [f"{k} -- {v}" for k, v in changes.items()]
    elif isinstance(changes, list):
        for item in changes:
            try:
                if field == "references":
                    formatted_changes.append(
                        f"{updated['bibcode']}\t{item.replace('(bibcode) ', '').replace('(reference) ', '')}"
                    )
                else:
                    formatted_changes.append(str(item) + "\n")
            except:  # noqa
                formatted_changes.append(str(item) + "\n")
    else:
        formatted_changes.append(str(changes) + "\n")
    return formatted_changes


def make_json_diff(original: str, updated: str):
    diff_data = jd.diff(original, updated)

    results = []
    if diff_data.get("comments"):
        results.append(f"\n\nComments: {diff_data['comments']}\n\n")

    for field, changes in diff_data.items():
        if field == "comments":
            continue
        results.append(f">>>> {field}\n")
        results.extend(_format_changes(field, changes, updated))
        results.append(">>>>\n")

    return "\n".join(results)


def send_password_reset_email(token: str, email: str):
    if "scixplorer" in request.headers.get("Host", ""):
        ui_env = "SciX"
        ui_url = current_app.config.get("SCIX_HOST_DOMAIN", "dev.scixplorer.org")
        verification_url = f"{current_app.config['SCIX_VERIFY_URL']}/reset-password/{token}"
    else:
        ui_env = "ADS"
        ui_url = current_app.config.get("ADS_HOST_DOMAIN", "dev.adsabs.harvard.edu")
        verification_url = f"{current_app.config['VERIFY_URL']}/reset-password/{token}"    
    send_email(
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
        recipient=email,
        template=PasswordResetEmail,
        verification_url=verification_url,
        ui_env=ui_env,
        ui_url=ui_url,
    )


def send_welcome_email(token: str, email: str):
    if "scixplorer" in request.headers.get("Host", ""):
        ui_env = "SciX"
        ui_url = current_app.config.get("SCIX_HOST_DOMAIN", "dev.scixplorer.org")
        verification_url = f"{current_app.config['SCIX_VERIFY_URL']}/register/{token}"
    else:
        ui_env = "ADS"
        ui_url = current_app.config.get("ADS_HOST_DOMAIN", "dev.adsabs.harvard.edu")
        verification_url = f"{current_app.config['VERIFY_URL']}/register/{token}"
    send_email(
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
        recipient=email,
        template=WelcomeVerificationEmail,
        verification_url=verification_url,
        ui_env=ui_env,
        ui_url=ui_url,
    )


def send_account_registration_attempt_email(email: str):
    if "scixplorer" in request.headers.get("Host", ""):
            ui_env = "SciX"
            ui_url = current_app.config.get("SCIX_HOST_DOMAIN", "dev.scixplorer.org")
    else:
        ui_env = "ADS"
        ui_url = current_app.config.get("ADS_HOST_DOMAIN", "dev.adsabs.harvard.edu")
    send_email(
        sender=current_app.config["MAIL_DEFAULT_SENDER"],
        recipient=email,
        template=AccountRegistrationAttemptEmail,
        ui_env=ui_env,
        ui_url=ui_url,
    )

def normalize_email_domain(domain: str) -> str:
    """Return the canonical form used for disposable-domain policy checks."""
    return domain.strip().rstrip(".").lower()


def generate_complete_blocklist():
    local_blocklist_path = os.path.join(
        os.path.dirname(__file__), "disallowed_email_domain_list.conf"
    )
    with open(local_blocklist_path, encoding="utf-8") as domain_file:
        domains = list(domain_file) + list(blocklist)

    return {
        normalized
        for domain in domains
        if (normalized := normalize_email_domain(domain))
    }