import gzip
import socketserver
import threading
import time
import zlib
from datetime import datetime
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
import requests
from flask import g
from flask_login import current_user, login_user
from marshmallow import ValidationError
from werkzeug.exceptions import Unauthorized
from urllib3.exceptions import ReadTimeoutError

from apigateway import views
from apigateway.email_templates import EmailChangedNotification, VerificationEmail
from apigateway.models import AnonymousUser, EmailChangeRequest, User
from apigateway.schemas import bootstrap_response
from apigateway.utils import (
    ProxyTimeoutError,
    ProxyView,
    _AbsoluteDeadlineTimeout,
    _DeadlineHTTPAdapter,
    generate_complete_blocklist,
    normalize_email_domain,
)


class TestBootstrapView:
    @pytest.fixture
    def bootstrap(self):
        return views.BootstrapView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "test_user"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_get_authenticated_user(self, app, bootstrap, mock_regular_user, authenticated_user):
        with app.test_request_context(json={}):
            response, status_code = bootstrap.get()

            assert status_code == 200
            assert not bootstrap_response.validate(response)

    def test_get_authenticated_user_with_params(
        self, app, bootstrap, mock_regular_user, authenticated_user
    ):
        req_json = {
            "scope": "test_scope",
            "client_name": "test_client",
            "redirect_uri": "test_uri",
        }
        with app.test_request_context(json=req_json):
            response, status_code = bootstrap.get()
            parsed_response = bootstrap_response.load(response)

            assert status_code == 200
            assert not bootstrap_response.validate(response)
            assert parsed_response.scopes == req_json["scope"].split(" ")

    def test_get_anonymous_user_with_params(self, app, bootstrap, mock_anon_user):
        json = {"scope": "test_scope", "client_name": "test_client", "redirect_uri": "test_uri"}
        with app.test_request_context(json=json):
            with pytest.raises(Unauthorized):
                bootstrap.get()


class TestUserAuthView:
    @pytest.fixture
    def user_auth_view(self):
        return views.UserAuthView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    @pytest.fixture
    def unverified_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.email = "test_unverified@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id_unverified"
            app.db.session.add(user)
            app.db.session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_successful_login(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": authenticated_user.email, "password": "Valid_password1"}
        ):
            _, status_code = user_auth_view.post()

            assert status_code == 200

    def test_post_invalid_password(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": authenticated_user.email, "password": "invalid_password"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()

    def test_post_invalid_email(self, app, authenticated_user, user_auth_view):
        with app.test_request_context(
            json={"email": "invalid@gmail.com", "password": "Valid_password1"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()

    def test_post_unverified_account(self, app, unverified_user, user_auth_view):
        with app.test_request_context(
            json={"email": unverified_user.email, "password": "Valid_password1"}
        ):
            with pytest.raises(Unauthorized):
                user_auth_view.post()


class TestProxyView:
    @pytest.fixture
    def upstream(self):
        response = MagicMock()
        response.status_code = 200
        response.headers = {
            "Content-Type": "application/json",
            "X-Internal": "drop-me",
        }
        response.raw.read1.side_effect = [b'{"ok":true}', b""]
        return response

    @pytest.fixture
    def mock_session(self, upstream):
        with patch("requests.Session", new_callable=MagicMock) as session:
            session.return_value.request.return_value = upstream
            yield session

    @pytest.fixture(scope="module")
    def proxy_view(self):
        return ProxyView.as_view(
            "proxy_view",
            deploy_path="/proxy",
            remote_base_url="https://remote.example/base",
            remote_path="/resource",
            methods=["GET", "POST"],
            authorization=True,
        )

    @pytest.fixture(scope="module", autouse=True)
    def register_proxy_view(self, app, proxy_view):
        app.add_url_rule("/proxy", view_func=proxy_view, methods=["GET", "POST"])

    @pytest.fixture
    def client(self, app):
        return app.test_client()

    def test_proxy_uses_bounded_verified_nonredirecting_transport(
        self, client, mock_session, upstream, mock_redis_service
    ):
        response = client.get("/proxy?a=1")
        assert response.status_code == 200
        assert response.is_streamed
        assert response.data == b'{"ok":true}'
        mock_session.return_value.request.assert_called_once()
        kwargs = mock_session.return_value.request.call_args.kwargs
        assert kwargs["url"] == "https://remote.example/base/resource?a=1"
        timeout = kwargs["timeout"]
        assert timeout.total == 60
        assert timeout.connect_timeout == 3
        assert kwargs["stream"] is True
        assert kwargs["allow_redirects"] is False
        assert kwargs["verify"] is True
        assert kwargs["cert"] is None
        upstream.close.assert_called_once()

    def test_redirect_is_returned_without_following(
        self, client, mock_session, upstream, mock_redis_service
    ):
        upstream.status_code = 302
        upstream.headers = {"Location": "https://elsewhere.example/"}
        upstream.raw.read1.side_effect = [b"", b""]
        response = client.get("/proxy")
        assert response.status_code == 302
        assert response.headers["Location"] == "https://elsewhere.example/"
        assert mock_session.return_value.request.call_count == 1

    def test_browser_credentials_and_hop_headers_are_stripped(
        self, client, mock_session, mock_anon_user, mock_redis_service
    ):
        mock_anon_user.is_authenticated = False
        anonymous_state = MagicMock()
        anonymous_state.get.return_value = None
        with patch("apigateway.utils.g", anonymous_state):
            client.get(
                "/proxy",
                headers={
                    "Host": "attacker.example",
                    "Authorization": "Bearer browser-token",
                    "Cookie": "session=secret",
                    "Proxy-Authorization": "Basic secret",
                    "Forwarded": "for=attacker",
                    "X-Forwarded-For": "203.0.113.1",
                    "Connection": "X-Remove",
                    "X-Remove": "secret",
                    "Accept": "application/json",
                    "X-api-uid": "attacker",
                    "X-Access-Modality": "attacker",
                },
            )
        headers = {
            name.lower(): value
            for name, value in mock_session.return_value.request.call_args.kwargs[
                "headers"
            ].items()
        }
        assert headers == {
            "accept": "application/json",
            "accept-encoding": "gzip, deflate",
        }

    def test_authenticated_identity_is_generated_from_trusted_state(
        self,
        client,
        mock_session,
        mock_regular_user,
        mock_redis_service,
    ):
        mock_regular_user.is_authenticated = True
        token = MagicMock(user=mock_regular_user)
        trusted_state = MagicMock()
        trusted_state.get.side_effect = {
            "authlib_server_oauth2_token": token,
            "access_modality": "api",
        }.get

        with patch("apigateway.utils.g", trusted_state):
            client.get(
                "/proxy",
                headers={
                    "Accept": "application/json",
                    "X-api-uid": "attacker",
                    "X-Access-Modality": "attacker",
                },
            )

        headers = {
            name.lower(): value
            for name, value in mock_session.return_value.request.call_args.kwargs[
                "headers"
            ].items()
        }
        assert headers == {
            "accept": "application/json",
            "accept-encoding": "gzip, deflate",
            "x-api-uid": "123",
            "x-access-modality": "api",
        }

    def test_response_headers_are_allowlisted(
        self, client, mock_session, mock_redis_service
    ):
        response = client.get("/proxy")
        assert response.headers["Content-Type"] == "application/json"
        assert "X-Internal" not in response.headers

    def test_timeout_returns_gateway_timeout(
        self, client, mock_session, mock_redis_service
    ):
        mock_session.return_value.request.side_effect = requests.exceptions.Timeout
        response = client.get("/proxy")
        assert response.data == b"504 Gateway Timeout"
        assert response.status_code == 504

    def test_total_deadline_is_enforced_without_sleeping(
        self, client, mock_session, upstream, mock_redis_service
    ):
        with patch("apigateway.utils.time.monotonic", side_effect=[0, 61]):
            response = client.get("/proxy")
        assert response.status_code == 504
        upstream.close.assert_called_once()

    @staticmethod
    def _read_local_closing_response(response_head, body):
        send_body = threading.Event()

        class ClosingResponseHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                request_bytes = b""
                while b"\r\n\r\n" not in request_bytes:
                    received = self.request.recv(4096)
                    if not received:
                        return
                    request_bytes += received
                self.request.sendall(response_head)
                if send_body.wait(2):
                    self.request.sendall(body)

        server = socketserver.TCPServer(("127.0.0.1", 0), ClosingResponseHandler)
        server_thread = threading.Thread(target=server.handle_request)
        server_thread.start()
        session = requests.Session()
        session.trust_env = False
        session.mount("http://", _DeadlineHTTPAdapter(max_retries=0))
        response = None
        try:
            started = time.monotonic()
            response = session.get(
                f"http://127.0.0.1:{server.server_address[1]}/",
                stream=True,
                timeout=_AbsoluteDeadlineTimeout(
                    started + 5,
                    total=5,
                    connect=2,
                    read=2,
                ),
            )
            send_body.set()
            return response.raw.read()
        finally:
            send_body.set()
            if response is not None:
                response.close()
            session.close()
            server.server_close()
            server_thread.join(2)
            assert not server_thread.is_alive()

    def test_content_length_response_remains_readable_after_connection_close(self):
        body = b"content-length body"
        response_head = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nConnection: close\r\n\r\n"
        )

        assert self._read_local_closing_response(response_head, body) == body

    def test_close_delimited_response_remains_readable_until_eof(self):
        response_head = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n"
        body = b"close-delimited body"

        assert self._read_local_closing_response(response_head, body) == body

    @pytest.mark.parametrize("slow_phase", ["status", "headers", "chunk", "body"])
    def test_transport_deadline_stops_slow_drip_inside_parser(self, slow_phase):
        scripts = {
            "status": (
                b"",
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
            ),
            "headers": (
                b"HTTP/1.1 200 OK\r\n",
                b"X-Slow: " + b"a" * 40 + b"\r\nContent-Length: 1\r\n\r\nx",
            ),
            "chunk": (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                b"00000000000000000000000000000001\r\nx\r\n0\r\n\r\n",
            ),
            "body": (
                b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n",
                b"x" * 32,
            ),
        }
        immediate, drip = scripts[slow_phase]
        stop = threading.Event()

        class SlowDripHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                request_bytes = b""
                while b"\r\n\r\n" not in request_bytes:
                    received = self.request.recv(4096)
                    if not received:
                        return
                    request_bytes += received
                try:
                    if immediate:
                        self.request.sendall(immediate)
                    for value in drip:
                        if stop.is_set():
                            break
                        self.request.sendall(bytes((value,)))
                        if stop.wait(0.03):
                            break
                except OSError:
                    pass

        server = socketserver.TCPServer(("127.0.0.1", 0), SlowDripHandler)
        server_thread = threading.Thread(target=server.handle_request)
        server_thread.start()
        response = None
        session = requests.Session()
        session.trust_env = False
        session.mount("http://", _DeadlineHTTPAdapter(max_retries=0))
        started = time.monotonic()
        try:
            with pytest.raises(
                (
                    ProxyTimeoutError,
                    ReadTimeoutError,
                    TimeoutError,
                    requests.exceptions.RequestException,
                )
            ):
                response = session.get(
                    f"http://127.0.0.1:{server.server_address[1]}/",
                    stream=True,
                    timeout=_AbsoluteDeadlineTimeout(
                        started + 0.15,
                        total=0.15,
                        connect=0.08,
                        read=0.08,
                    ),
                )
                response.raw.read(32 if slow_phase == "body" else 1)
            assert time.monotonic() - started < 0.7
        finally:
            if response is not None:
                response.close()
            session.close()
            stop.set()
            server.server_close()
            server_thread.join(1)
        assert not server_thread.is_alive()

    def test_reused_connection_receives_the_new_request_deadline(self):
        class TwoResponseHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                for body in (b"first", b"second"):
                    request_bytes = b""
                    while b"\r\n\r\n" not in request_bytes:
                        received = self.request.recv(4096)
                        if not received:
                            return
                        request_bytes += received
                    self.request.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(body)).encode("ascii")
                        + b"\r\n\r\n"
                        + body
                    )

        server = socketserver.TCPServer(("127.0.0.1", 0), TwoResponseHandler)
        server_thread = threading.Thread(target=server.handle_request)
        server_thread.start()
        session = requests.Session()
        session.trust_env = False
        session.mount("http://", _DeadlineHTTPAdapter(max_retries=0))
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        try:
            first_started = time.monotonic()
            first = session.get(
                url,
                timeout=_AbsoluteDeadlineTimeout(
                    first_started + 0.15,
                    total=0.15,
                    connect=0.1,
                    read=0.1,
                ),
            )
            assert first.content == b"first"
            time.sleep(0.17)
            second_started = time.monotonic()
            second = session.get(
                url,
                timeout=_AbsoluteDeadlineTimeout(
                    second_started + 0.15,
                    total=0.15,
                    connect=0.1,
                    read=0.1,
                ),
            )
            assert second.content == b"second"
        finally:
            session.close()
            server.server_close()
            server_thread.join(1)
        assert not server_thread.is_alive()

    def test_slow_read_crossing_total_deadline_is_discarded_and_closed(
        self, app, mock_session, upstream, mock_redis_service, monkeypatch
    ):
        monkeypatch.setitem(app.config, "PROXY_SERVICE_TOTAL_TIMEOUT_SECONDS", 1)
        upstream.raw.read1.side_effect = [b"late"]
        view = ProxyView.as_view(
            "absolute_deadline_proxy",
            "/absolute-deadline",
            "https://remote.example",
            "/resource",
            ["GET"],
        )

        with app.test_request_context("/absolute-deadline"), patch(
            "apigateway.utils.time.monotonic",
            side_effect=[0, 0.1, 0.2, 1.1],
        ):
            response = app.make_response(view())

        assert response.status_code == 504
        assert response.data == b"504 Gateway Timeout"
        upstream.raw._connection.sock.settimeout.assert_called_once_with(
            pytest.approx(0.8)
        )
        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    def test_cache_capture_obeys_total_deadline_and_discards_partial_body(
        self, app, mock_session, upstream, mock_redis_service, monkeypatch
    ):
        monkeypatch.setitem(app.config, "PROXY_SERVICE_TOTAL_TIMEOUT_SECONDS", 1)
        upstream.raw.read1.side_effect = [b"first", b"late"]
        view = ProxyView.as_view(
            "cache_deadline_proxy",
            "/cache-deadline",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/cache-deadline"), patch(
            "apigateway.utils.time.monotonic",
            side_effect=[0, 0.1, 0.2, 0.3, 0.4, 1.1],
        ):
            g.proxy_cache_capture = 1024
            response = app.make_response(view())

        assert response.status_code == 504
        assert response.data == b"504 Gateway Timeout"
        assert not hasattr(response, "_proxy_cache_forbidden")
        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    def test_downstream_streaming_obeys_total_deadline_and_cleans_up(
        self, app, mock_session, upstream, mock_redis_service, monkeypatch
    ):
        monkeypatch.setitem(app.config, "PROXY_SERVICE_TOTAL_TIMEOUT_SECONDS", 1)
        upstream.headers = {"Cache-Control": "no-store"}
        upstream.raw.read1.side_effect = [b"first", b"late"]
        view = ProxyView.as_view(
            "stream_deadline_proxy",
            "/stream-deadline",
            "https://remote.example",
            "/resource",
            ["GET"],
        )

        with app.test_request_context("/stream-deadline"), patch(
            "apigateway.utils.time.monotonic",
            side_effect=[0, 0.1, 0.2, 0.3, 0.4, 1.1],
        ):
            response = app.make_response(view())
            assert response.status_code == 200
            with pytest.raises(ProxyTimeoutError):
                response.get_data()

        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    def test_declared_oversized_body_is_rejected_before_upstream(
        self, app, mock_session, mock_redis_service, monkeypatch
    ):
        monkeypatch.setitem(app.config, "PROXY_SERVICE_MAX_REQUEST_BYTES", 4)
        view = ProxyView.as_view(
            "tiny_request_proxy",
            "/tiny",
            "https://remote.example",
            "/resource",
            ["POST"],
        )
        with app.test_request_context("/tiny", method="POST", data=b"12345"):
            response = app.make_response(view())
        assert response.status_code == 413
        mock_session.return_value.request.assert_not_called()

    def test_wire_response_ceiling_closes_upstream(
        self, app, mock_session, upstream, mock_redis_service, monkeypatch
    ):
        monkeypatch.setitem(app.config, "PROXY_SERVICE_MAX_RESPONSE_WIRE_BYTES", 4)
        upstream.headers = {"Content-Length": "5"}
        view = ProxyView.as_view(
            "tiny_wire_proxy",
            "/tiny-wire",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )
        with app.test_request_context("/tiny-wire"):
            response = app.make_response(view())
        assert response.status_code == 502
        upstream.close.assert_called_once()

    def test_decompressed_response_ceiling_closes_upstream(
        self, app, mock_session, upstream, mock_redis_service, monkeypatch
    ):
        monkeypatch.setitem(app.config, "PROXY_SERVICE_MAX_RESPONSE_DECODED_BYTES", 4)
        encoded = gzip.compress(b"expanded")
        upstream.headers = {"Content-Encoding": "gzip"}
        upstream.raw.read1.side_effect = [encoded, b""]
        view = ProxyView.as_view(
            "tiny_output_proxy",
            "/tiny-output",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )
        with app.test_request_context("/tiny-output"):
            response = app.make_response(view())
        assert response.status_code == 502
        upstream.close.assert_called_once()

    def test_empty_gzip_representation_is_rejected_before_caching(
        self, app, mock_session, upstream, mock_redis_service
    ):
        upstream.headers = {"Content-Encoding": "gzip"}
        upstream.raw.read1.side_effect = [b""]
        view = ProxyView.as_view(
            "empty_gzip_proxy",
            "/empty-gzip",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/empty-gzip"):
            g.proxy_cache_capture = 1024
            response = app.make_response(view())

        assert response.status_code == 502
        assert not hasattr(response, "_proxy_cache_forbidden")
        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    def test_complete_empty_gzip_member_is_cacheable(
        self, app, mock_session, upstream, mock_redis_service
    ):
        upstream.headers = {"Content-Encoding": "gzip"}
        upstream.raw.read1.side_effect = [gzip.compress(b""), b""]
        view = ProxyView.as_view(
            "complete_empty_gzip_proxy",
            "/complete-empty-gzip",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/complete-empty-gzip"):
            g.proxy_cache_capture = 1024
            response = app.make_response(view())

        assert response.status_code == 200
        assert response.data == b""
        assert response._proxy_cache_forbidden is False
        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    @pytest.mark.parametrize(
        ("encoding", "encoded"),
        [
            ("gzip", gzip.compress(b"body")[:-4]),
            ("gzip", gzip.compress(b"body") + b"trailing"),
            ("deflate", zlib.compress(b"body")[:-2]),
            ("deflate", zlib.compress(b"body") + b"trailing"),
        ],
    )
    def test_incomplete_or_trailing_compression_is_rejected_before_caching(
        self,
        app,
        mock_session,
        upstream,
        mock_redis_service,
        encoding,
        encoded,
    ):
        upstream.headers = {"Content-Encoding": encoding}
        upstream.raw.read1.side_effect = [encoded, b""]
        view = ProxyView.as_view(
            f"invalid_{encoding}_{len(encoded)}_proxy",
            "/invalid-compression",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/invalid-compression"):
            g.proxy_cache_capture = 1024
            response = app.make_response(view())

        assert response.status_code == 502
        assert not hasattr(response, "_proxy_cache_forbidden")
        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    def test_concatenated_gzip_members_are_completely_decoded_before_caching(
        self, app, mock_session, upstream, mock_redis_service
    ):
        encoded = gzip.compress(b"first") + gzip.compress(b"-second")
        upstream.headers = {"Content-Encoding": "gzip"}
        upstream.raw.read1.side_effect = [encoded, b""]
        view = ProxyView.as_view(
            "concatenated_gzip_proxy",
            "/concatenated-gzip",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/concatenated-gzip"):
            g.proxy_cache_capture = 1024
            response = app.make_response(view())

        assert response.status_code == 200
        assert response.data == b"first-second"
        assert response._proxy_cache_forbidden is False
        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    def test_decoded_ceiling_is_shared_by_all_gzip_members(
        self, app, mock_session, upstream, mock_redis_service, monkeypatch
    ):
        monkeypatch.setitem(app.config, "PROXY_SERVICE_MAX_RESPONSE_DECODED_BYTES", 5)
        encoded = gzip.compress(b"abc") + gzip.compress(b"def")
        upstream.headers = {"Content-Encoding": "gzip"}
        upstream.raw.read1.side_effect = [encoded, b""]
        view = ProxyView.as_view(
            "concatenated_gzip_ceiling_proxy",
            "/concatenated-gzip-ceiling",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/concatenated-gzip-ceiling"):
            g.proxy_cache_capture = 1024
            response = app.make_response(view())

        assert response.status_code == 502
        upstream.close.assert_called_once()
        mock_session.return_value.close.assert_called_once()

    def test_oversized_cache_capture_streams_without_reading_full_body(
        self, app, mock_session, upstream, mock_redis_service
    ):
        upstream.headers = {}
        upstream.raw.read1.side_effect = [
            b"1" * 40,
            b"2" * 40,
            b"tail",
            b"",
        ]
        view = ProxyView.as_view(
            "bounded_cache_capture_proxy",
            "/bounded-cache",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/bounded-cache"):
            g.proxy_cache_capture = 100
            response = app.make_response(view())
            assert response.is_streamed
            assert upstream.raw.read1.call_count == 2
            assert response.get_data() == b"1" * 40 + b"2" * 40 + b"tail"

        upstream.close.assert_called_once()

    def test_declared_oversized_cache_object_bypasses_capture(
        self, app, mock_session, upstream, mock_redis_service
    ):
        upstream.headers = {"Content-Length": "80"}
        upstream.raw.read1.side_effect = [b"1" * 40, b"2" * 40, b""]
        view = ProxyView.as_view(
            "declared_oversized_cache_proxy",
            "/declared-oversized-cache",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/declared-oversized-cache"):
            g.proxy_cache_capture = 100
            response = app.make_response(view())
            assert response.is_streamed
            assert upstream.raw.read1.call_count == 1
            assert response.get_data() == b"1" * 40 + b"2" * 40

        upstream.close.assert_called_once()

    def test_uncacheable_origin_response_remains_streamed(
        self, app, mock_session, upstream, mock_redis_service
    ):
        upstream.headers = {"Cache-Control": "no-store"}
        upstream.raw.read1.side_effect = [b"body", b""]
        view = ProxyView.as_view(
            "uncacheable_origin_proxy",
            "/uncacheable-origin",
            "https://remote.example",
            "/resource",
            ["GET"],
            cache_complete_response=True,
        )

        with app.test_request_context("/uncacheable-origin"):
            g.proxy_cache_capture = 1024
            response = app.make_response(view())
            assert response.is_streamed
            assert response.get_data() == b"body"

        upstream.close.assert_called_once()

    def test_http_non_loopback_origin_is_rejected(self, app):
        with app.app_context(), pytest.raises(RuntimeError):
            ProxyView(
                "/proxy",
                "http://192.168.1.2",
                "/resource",
                ["GET"],
            )

class TestCSRFView:
    @pytest.fixture
    def csrf_view(self):
        return views.CSRFView()

    def test_get_csrf_token(self, app, csrf_view):
        with app.test_request_context():
            data, status_code = csrf_view.get()
            assert status_code == 200
            assert "csrf" in data


class TestOAuthProtectedView:
    @pytest.fixture
    def oauth_protected_view(self):
        return views.OAuthProtectedView()

    def test_get(self, app, oauth_protected_view, mock_regular_user, mock_current_token):
        with app.test_request_context():
            mock_current_token.user = mock_regular_user
            data, status_code = oauth_protected_view.get()
            assert status_code == 200
            assert data["oauth"] == mock_regular_user.email


class TestUserManagementView:
    @pytest.fixture
    def user_management_view(self):
        return views.UserManagementView()

    @pytest.fixture
    def new_user_data(self):
        return {
            "given_name": "Test",
            "family_name": "User",
            "email": "testuser@gmail.com",
            "password1": "test_passwordU1",
            "password2": "test_passwordU1",
        }

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_new_user(self, app, user_management_view, new_user_data):
        with app.test_request_context(json=new_user_data):
            _, status_code = user_management_view.post()
            assert status_code == 200

    def test_post_new_user_invalid_data(self, app, user_management_view, new_user_data):
        new_user_data["email"] = "invalid_email"
        with app.test_request_context(json=new_user_data):
            with pytest.raises(ValidationError):
                user_management_view.post()

    @pytest.mark.parametrize("domain", ["0-mail.com", "0-MAIL.COM"])
    def test_post_new_user_disposable_email(
        self, app, user_management_view, new_user_data, domain
    ):
        new_user_data["email"] = f"test@{domain}"
        with app.test_request_context(json=new_user_data):
            _, status_code = user_management_view.post()
            assert status_code == 400

    def test_post_new_user_disposable_email_from_local_blocklist(
        self, app, user_management_view, new_user_data
    ):
        new_user_data["email"] = "test@BLOBAPPS.COM"
        with app.test_request_context(json=new_user_data):
            _, status_code = user_management_view.post()
            assert status_code == 400

    def test_domain_policy_normalizes_curated_entries(self):
        assert normalize_email_domain(" BlobApps.COM.\n") == "blobapps.com"
        assert "blobapps.com" in generate_complete_blocklist()

    def test_post_existing_user(self, app, user_management_view, authenticated_user):
        existing_user = {
            "given_name": "Test",
            "family_name": "User",
            "password1": "test_passwordU1",
            "password2": "test_passwordU1",
            "email": authenticated_user.email,
        }

        with app.test_request_context(json=existing_user):
            response, status_code = user_management_view.post()
            assert status_code == 200
            assert "error" not in response

    def test_delete_user(self, app, user_management_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            response, status_code = user_management_view.delete()
            assert status_code == 200
            assert response["message"] == "success"


class TestLogoutView:
    @pytest.fixture
    def logout_view(self):
        return views.LogoutView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_logout(self, app, logout_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            _, status_code = logout_view.post()
            assert status_code == 200
            assert isinstance(current_user._get_current_object(), AnonymousUser)


class TestChangePasswordView:
    @pytest.fixture
    def change_password_view(self):
        return views.ChangePasswordView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    def test_post_change_password(self, app, change_password_view, authenticated_user):
        with app.test_request_context(
            json={
                "old_password": "Valid_password1",
                "new_password1": "New_valid_password1",
                "new_password2": "New_valid_password1",
            }
        ):
            login_user(authenticated_user)
            response, status_code = change_password_view.post()
            assert status_code == 200
            assert response["message"] == "success"

    def test_post_change_password_invalid_new_password(
        self, app, change_password_view, authenticated_user
    ):
        with app.test_request_context(
            json={
                "old_password": "Valid_password1",
                "new_password1": "invalid_password",
                "new_password2": "invalid_password",
            }
        ):
            login_user(authenticated_user)
            with pytest.raises(ValidationError):
                change_password_view.post()

    def test_post_change_password_not_matching_password(
        self, app, change_password_view, authenticated_user
    ):
        with app.test_request_context(
            json={
                "old_password": "Valid_password1",
                "new_password1": "Valid_password12",
                "new_password2": "Valid_password22",
            }
        ):
            login_user(authenticated_user)
            with pytest.raises(ValidationError):
                change_password_view.post()

    def test_post_change_password_invalid_old_password(
        self, app, change_password_view, authenticated_user
    ):
        with app.test_request_context(
            json={
                "old_password": "invalid_password",
                "new_password1": "New_valid_password1",
                "new_password2": "New_valid_password1",
            }
        ):
            login_user(authenticated_user)
            response, status_code = change_password_view.post()
            assert status_code == 401
            assert "error" in response


class TestChangeEmailView:
    @pytest.fixture
    def change_email_view(self):
        return views.ChangeEmailView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    @pytest.fixture
    def send_email_mock(self):
        with mock.patch("apigateway.views.send_email") as _mock:
            yield _mock

    def test_post_change_email(self, app, change_email_view, authenticated_user, send_email_mock):
        old_email = authenticated_user.email
        with app.test_request_context(
            json={"password": "Valid_password1", "email": "new_email@gmail.com"},
        ):
            login_user(authenticated_user)
            _, status_code = change_email_view.post()
            assert status_code == 200
            send_email_mock.assert_any_call(
                app.config["MAIL_DEFAULT_SENDER"],
                "new_email@gmail.com",
                VerificationEmail,
                verification_url=mock.ANY,
                ui_env="ADS",
                ui_url="https://ui.adsabs.harvard.edu",
            )
            send_email_mock.assert_any_call(
                app.config["MAIL_DEFAULT_SENDER"], old_email, EmailChangedNotification, ui_env=mock.ANY, ui_url=mock.ANY,
            )

    def test_post_change_email_scix(self, app, change_email_view, authenticated_user, send_email_mock):
        old_email = authenticated_user.email
        with app.test_request_context(
            json={"password": "Valid_password1", "email": "new_email@gmail.com"},
            headers={"Host":"https://scixplorer.org"}
        ):
            login_user(authenticated_user)
            _, status_code = change_email_view.post()
            assert status_code == 200
            send_email_mock.assert_any_call(
                app.config["MAIL_DEFAULT_SENDER"],
                "new_email@gmail.com",
                VerificationEmail,
                verification_url=mock.ANY,
                ui_env="SciX",
                ui_url="https://scixplorer.org",
            )
            send_email_mock.assert_any_call(
                app.config["MAIL_DEFAULT_SENDER"], old_email, EmailChangedNotification, ui_env=mock.ANY, ui_url=mock.ANY,
            )

    def test_post_change_email_incorrect_password(
        self, app, change_email_view, authenticated_user
    ):
        with app.test_request_context(
            json={"password": "Incorrect_password1", "email": "new_email@gmail.com"}
        ):
            login_user(authenticated_user)
            response, status_code = change_email_view.post()
            assert status_code == 401
            assert response["error"] == "the provided password is incorrect"

    def test_post_change_email_invalid_email(self, app, change_email_view, authenticated_user):
        with app.test_request_context(
            json={"password": "Valid_password1", "email": "invalid_email"}
        ):
            login_user(authenticated_user)
            with pytest.raises(ValidationError):
                change_email_view.post()

    def test_post_change_email_existing_email(self, app, change_email_view, authenticated_user):
        with app.test_request_context(
            json={"password": "Valid_password1", "email": authenticated_user.email}
        ):
            login_user(authenticated_user)
            _, status_code = change_email_view.post()
            assert status_code == 403


class TestVerifyEmailView:
    @pytest.fixture
    def verify_email_view(self):
        return views.VerifyEmailView()

    @pytest.fixture
    def authenticated_user(self, app):
        with app.session_scope() as session:
            user = User()
            user.id = 123
            user.active = True
            user.confirmed_at = datetime.utcnow()
            user.email = "test@gmail.com"
            user.password = "Valid_password1"
            user.fs_uniquifier = "unique_id"
            session.add(user)
            session.commit()
            yield user

        with app.session_scope() as session:
            session.delete(user)
            session.commit()

    @pytest.fixture
    def email_change_request(self, app, authenticated_user):
        with app.session_scope() as session:
            request = EmailChangeRequest()
            request.user_id = authenticated_user.id
            request.new_email = "new_email@gmail.com"
            session.add(request)
            session.commit()
            yield request

        with app.session_scope() as session:
            session.delete(request)
            session.commit()

    def test_get_valid_token(
        self, app, verify_email_view, authenticated_user, email_change_request
    ):
        with app.test_request_context():
            email_change_request.token = app.security_service.generate_email_token()
            login_user(authenticated_user)
            response, status_code = verify_email_view.get(email_change_request.token)
            assert status_code == 200
            assert response["message"] == "success"

    def test_get_no_associated_token(self, app, verify_email_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            _, status_code = verify_email_view.get(app.security_service.generate_email_token())
            assert status_code == 200

    def test_get_invalid_token(self, app, verify_email_view, authenticated_user):
        with app.test_request_context():
            login_user(authenticated_user)
            with pytest.raises(ValueError, match="unknown verification token"):
                verify_email_view.get("invalid_token")
