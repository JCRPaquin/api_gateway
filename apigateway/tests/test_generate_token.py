import os
import time

import pytest

from apigateway.exceptions import ValidationError
from apigateway.models import OAuth2Token, User
from scripts import generate_oauth_client
from scripts.generate_oauth_client import get_token


def _owner(app, *, quota=-1, scopes="api user"):
    with app.app_context():
        owner = User(
            email="operator-target@example.org",
            fs_uniquifier="operator-target",
            active=True,
            ratelimit_quota=quota,
            _allowed_scopes=scopes,
        )
        app.db.session.add(owner)
        app.db.session.commit()


def _args(*extra):
    return [
        "--user-email",
        "operator-target@example.org",
        "--name",
        "automation",
        "--output",
        "-",
        *extra,
    ]


def test_operator_uses_digest_storage_and_returns_raw_once(app):
    _owner(app)
    raw = get_token(app, _args("--scopes", "api", "--expires-in", "3600"))
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.access_token != raw
        assert len(token.access_token) == 64
        assert token.token_key_id == app.config["ACCESS_TOKEN_HMAC_ACTIVE_KEY_ID"]
        assert token.credential_purpose == "operator"
        assert token.expires_in == 3600
        assert app.auth_service.lookup_access_token(raw).id == token.id
        assert "refresh_token" not in token.__table__.c


def test_operator_rotation_revokes_previous_raw_value(app):
    _owner(app)
    first = get_token(app, _args("--scopes", "api"))
    second = get_token(app, _args("--scopes", "api"))
    with app.app_context():
        assert first != second
        assert app.auth_service.lookup_access_token(first) is None
        assert app.auth_service.lookup_access_token(second) is not None
        assert app.db.session.query(OAuth2Token).count() == 1


def test_operator_obeys_scope_quota_and_expiry_policy(app):
    _owner(app, quota=0, scopes="api")
    with pytest.raises(ValidationError):
        get_token(app, _args("--scopes", "api"))

    with app.app_context():
        owner = app.db.session.query(User).one()
        owner.ratelimit_quota = -1
        app.db.session.commit()
    with pytest.raises(ValidationError):
        get_token(app, _args("--scopes", "admin"))
    with pytest.raises(ValidationError):
        get_token(app, _args("--scopes", "api", "--expires-in", str(31 * 86400)))


def test_operator_relative_expiry_is_not_fixed_calendar_time(app):
    _owner(app)
    before = int(time.time())
    get_token(app, _args("--scopes", "api", "--expires-in", "120"))
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.expires_in == 120
        assert before + 120 <= token.expires_at() <= int(time.time()) + 120


def test_operator_main_writes_only_raw_token_to_stdout(monkeypatch, capsys):
    monkeypatch.setattr(
        generate_oauth_client, "get_token", lambda app=None, argv=None: "raw-canary"
    )
    generate_oauth_client.main(
        [
            "--user-email",
            "operator-target@example.org",
            "--name",
            "automation",
            "--output",
            "-",
        ]
    )
    captured = capsys.readouterr()
    assert captured.out == "raw-canary\n"
    assert captured.err == ""


def test_operator_file_delivery_is_digest_only_and_mode_0600(app, tmp_path):
    _owner(app)
    output = tmp_path / "credential"
    status = get_token(
        app,
        [
            "--user-email",
            "operator-target@example.org",
            "--name",
            "automation",
            "--scopes",
            "api",
            "--output",
            str(output),
        ],
    )
    raw = output.read_text().removesuffix("\n")
    assert status["status"] == "created"
    assert raw not in str(status)
    assert os.stat(output).st_mode & 0o777 == 0o600
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.access_token != raw
        assert app.auth_service.lookup_access_token(raw).id == token.id
        assert token.credential_delivery_pending is False
        assert token.credential_delivery_path is None


def test_operator_recovers_pending_file_after_publish_commit_failure(
    app, tmp_path, monkeypatch
):
    _owner(app)
    output = tmp_path / "credential"
    arguments = [
        "--user-email",
        "Operator-Target@Example.ORG",
        "--name",
        "automation",
        "--scopes",
        "api",
        "--output",
        str(output),
    ]
    original_commit = generate_oauth_client.db.session.commit
    calls = 0

    def fail_delivery_commit():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("delivery commit failed")
        return original_commit()

    monkeypatch.setattr(generate_oauth_client.db.session, "commit", fail_delivery_commit)
    with pytest.raises(RuntimeError):
        get_token(app, arguments)
    raw = output.read_text().removesuffix("\n")
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.credential_delivery_pending is True
        assert token.access_token != raw

    arguments[1] = "operator-target@example.org"
    monkeypatch.setattr(generate_oauth_client.db.session, "commit", original_commit)
    status = get_token(app, arguments)
    assert status["status"] == "delivered"
    assert output.read_text() == raw + "\n"
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.credential_delivery_pending is False
        assert token.credential_delivery_path is None


def test_operator_recovers_when_issuance_commit_acknowledgement_is_lost(
    app, tmp_path, monkeypatch
):
    _owner(app)
    output = tmp_path / "credential"
    arguments = [
        "--user-email",
        "Operator-Target@Example.ORG",
        "--name",
        "automation",
        "--scopes",
        "api",
        "--output",
        str(output),
    ]
    original_commit = generate_oauth_client.db.session.commit
    calls = 0

    def commit_then_lose_acknowledgement():
        nonlocal calls
        calls += 1
        result = original_commit()
        if calls == 1:
            raise RuntimeError("issuance commit acknowledgement lost")
        return result

    monkeypatch.setattr(
        generate_oauth_client.db.session,
        "commit",
        commit_then_lose_acknowledgement,
    )

    with pytest.raises(
        generate_oauth_client.DatabaseIntegrityError,
        match="outcome is uncertain",
    ):
        get_token(app, arguments)

    pending_path = generate_oauth_client._pending_delivery_path(
        os.path.abspath(str(output))
    )
    assert not output.exists()
    assert os.path.exists(pending_path)
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.credential_delivery_pending is True

    arguments[1] = "operator-target@example.org"
    status = get_token(app, arguments)

    raw = output.read_text().removesuffix("\n")
    assert status["status"] == "delivered"
    assert raw not in str(status)
    assert not os.path.exists(pending_path)
    with app.app_context():
        token = app.db.session.query(OAuth2Token).one()
        assert token.credential_delivery_pending is False
        assert token.credential_delivery_path is None
        assert app.auth_service.lookup_access_token(raw).id == token.id


def test_operator_preserves_unresolved_pending_file_without_database_row(
    app, tmp_path, monkeypatch
):
    _owner(app)
    output = tmp_path / "credential"
    arguments = [
        "--user-email",
        "operator-target@example.org",
        "--name",
        "automation",
        "--scopes",
        "api",
        "--output",
        str(output),
    ]
    original_commit = generate_oauth_client.db.session.commit

    def unresolved_commit():
        raise RuntimeError("database commit outcome unavailable")

    monkeypatch.setattr(generate_oauth_client.db.session, "commit", unresolved_commit)
    with pytest.raises(
        generate_oauth_client.DatabaseIntegrityError,
        match="outcome is uncertain",
    ):
        get_token(app, arguments)

    pending_path = generate_oauth_client._pending_delivery_path(
        os.path.abspath(str(output))
    )
    pending_stat = os.stat(pending_path)
    assert not output.exists()
    with app.app_context():
        assert app.db.session.query(OAuth2Token).count() == 0

    monkeypatch.setattr(generate_oauth_client.db.session, "commit", original_commit)
    with pytest.raises(
        generate_oauth_client.DatabaseIntegrityError,
        match="no confirmed database row",
    ):
        get_token(app, arguments)

    assert os.stat(pending_path).st_ino == pending_stat.st_ino
    assert not output.exists()


def test_operator_requires_email_syntax_for_owner(app):
    arguments = _args("--scopes", "api")
    arguments[1] = "operator-target"

    with pytest.raises(SystemExit):
        get_token(app, arguments)


def test_operator_rejects_owner_identifier_as_user_email(app):
    _owner(app)
    with app.app_context():
        owner = app.db.session.query(User).one()
        owner.fs_uniquifier = "owner-identifier@example.net"
        app.db.session.commit()
    arguments = _args("--scopes", "api")
    arguments[1] = "owner-identifier@example.net"

    with pytest.raises(ValueError, match="Credential owner not found"):
        get_token(app, arguments)

    with app.app_context():
        assert app.db.session.query(OAuth2Token).count() == 0


def test_operator_rejects_existing_output_before_rotation(app, tmp_path):
    _owner(app)
    first = get_token(app, _args("--scopes", "api"))
    output = tmp_path / "credential"
    output.write_text("do-not-overwrite\n")
    os.chmod(output, 0o600)
    with pytest.raises(FileExistsError):
        get_token(
            app,
            [
                "--user-email",
                "operator-target@example.org",
                "--name",
                "automation",
                "--scopes",
                "api",
                "--output",
                str(output),
            ],
        )
    assert output.read_text() == "do-not-overwrite\n"
    with app.app_context():
        assert app.auth_service.lookup_access_token(first) is not None
