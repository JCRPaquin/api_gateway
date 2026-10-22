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


def test_operator_main_creates_exclusive_mode_0600_file(monkeypatch, tmp_path):
    monkeypatch.setattr(
        generate_oauth_client, "get_token", lambda app=None, argv=None: "file-canary"
    )
    output = tmp_path / "credential"
    arguments = [
        "--user-email",
        "operator-target@example.org",
        "--name",
        "automation",
        "--output",
        str(output),
    ]
    generate_oauth_client.main(arguments)
    assert output.read_text() == "file-canary\n"
    assert os.stat(output).st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        generate_oauth_client.main(arguments)
