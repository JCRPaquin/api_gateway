"""Issue operator bearers with recoverable, one-time credential delivery."""

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import stat
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from marshmallow import ValidationError as MarshmallowValidationError
from marshmallow import validate
from sqlalchemy.orm.exc import MultipleResultsFound

PROJECT_HOME = str(Path(__file__).resolve().parent.parent)
if PROJECT_HOME not in sys.path:
    sys.path.append(PROJECT_HOME)

from apigateway.app import create_app
from apigateway.domains import canonicalize_email
from apigateway.extensions import db
from apigateway.models import OAuth2Token, User


def _route_capacities(value):
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as error:
        raise argparse.ArgumentTypeError("route capacities must be JSON") from error
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("route capacities must be a JSON object")
    return parsed


def _canonical_email(value):
    try:
        canonical = canonicalize_email(value)
        validate.Email()(canonical)
    except (TypeError, ValueError, MarshmallowValidationError) as error:
        raise argparse.ArgumentTypeError("must be a valid email address") from error
    return canonical


def add_arguments(parser):
    parser.add_argument(
        "--user-email",
        required=True,
        type=_canonical_email,
        help="Existing active credential owner's email address",
    )
    parser.add_argument("--name", required=True, help="OAuth client display name")
    parser.add_argument("--scopes", nargs="+", help="Requested scopes")
    parser.add_argument(
        "--expires-in",
        type=int,
        help="Relative lifetime in seconds (maximum 30 days)",
    )
    parser.add_argument("--ratelimit", type=float, default=1.0)
    parser.add_argument(
        "--route-capacities",
        type=_route_capacities,
        help="JSON object keyed by exact registered Flask endpoint",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="'-' for stdout or a new mode-0600 file receiving only the raw token",
    )


class DatabaseIntegrityError(Exception):
    """The persisted delivery state cannot be reconciled safely."""


def _normalize_output_path(path):
    absolute_path = os.path.abspath(path)
    parent = os.path.realpath(os.path.dirname(absolute_path))
    return os.path.join(parent, os.path.basename(absolute_path))


def _pending_delivery_path(output_path):
    digest = hashlib.sha256(output_path.encode("utf-8")).hexdigest()
    return os.path.join(os.path.dirname(output_path), ".oauth-pending-" + digest)


def _delivery_lock_path(output_path):
    digest = hashlib.sha256(output_path.encode("utf-8")).hexdigest()
    return os.path.join(os.path.dirname(output_path), ".oauth-lock-" + digest)


@contextmanager
def _delivery_lock(output_path):
    lock_path = _delivery_lock_path(output_path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow, 0o600
        )
        os.fchmod(descriptor, 0o600)
    except FileExistsError:
        descriptor = os.open(lock_path, os.O_RDWR | nofollow)
    try:
        lock_stat = os.fstat(descriptor)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or stat.S_IMODE(lock_stat.st_mode) != 0o600
            or lock_stat.st_uid != os.geteuid()
        ):
            raise OSError("Credential delivery lock is not a safe mode-0600 file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def _safe_file_stat(path):
    try:
        path_stat = os.lstat(path)
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(path_stat.st_mode)
        or stat.S_IMODE(path_stat.st_mode) != 0o600
        or path_stat.st_uid != os.geteuid()
    ):
        raise OSError("Credential delivery entry is not a safe mode-0600 file")
    return path_stat


def _read_raw_token(path):
    path_stat = _safe_file_stat(path)
    if path_stat is None:
        return None, None
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        file_stat = os.fstat(descriptor)
        if (
            file_stat.st_dev != path_stat.st_dev
            or file_stat.st_ino != path_stat.st_ino
            or not stat.S_ISREG(file_stat.st_mode)
            or stat.S_IMODE(file_stat.st_mode) != 0o600
            or file_stat.st_uid != os.geteuid()
        ):
            raise OSError("Credential delivery entry changed during validation")
        with os.fdopen(descriptor, "rb") as output:
            descriptor = None
            payload = output.read(4097)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(payload) > 4096:
        raise OSError("Credential delivery entry is too large")
    try:
        raw_token = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise OSError("Credential delivery entry is not an ASCII bearer") from error
    if not raw_token.endswith("\n") or "\n" in raw_token[:-1]:
        raise OSError("Credential delivery entry is not one raw bearer")
    raw_token = raw_token[:-1]
    if not raw_token or raw_token.strip() != raw_token:
        raise OSError("Credential delivery entry contains an invalid bearer")
    return raw_token, path_stat


def _write_pending_credentials(pending_path, raw_token):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(pending_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write((raw_token + "\n").encode("ascii"))
            output.flush()
            os.fsync(output.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory(path):
    descriptor = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)




def _validate_delivery_token(app, token, raw_token):
    if token.client_id is None or token.client is None or token.user is None:
        raise DatabaseIntegrityError("Pending OAuth token has no owner or client")
    if token.credential_purpose != "operator":
        raise DatabaseIntegrityError("Pending credential has the wrong purpose")
    expected = app.auth_service.digest_access_token(raw_token, token.token_key_id)
    if not hmac.compare_digest(expected, token.access_token):
        raise OSError("Credential delivery content conflicts with pending token")


def _reconcile_delivery_files(app, token, output_path):
    pending_path = _pending_delivery_path(output_path)
    output_raw, output_stat = _read_raw_token(output_path)
    pending_raw, pending_stat = _read_raw_token(pending_path)
    if output_raw is not None:
        _validate_delivery_token(app, token, output_raw)
    if pending_raw is not None:
        _validate_delivery_token(app, token, pending_raw)

    if output_stat is not None and pending_stat is not None:
        if (
            output_stat.st_dev != pending_stat.st_dev
            or output_stat.st_ino != pending_stat.st_ino
            or output_stat.st_nlink != 2
            or pending_stat.st_nlink != 2
        ):
            raise OSError("Credential delivery entries do not form one safe pair")
        os.unlink(pending_path)
        _fsync_directory(output_path)
    elif output_stat is not None:
        if output_stat.st_nlink != 1:
            raise OSError("Credential output has an unexpected extra link")
    elif pending_stat is not None:
        if pending_stat.st_nlink != 1:
            raise OSError("Pending credential has an unexpected extra link")
        os.link(pending_path, output_path)
        linked_raw, linked_stat = _read_raw_token(output_path)
        if linked_raw != pending_raw or linked_stat.st_nlink != 2:
            raise OSError("Credential delivery link could not be verified")
        os.unlink(pending_path)
        _fsync_directory(output_path)
    else:
        raise OSError("Pending credential material is unavailable")

    completed_raw, completed_stat = _read_raw_token(output_path)
    _validate_delivery_token(app, token, completed_raw)
    if completed_stat.st_nlink != 1:
        raise OSError("Credential output did not reach a safe completed state")


def _deliver_pending_token(app, token_id, output_path, created_status):
    token = (
        db.session.query(OAuth2Token)
        .filter(OAuth2Token.id == token_id)
        .with_for_update()
        .one_or_none()
    )
    if token is None:
        db.session.rollback()
        raise DatabaseIntegrityError("Pending OAuth token disappeared")
    if not token.credential_delivery_pending:
        db.session.rollback()
        raise DatabaseIntegrityError("OAuth token is not pending delivery")
    expected_path = _normalize_output_path(token.credential_delivery_path or "")
    if expected_path != output_path:
        db.session.rollback()
        raise OSError("Pending credential delivery requires its original output path")

    try:
        _reconcile_delivery_files(app, token, output_path)
        token.credential_delivery_pending = False
        token.credential_delivery_path = None
        db.session.add(token)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return {
        "status": created_status,
        "expires_in": max(0, int(token.expires_at() - time.time())),
        "credential_output": output_path,
    }


def _resolve_owner_id(canonical_email):
    try:
        owner = db.session.query(User).filter_by(email=canonical_email).one_or_none()
    except MultipleResultsFound as error:
        raise DatabaseIntegrityError(
            "Multiple users found for the canonical email address"
        ) from error
    if owner is None:
        raise ValueError("Credential owner not found")
    return owner.fs_uniquifier


def _matching_pending_token(args, owner_id, output_path):
    pending = (
        db.session.query(OAuth2Token)
        .filter_by(
            credential_delivery_pending=True,
            credential_delivery_path=output_path,
        )
        .with_for_update()
        .all()
    )
    if len(pending) > 1:
        raise DatabaseIntegrityError("Multiple OAuth credentials await this delivery path")
    if not pending:
        return None
    token = pending[0]
    if token.client is None or token.user is None:
        raise DatabaseIntegrityError("Pending OAuth token has no owner or client")
    requested_scopes = set(args.scopes or token.scope.split())
    if (
        token.user_id != owner_id
        or token.client.user_id != owner_id
        or token.credential_purpose != "operator"
        or token.client.client_name != args.name
        or set(token.scope.split()) != requested_scopes
        or (args.expires_in is not None and token.expires_in != args.expires_in)
        or token.client.ratelimit_multiplier != args.ratelimit
        or (token.client.individual_ratelimit_multipliers or {})
        != (args.route_capacities or {})
    ):
        raise DatabaseIntegrityError("Pending delivery does not match this request")
    return token


def _get_file_token(app, args, owner_id, output_path):
    pending_path = _pending_delivery_path(output_path)
    pending = _matching_pending_token(args, owner_id, output_path)
    if pending is not None:
        return _deliver_pending_token(app, pending.id, output_path, "delivered")
    db.session.rollback()

    if _safe_file_stat(pending_path) is not None:
        raise DatabaseIntegrityError(
            "Pending credential has no confirmed database row; preserve the "
            "file until an operator verifies that no transaction can commit "
            "and no matching digest or pending row exists"
        )
    if _safe_file_stat(output_path) is not None:
        raise FileExistsError(output_path)
    prepared = False

    def prepare_delivery(issued):
        nonlocal prepared
        _write_pending_credentials(pending_path, issued.access_token)
        _fsync_directory(pending_path)
        prepared = True

    try:
        issued = app.auth_service.issue_credential(
            owner_id,
            purpose="operator",
            scopes=args.scopes,
            expires_in=args.expires_in,
            client_name=args.name,
            ratelimit_multiplier=args.ratelimit,
            individual_ratelimit_multipliers=args.route_capacities,
            credential_delivery_path=output_path,
            prepare_delivery=prepare_delivery,
        )
    except Exception as issue_error:
        if not prepared:
            raise
        try:
            db.session.rollback()
        except Exception:
            pass
        raise DatabaseIntegrityError(
            "Credential issuance outcome is uncertain; the pending bearer "
            "was preserved for operator recovery"
        ) from issue_error
    return _deliver_pending_token(app, issued.token.id, output_path, "created")


def get_token(app=None, argv=None):
    """Issue or recover one operator bearer without persisting its raw value."""
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    args = parser.parse_args(argv)
    if not args.name.strip() or args.name != args.name.strip():
        parser.error("--name must be nonempty without surrounding whitespace")

    app = app or create_app()
    with app.app_context():
        owner_id = _resolve_owner_id(args.user_email)
        if args.output == "-":
            issued = app.auth_service.issue_credential(
                owner_id,
                purpose="operator",
                scopes=args.scopes,
                expires_in=args.expires_in,
                client_name=args.name,
                ratelimit_multiplier=args.ratelimit,
                individual_ratelimit_multipliers=args.route_capacities,
            )
            return issued.access_token

        output_path = _normalize_output_path(args.output)
        with _delivery_lock(output_path):
            return _get_file_token(app, args, owner_id, output_path)


def main(argv=None):
    result = get_token(argv=argv)
    if isinstance(result, str):
        sys.stdout.write(result + "\n")
    else:
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()