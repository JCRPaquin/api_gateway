import base64
import json
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

import requests
import sqlalchemy as sa
from flask import current_app
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from apigateway import email_templates, extensions
from apigateway.config import canonical_authority
from apigateway.domains import canonicalize_email
from apigateway.exceptions import AccountActionTokenError
from apigateway.models import AccountActionToken, NotificationOutbox, User
from apigateway.utils import DeliveryResult, DeliveryState, send_email, send_feedback_email


ACCOUNT_ACCEPTED_MESSAGE = "Request accepted. If the account is eligible, an email will be sent."
_ACTIVE_STATES = ("pending", "retry", "processing")
_TEMPLATE_TYPES = {
    "EmailChangedNotification": email_templates.EmailChangedNotification,
    "AccountRegistrationAttemptEmail": email_templates.AccountRegistrationAttemptEmail,
}


def request_environment(host: str) -> dict:
    authority = canonical_authority(host)
    try:
        site = current_app.config["SITE_HOST_MAPPING"][authority]
    except KeyError as exc:
        raise ValueError("Untrusted request authority") from exc
    if site == "SCIX":
        return {
            "ui_env": "SciX",
            "ui_url": current_app.config["SCIX_HOST_DOMAIN"],
            "verify_url": current_app.config["SCIX_VERIFY_URL"],
        }
    return {
        "ui_env": "ADS",
        "ui_url": current_app.config["ADS_HOST_DOMAIN"],
        "verify_url": current_app.config["VERIFY_URL"],
    }


def _payload_size(payload: dict) -> int:
    return len(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    )

def _contains_forbidden_payload_key(value) -> bool:
    if isinstance(value, dict):
        if any(
            str(key).lower() in {"password", "password_hash", "token", "verification_url"}
            for key in value
        ):
            return True
        return any(_contains_forbidden_payload_key(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_payload_key(child) for child in value)
    return False




def enqueue_notification(
    event_type: str,
    payload: dict,
    dedupe_key: str = None,
    session=None,
    commit: bool = True,
    replace: bool = False,
) -> DeliveryResult:
    session = session or extensions.db.session
    channel = "slack" if event_type == "feedback_slack" else "email"
    if event_type not in {"feedback_email", "feedback_slack"} and _contains_forbidden_payload_key(
        payload
    ):
        return DeliveryResult(channel, DeliveryState.REJECTED, "sensitive_payload")
    try:
        if session.get_bind().dialect.name == "postgresql":
            session.execute(
                sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": 0x4E4F54494659}
            )
        encoded_size = _payload_size(payload)
        existing = None
        if dedupe_key:
            existing = session.query(NotificationOutbox).filter_by(dedupe_key=dedupe_key).first()
        if existing is not None:
            if not replace:
                if commit:
                    session.commit()
                return DeliveryResult(channel, DeliveryState.QUEUED, "coalesced")
            if existing.state == "processing":
                existing.dedupe_key = None
                existing = None
                previous_size = 0
            else:
                previous_size = existing.payload_size
        else:
            previous_size = 0

        pending_count, active_bytes = session.query(
            func.count(NotificationOutbox.id),
            func.coalesce(func.sum(NotificationOutbox.payload_size), 0),
        ).filter(NotificationOutbox.state.in_(_ACTIVE_STATES)).one()
        if existing is None and pending_count >= current_app.config.get(
            "MAIL_OUTBOX_MAX_PENDING", 10_000
        ):
            if commit:
                session.rollback()
            return DeliveryResult(channel, DeliveryState.REJECTED, "outbox_full")
        if active_bytes - previous_size + encoded_size > current_app.config.get(
            "MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES", 33_554_432
        ):
            if commit:
                session.rollback()
            return DeliveryResult(channel, DeliveryState.REJECTED, "outbox_payload_full")

        if existing is None:
            existing = NotificationOutbox(dedupe_key=dedupe_key)
            session.add(existing)
        existing.event_type = event_type
        existing.payload = payload
        existing.payload_size = encoded_size
        existing.state = "pending"
        existing.available_at = datetime.utcnow()
        existing.claimed_at = None
        existing.ownership_token = None
        existing.terminal_at = None
        existing.last_error = None
        if replace:
            existing.attempts = 0
        if commit:
            session.commit()
        else:
            session.flush()
        return DeliveryResult(channel, DeliveryState.QUEUED, "queued")
    except IntegrityError:
        session.rollback()
        return DeliveryResult(channel, DeliveryState.RETRYABLE_FAILURE, "outbox_conflict")
    except Exception:
        session.rollback()
        current_app.logger.exception("Notification enqueue failed")
        return DeliveryResult(channel, DeliveryState.RETRYABLE_FAILURE, "outbox_unavailable")


def enqueue_template_email(
    recipient: str,
    template,
    ui_env: str = "ADS",
    ui_url: str = "https://ui.adsabs.harvard.edu",
    dedupe_key: str = None,
    session=None,
    commit: bool = True,
    replace: bool = False,
) -> DeliveryResult:
    try:
        canonical = canonicalize_email(recipient)
    except ValueError:
        return DeliveryResult("email", DeliveryState.REJECTED, "invalid_recipient")
    return enqueue_notification(
        "template_email",
        {
            "recipient": canonical,
            "template": template.__name__,
            "ui_env": ui_env,
            "ui_url": ui_url,
        },
        dedupe_key=dedupe_key,
        session=session,
        commit=commit,
        replace=replace,
    )


def enqueue_account_request(event_type: str, email: str, host: str) -> DeliveryResult:
    try:
        canonical = canonicalize_email(email)
    except ValueError:
        return DeliveryResult("email", DeliveryState.REJECTED, "invalid_recipient")
    return enqueue_notification(
        event_type,
        {"email": canonical, **request_environment(host)},
        dedupe_key=f"{event_type}:{canonical}",
    )


def enqueue_feedback_notifications(
    submitter_name: str,
    submitter_email: str,
    subject: str,
    body: str,
    attachments: list,
    slack_payload: dict,
) -> tuple[DeliveryResult, DeliveryResult]:
    session = extensions.db.session
    try:
        canonical_submitter = canonicalize_email(submitter_email)
    except ValueError:
        rejected = DeliveryResult("email", DeliveryState.REJECTED, "invalid_recipient")
        return rejected, DeliveryResult(
            "slack", DeliveryState.REJECTED, "transaction_rejected"
        )
    try:
        email_result = enqueue_notification(
            "feedback_email",
            {
                "submitter_name": submitter_name,
                "submitter_email": canonical_submitter,
                "subject": subject,
                "body": body,
                "attachments": [
                    {
                        "filename": filename,
                        "content": base64.b64encode(content).decode("ascii"),
                    }
                    for filename, content in attachments
                ],
            },
            session=session,
            commit=False,
        )
        if email_result.state != DeliveryState.QUEUED:
            session.rollback()
            return email_result, DeliveryResult(
                "slack", DeliveryState.REJECTED, "transaction_rejected"
            )
        slack_result = enqueue_notification(
            "feedback_slack", slack_payload, session=session, commit=False
        )
        if slack_result.state != DeliveryState.QUEUED:
            session.rollback()
            return DeliveryResult("email", DeliveryState.REJECTED, "transaction_rejected"), slack_result
        session.commit()
        return email_result, DeliveryResult("slack", DeliveryState.QUEUED, "queued")
    except Exception:
        session.rollback()
        current_app.logger.exception("Feedback notification enqueue failed")
        failure = DeliveryResult("email", DeliveryState.RETRYABLE_FAILURE, "outbox_unavailable")
        return failure, DeliveryResult("slack", DeliveryState.RETRYABLE_FAILURE, "outbox_unavailable")


def _send_slack(payload: dict) -> DeliveryResult:
    endpoint = current_app.config.get("FEEDBACK_SLACK_END_POINT")
    if not endpoint:
        return DeliveryResult("slack", DeliveryState.PERMANENT_FAILURE, "not_configured")
    try:
        response = requests.post(
            endpoint,
            json=payload,
            timeout=current_app.config.get("FEEDBACK_SLACK_TIMEOUT_SECONDS", 5),
            allow_redirects=False,
        )
    except requests.exceptions.RequestException:
        return DeliveryResult("slack", DeliveryState.RETRYABLE_FAILURE, "transport_error")
    if response.status_code == 200:
        return DeliveryResult("slack", DeliveryState.SENT, "sent")
    if response.status_code >= 500:
        return DeliveryResult("slack", DeliveryState.RETRYABLE_FAILURE, "remote_error")
    return DeliveryResult("slack", DeliveryState.PERMANENT_FAILURE, "remote_rejected")


def _prepare_password_reset(job_id: int, ownership: str) -> DeliveryResult | None:
    """Commit the reset action before making its delivery job claimable."""
    session = extensions.db.session
    job = (
        session.query(NotificationOutbox)
        .filter_by(id=job_id, state="processing", ownership_token=ownership)
        .with_for_update()
        .first()
    )
    if job is None:
        session.rollback()
        return None

    payload = job.payload
    user = (
        session.query(User)
        .filter_by(email=canonicalize_email(payload["email"]))
        .with_for_update()
        .first()
    )
    if (
        user is None
        or user.is_anonymous_bootstrap_user
        or not user.active
        or not user.confirmed_at
    ):
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "account_ineligible")

    # The user lock serializes replacement with delivery. The persisted action
    # contains only a digest; its bearer is deterministically derived in memory.
    token = extensions.security_service.issue_account_action_token(
        session,
        user_id=user.id,
        purpose="password_reset",
        target_email=str(user.email),
    )
    action = (
        session.query(AccountActionToken)
        .filter_by(
            token_digest=extensions.security_service.account_action_token_digest(token)
        )
        .one()
    )

    delivery_payload = {
        "action_id": action.delivery_id,
        "ui_env": payload["ui_env"],
        "ui_url": payload["ui_url"],
        "verify_url": payload["verify_url"],
    }
    delivery_size = _payload_size(delivery_payload)
    active_bytes = (
        session.query(func.coalesce(func.sum(NotificationOutbox.payload_size), 0))
        .filter(NotificationOutbox.state.in_(_ACTIVE_STATES))
        .scalar()
    )
    if active_bytes - job.payload_size + delivery_size > current_app.config.get(
        "MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES", 33_554_432
    ):
        session.rollback()
        return DeliveryResult(
            "email", DeliveryState.RETRYABLE_FAILURE, "outbox_payload_full"
        )

    job.event_type = "password_reset_action"
    job.payload = delivery_payload
    job.payload_size = delivery_size
    job.state = "pending"
    job.attempts = 0
    job.available_at = datetime.utcnow()
    job.claimed_at = None
    job.ownership_token = None
    job.last_error = None
    job.dedupe_key = f"password-reset-delivery:{action.delivery_id}"
    session.commit()
    return None


def _prepare_verification_resend(
    job_id: int, ownership: str
) -> DeliveryResult | None:
    """Replace an unconfirmed account's verification action before delivery."""
    session = extensions.db.session
    job = (
        session.query(NotificationOutbox)
        .filter_by(id=job_id, state="processing", ownership_token=ownership)
        .with_for_update()
        .first()
    )
    if job is None:
        session.rollback()
        return None

    payload = job.payload
    user = (
        session.query(User)
        .filter_by(email=canonicalize_email(payload["email"]))
        .with_for_update()
        .first()
    )
    if (
        user is None
        or user.is_anonymous_bootstrap_user
        or not user.active
        or user.confirmed_at is not None
    ):
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "account_ineligible")

    previous_action = (
        session.query(AccountActionToken)
        .filter_by(user_id=user.id, purpose="verify_registration")
        .with_for_update()
        .first()
    )
    if previous_action is not None:
        previous_job = (
            session.query(NotificationOutbox)
            .filter_by(
                dedupe_key=(
                    f"account-action-delivery:{previous_action.delivery_id}"
                )
            )
            .with_for_update()
            .first()
        )
        if previous_job is not None and previous_job.state in ("pending", "retry"):
            previous_job.state = "suppressed"
            previous_job.payload = {}
            previous_job.payload_size = 0
            previous_job.claimed_at = None
            previous_job.ownership_token = None
            previous_job.dedupe_key = None
            previous_job.terminal_at = datetime.utcnow()
            previous_job.last_error = "action_replaced"


    extensions.security_service.issue_account_action_token(
        session,
        user_id=user.id,
        purpose="verify_registration",
        target_email=str(user.email),
    )
    action = session.query(AccountActionToken).filter_by(
        user_id=user.id, purpose="verify_registration"
    ).one()
    delivery_payload = {
        "action_id": action.delivery_id,
        "ui_env": payload["ui_env"],
        "ui_url": payload["ui_url"],
        "verify_url": payload["verify_url"],
    }
    delivery_size = _payload_size(delivery_payload)
    active_bytes = (
        session.query(func.coalesce(func.sum(NotificationOutbox.payload_size), 0))
        .filter(NotificationOutbox.state.in_(_ACTIVE_STATES))
        .scalar()
    )
    if active_bytes - job.payload_size + delivery_size > current_app.config.get(
        "MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES", 33_554_432
    ):
        session.rollback()
        return DeliveryResult(
            "email", DeliveryState.RETRYABLE_FAILURE, "outbox_payload_full"
        )

    job.event_type = "account_action_delivery"
    job.payload = delivery_payload
    job.payload_size = delivery_size
    job.state = "pending"
    job.attempts = 0
    job.available_at = datetime.utcnow()
    job.claimed_at = None
    job.ownership_token = None
    job.last_error = None
    job.dedupe_key = f"account-action-delivery:{action.delivery_id}"
    session.commit()
    return None


def _account_action_url(verify_url: str, purpose: str, token: str) -> str:
    """Build the UI fragment; the UI submits its token only in an API JSON body."""
    flow = "register" if purpose == "verify_registration" else "change-email"
    parsed = urlsplit(verify_url)
    prefix = parsed.fragment.rstrip("/")
    fragment = f"{prefix}/{flow}/{token}" if prefix else f"{flow}/{token}"
    return urlunsplit(parsed._replace(fragment=fragment))


def _deliver_email_account_action(payload: dict) -> DeliveryResult:
    """Lock and deliver only the exact current registration/email-change action."""
    session = extensions.db.session
    candidate = (
        session.query(AccountActionToken.user_id, AccountActionToken.purpose)
        .filter_by(delivery_id=payload["action_id"])
        .first()
    )
    if candidate is None or candidate.purpose not in {
        "verify_registration",
        "change_email",
    }:
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_missing")
    user = (
        session.query(User)
        .filter_by(id=candidate.user_id)
        .with_for_update()
        .first()
    )
    if user is None:
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_missing")
    action = (
        session.query(AccountActionToken)
        .filter_by(delivery_id=payload["action_id"], purpose=candidate.purpose)
        .with_for_update()
        .first()
    )
    if action is None or action.user_id != user.id:
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_missing")
    try:
        token = extensions.security_service.derive_account_action_token(action)
        extensions.security_service.verify_account_action_token(
            session, token, action.purpose
        )
        current_email = extensions.security_service.normalize_account_email(
            str(user.email)
        )
        if (
            not user.active
            or user.is_anonymous_bootstrap_user
            or (
                action.purpose == "verify_registration"
                and (
                    user.confirmed_at is not None
                    or action.target_email != current_email
                )
            )
            or (
                action.purpose == "change_email"
                and (
                    user.confirmed_at is None
                    or action.target_email == current_email
                    or session.query(User.id)
                    .filter(
                        User.email == action.target_email,
                        User.id != user.id,
                    )
                    .first()
                    is not None
                )
            )
        ):
            raise AccountActionTokenError()
    except (AccountActionTokenError, TypeError, ValueError):
        return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_invalid")

    template = (
        email_templates.WelcomeVerificationEmail
        if action.purpose == "verify_registration"
        else email_templates.VerificationEmail
    )
    recipient = (
        current_email
        if action.purpose == "verify_registration"
        else action.target_email
    )
    return send_email(
        current_app.config["MAIL_DEFAULT_SENDER"],
        recipient,
        template,
        verification_url=_account_action_url(
            payload["verify_url"], action.purpose, token
        ),
        ui_env=payload["ui_env"],
        ui_url=payload["ui_url"],
    )


def _password_reset_url(verify_url: str, token: str) -> str:
    parsed = urlsplit(verify_url)
    prefix = parsed.fragment.rstrip("/")
    fragment = f"{prefix}/reset-password/{token}" if prefix else f"reset-password/{token}"
    return urlunsplit(parsed._replace(fragment=fragment))


def _deliver(job: NotificationOutbox) -> DeliveryResult:
    payload = job.payload
    session = extensions.db.session
    if job.event_type == "template_email":
        template = _TEMPLATE_TYPES.get(payload.get("template"))
        if template is None:
            return DeliveryResult("email", DeliveryState.REJECTED, "unknown_template")
        return send_email(
            current_app.config["MAIL_DEFAULT_SENDER"],
            payload["recipient"],
            template,
            ui_env=payload["ui_env"],
            ui_url=payload["ui_url"],
        )
    if job.event_type == "password_reset_action":
        candidate = (
            session.query(AccountActionToken)
            .filter_by(delivery_id=payload["action_id"], purpose="password_reset")
            .first()
        )
        if candidate is None:
            return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_missing")
        user = (
            session.query(User)
            .filter_by(id=candidate.user_id)
            .with_for_update()
            .first()
        )
        if user is None:
            return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_missing")
        action = (
            session.query(AccountActionToken)
            .filter_by(delivery_id=payload["action_id"], purpose="password_reset")
            .with_for_update()
            .first()
        )
        if action is None or action.user_id != user.id:
            return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_missing")
        try:
            token = extensions.security_service.derive_account_action_token(action)
            extensions.security_service.verify_account_action_token(
                session, token, "password_reset"
            )
        except AccountActionTokenError:
            return DeliveryResult("email", DeliveryState.SUPPRESSED, "action_invalid")
        return send_email(
            current_app.config["MAIL_DEFAULT_SENDER"],
            user.email,
            email_templates.PasswordResetEmail,
            verification_url=_password_reset_url(payload["verify_url"], token),
            ui_env=payload["ui_env"],
            ui_url=payload["ui_url"],
        )
    if job.event_type == "account_action_delivery":
        return _deliver_email_account_action(payload)
    if job.event_type == "feedback_email":
        attachments = [
            (item["filename"], base64.b64decode(item["content"], validate=True))
            for item in payload.get("attachments", [])
        ]
        return send_feedback_email(
            payload["submitter_name"], payload["submitter_email"], payload["subject"],
            payload["body"], attachments
        )
    if job.event_type == "feedback_slack":
        return _send_slack(payload)
    return DeliveryResult("email", DeliveryState.REJECTED, "unknown_event")


def claim_notification() -> tuple[int, str] | None:
    session = extensions.db.session
    now = datetime.utcnow()
    stale = now - timedelta(seconds=current_app.config.get("MAIL_OUTBOX_LEASE_SECONDS", 120))
    try:
        query = session.query(NotificationOutbox).filter(
            or_(
                sa.and_(NotificationOutbox.state.in_(("pending", "retry")), NotificationOutbox.available_at <= now),
                sa.and_(NotificationOutbox.state == "processing", NotificationOutbox.claimed_at < stale),
            )
        ).order_by(NotificationOutbox.id).limit(1)
        if session.get_bind().dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        job = query.first()
        if job is None:
            session.rollback()
            return None
        ownership = str(uuid.uuid4())
        job.state = "processing"
        job.claimed_at = now
        job.ownership_token = ownership
        job.attempts += 1
        job_id = job.id
        session.commit()
        return job_id, ownership
    except Exception:
        session.rollback()
        current_app.logger.exception("Notification claim failed")
        return None


def _finish(job_id: int, ownership: str, result: DeliveryResult) -> bool:
    session = extensions.db.session
    job = session.query(NotificationOutbox).filter_by(
        id=job_id, state="processing", ownership_token=ownership
    ).with_for_update().first()
    if job is None:
        session.rollback()
        return False
    now = datetime.utcnow()
    max_attempts = current_app.config.get("MAIL_OUTBOX_MAX_ATTEMPTS", 5)
    if result.state == DeliveryState.RETRYABLE_FAILURE and job.attempts < max_attempts:
        delays = current_app.config.get(
            "MAIL_OUTBOX_RETRY_DELAYS_SECONDS", [60, 300, 1800, 7200]
        ) or [60]
        delay = delays[min(max(job.attempts - 1, 0), len(delays) - 1)]
        job.state = "retry"
        job.available_at = now + timedelta(seconds=delay)
    else:
        job.state = (
            "sent" if result.state == DeliveryState.SENT
            else "suppressed" if result.state == DeliveryState.SUPPRESSED
            else "dead"
        )
        job.payload = {}
        job.payload_size = 0
        job.dedupe_key = None
        job.terminal_at = now
    job.last_error = result.reason
    job.claimed_at = None
    job.ownership_token = None
    session.commit()
    return True


def process_outbox_batch() -> int:
    processed = 0
    batch = current_app.config.get("MAIL_OUTBOX_CLAIM_BATCH", 50)
    for _ in range(batch):
        claim = claim_notification()
        if claim is None:
            break
        job_id, ownership = claim
        try:
            job = extensions.db.session.query(NotificationOutbox).filter_by(
                id=job_id, state="processing", ownership_token=ownership
            ).first()
            if job is None:
                extensions.db.session.rollback()
                continue
            if job.event_type in {
                "password_reset_request",
                "verification_resend_request",
            }:
                prepare = (
                    _prepare_password_reset
                    if job.event_type == "password_reset_request"
                    else _prepare_verification_resend
                )
                result = prepare(job_id, ownership)
                if result is not None:
                    _finish(job_id, ownership, result)
                processed += 1
                continue
            result = _deliver(job)
            if result.state not in (DeliveryState.SENT, DeliveryState.SUPPRESSED):
                extensions.db.session.rollback()
            _finish(job_id, ownership, result)
        except Exception:
            extensions.db.session.rollback()
            current_app.logger.exception("Notification delivery failed", extra={"job_id": job_id})
            try:
                _finish(
                    job_id, ownership,
                    DeliveryResult("notification", DeliveryState.RETRYABLE_FAILURE, "worker_error")
                )
            except Exception:
                extensions.db.session.rollback()
                current_app.logger.exception("Notification failure state update failed", extra={"job_id": job_id})
        processed += 1
    return processed


def cleanup_terminal_notifications() -> int:
    session = extensions.db.session
    now = datetime.utcnow()
    terminal_before = now - timedelta(
        seconds=current_app.config.get("MAIL_OUTBOX_TERMINAL_RETENTION_SECONDS", 604_800)
    )
    dead_before = now - timedelta(
        seconds=current_app.config.get("MAIL_OUTBOX_DEAD_RETENTION_SECONDS", 86_400)
    )
    ids = [
        row[0]
        for row in session.query(NotificationOutbox.id).filter(
            or_(
                sa.and_(NotificationOutbox.state.in_(("sent", "suppressed")), NotificationOutbox.terminal_at < terminal_before),
                sa.and_(NotificationOutbox.state == "dead", NotificationOutbox.terminal_at < dead_before),
            )
        ).order_by(NotificationOutbox.id).limit(
            current_app.config.get("MAIL_OUTBOX_CLEANUP_BATCH", 1000)
        ).all()
    ]
    if ids:
        session.query(NotificationOutbox).filter(NotificationOutbox.id.in_(ids)).delete(
            synchronize_session=False
        )
    session.commit()
    return len(ids)
