from datetime import datetime, timedelta
from unittest import mock
from urllib.parse import urlsplit

import pytest

from apigateway import notifications
from apigateway.email_templates import (
    AccountRegistrationAttemptEmail,
    VerificationEmail,
    WelcomeVerificationEmail,
)
from apigateway.models import AccountActionToken, NotificationOutbox, User
from apigateway.utils import DeliveryResult, DeliveryState


def test_terminal_delivery_scrubs_payload_and_dedupe_key(app):
    result = notifications.enqueue_template_email(
        "recipient@example.org",
        AccountRegistrationAttemptEmail,
        dedupe_key="registration-attempt:1",
    )
    assert result.state == DeliveryState.QUEUED

    sent = DeliveryResult("email", DeliveryState.SENT, "sent")
    with mock.patch.object(notifications, "send_email", return_value=sent):
        assert notifications.process_outbox_batch() == 1

    job = app.db.session.query(NotificationOutbox).one()
    assert job.state == "sent"
    assert job.payload == {}
    assert job.payload_size == 0
    assert job.dedupe_key is None
    assert job.terminal_at is not None
    assert job.ownership_token is None


def test_retryable_delivery_failure_remains_visible_and_scheduled(app):
    notifications.enqueue_template_email(
        "recipient@example.org",
        AccountRegistrationAttemptEmail,
    )
    failure = DeliveryResult("email", DeliveryState.RETRYABLE_FAILURE, "transport_error")
    with mock.patch.object(notifications, "send_email", return_value=failure):
        notifications.process_outbox_batch()

    job = app.db.session.query(NotificationOutbox).one()
    assert job.state == "retry"
    assert job.attempts == 1
    assert job.last_error == "transport_error"
    assert job.available_at > job.created_at
    assert job.payload["recipient"] == "recipient@example.org"


def test_active_payload_byte_quota_rejects_before_insert(app):
    original = app.config["MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES"]
    app.config["MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES"] = 8
    result = notifications.enqueue_notification("template_email", {"value": "too large"})
    app.config["MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES"] = original

    assert result.state == DeliveryState.REJECTED
    assert result.reason == "outbox_payload_full"
    assert app.db.session.query(NotificationOutbox).count() == 0


def test_sensitive_account_payload_is_never_persisted(app):
    result = notifications.enqueue_notification(
        "template_email",
        {"recipient": "person@example.org", "password_hash": "secret"},
    )

    assert result.state == DeliveryState.REJECTED
    assert result.reason == "sensitive_payload"
    assert app.db.session.query(NotificationOutbox).count() == 0


def test_stale_owner_cannot_finalize_reclaimed_job(app):
    job = NotificationOutbox(
        event_type="template_email",
        payload={},
        payload_size=2,
        state="processing",
        ownership_token="new-owner",
    )
    app.db.session.add(job)
    app.db.session.commit()
    sent = DeliveryResult("email", DeliveryState.SENT, "sent")

    assert notifications._finish(job.id, "old-owner", sent) is False
    assert notifications._finish(job.id, "new-owner", sent) is True
    app.db.session.refresh(job)
    assert job.state == "sent"


def test_feedback_email_and_slack_are_enqueued_atomically(app):
    slack = {"text": "safe", "username": "configured", "mrkdwn": False}
    with mock.patch.object(notifications.requests, "post") as post:
        email, slack_result = notifications.enqueue_feedback_notifications(
            "Researcher",
            "person@example.org",
            "Feedback",
            "body",
            [("record.json", b"{}")],
            slack,
        )

    assert email.state == DeliveryState.QUEUED
    assert slack_result.state == DeliveryState.QUEUED
    assert app.db.session.query(NotificationOutbox).count() == 2
    assert {row.event_type for row in app.db.session.query(NotificationOutbox)} == {
        "feedback_email",
        "feedback_slack",
    }
    post.assert_not_called()


def test_poison_job_does_not_block_later_job(app):
    notifications.enqueue_notification("unknown", {})
    notifications.enqueue_template_email("recipient@example.org", AccountRegistrationAttemptEmail)
    sent = DeliveryResult("email", DeliveryState.SENT, "sent")

    with mock.patch.object(notifications, "send_email", return_value=sent):
        assert notifications.process_outbox_batch() == 2

    states = [row.state for row in app.db.session.query(NotificationOutbox).order_by(NotificationOutbox.id)]
    assert states == ["dead", "sent"]


def _confirmed_user(app, email="reset@example.org"):
    user = User(
        email=email,
        fs_uniquifier=f"reset-{email}",
        active=True,
        confirmed_at=datetime.utcnow(),
    )
    app.db.session.add(user)
    app.db.session.commit()
    return user


def test_password_reset_commits_action_before_smtp_and_recovers_after_acceptance(app):
    user = _confirmed_user(app)
    result = notifications.enqueue_account_request(
        "password_reset_request", user.email, "localhost"
    )
    assert result.state == DeliveryState.QUEUED

    original_batch = app.config["MAIL_OUTBOX_CLAIM_BATCH"]
    app.config["MAIL_OUTBOX_CLAIM_BATCH"] = 1
    try:
        claim = notifications.claim_notification()
        real_commit = notifications.extensions.db.session.commit

        def commit_then_crash():
            real_commit()
            raise RuntimeError("injected crash after action commit")

        with mock.patch.object(
            notifications.extensions.db.session,
            "commit",
            side_effect=commit_then_crash,
        ), mock.patch.object(notifications, "send_email") as send:
            with pytest.raises(RuntimeError, match="after action commit"):
                notifications._prepare_password_reset(*claim)
        send.assert_not_called()

        action = app.db.session.query(AccountActionToken).one()
        assert not hasattr(action, "token")
        job = app.db.session.query(NotificationOutbox).one()
        assert job.event_type == "password_reset_action"
        assert job.state == "pending"
        assert job.payload == {
            "action_id": action.delivery_id,
            **notifications.request_environment("localhost"),
        }
        assert job.dedupe_key == f"password-reset-delivery:{action.delivery_id}"
        assert all("token" not in str(value) for value in job.payload.values())

        # Simulate process loss after SMTP acceptance but before the outbox
        # finalization commit. The committed action remains the source of truth.
        job_id, ownership = notifications.claim_notification()
        claimed = app.db.session.query(NotificationOutbox).filter_by(id=job_id).one()
        accepted = DeliveryResult("email", DeliveryState.SENT, "sent")
        with mock.patch.object(
            notifications, "send_email", return_value=accepted
        ) as send:
            assert notifications._deliver(claimed) == accepted
        accepted_url = send.call_args.kwargs["verification_url"]
        token = urlsplit(accepted_url).fragment.rsplit("/", 1)[1]
        verified_user, verified_action = app.security_service.verify_account_action_token(
            app.db.session, token, "password_reset"
        )
        assert verified_user.id == user.id
        assert verified_action.delivery_id == action.delivery_id
        app.db.session.rollback()

        claimed = app.db.session.query(NotificationOutbox).filter_by(id=job_id).one()
        assert accepted_url not in str(claimed.payload)
        claimed.claimed_at = datetime.utcnow() - timedelta(
            seconds=app.config["MAIL_OUTBOX_LEASE_SECONDS"] + 1
        )
        app.db.session.commit()
        with mock.patch.object(notifications, "send_email", return_value=accepted):
            assert notifications.process_outbox_batch() == 1

        terminal = app.db.session.query(NotificationOutbox).filter_by(id=job_id).one()
        assert terminal.state == "sent"
        assert terminal.payload == {}
        assert terminal.dedupe_key is None
    finally:
        app.config["MAIL_OUTBOX_CLAIM_BATCH"] = original_batch


def test_superseded_password_reset_delivery_is_suppressed(app):
    user = _confirmed_user(app, "stale-reset@example.org")
    original_batch = app.config["MAIL_OUTBOX_CLAIM_BATCH"]
    app.config["MAIL_OUTBOX_CLAIM_BATCH"] = 1
    try:
        notifications.enqueue_account_request(
            "password_reset_request", user.email, "localhost"
        )
        notifications.process_outbox_batch()
        first_job = app.db.session.query(NotificationOutbox).one()
        first_action_id = first_job.payload["action_id"]

        claim = notifications.claim_notification()
        retryable = DeliveryResult(
            "email", DeliveryState.RETRYABLE_FAILURE, "transport_error"
        )
        assert notifications._finish(*claim, retryable)

        notifications.enqueue_account_request(
            "password_reset_request", user.email, "localhost"
        )
        notifications.process_outbox_batch()
        current_action = app.db.session.query(AccountActionToken).one()
        assert current_action.delivery_id != first_action_id

        first_job = app.db.session.query(NotificationOutbox).filter_by(
            id=first_job.id
        ).one()
        first_job.available_at = datetime.utcnow()
        app.db.session.commit()
        with mock.patch.object(notifications, "send_email") as send:
            notifications.process_outbox_batch()

        send.assert_not_called()
        app.db.session.refresh(first_job)
        assert first_job.state == "suppressed"
        assert first_job.payload == {}
    finally:
        app.config["MAIL_OUTBOX_CLAIM_BATCH"] = original_batch


def test_consumed_password_reset_delivery_is_suppressed(app):
    user = _confirmed_user(app, "consumed-reset@example.org")
    notifications.enqueue_account_request(
        "password_reset_request", user.email, "localhost"
    )
    request_claim = notifications.claim_notification()
    assert notifications._prepare_password_reset(*request_claim) is None
    job = app.db.session.query(NotificationOutbox).one()
    action = app.db.session.query(AccountActionToken).one()
    app.db.session.delete(action)
    app.db.session.commit()

    delivery_claim = notifications.claim_notification()
    claimed = app.db.session.query(NotificationOutbox).filter_by(
        id=delivery_claim[0]
    ).one()
    with mock.patch.object(notifications, "send_email") as send:
        result = notifications._deliver(claimed)

    assert result == DeliveryResult(
        "email", DeliveryState.SUPPRESSED, "action_missing"
    )
    send.assert_not_called()
    assert notifications._finish(*delivery_claim, result)
    app.db.session.refresh(job)
    assert job.state == "suppressed"
    assert job.payload == {}




def test_password_reset_stage_quota_failure_rolls_back_action(app):
    user = _confirmed_user(app, "quota-reset@example.org")
    notifications.enqueue_account_request(
        "password_reset_request", user.email, "localhost"
    )
    claim = notifications.claim_notification()
    original_limit = app.config["MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES"]
    app.config["MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES"] = 0
    try:
        result = notifications._prepare_password_reset(*claim)
        assert result == DeliveryResult(
            "email", DeliveryState.RETRYABLE_FAILURE, "outbox_payload_full"
        )
        assert notifications._finish(*claim, result)
    finally:
        app.config["MAIL_OUTBOX_MAX_ACTIVE_PAYLOAD_BYTES"] = original_limit

    assert app.db.session.query(AccountActionToken).count() == 0
    job = app.db.session.query(NotificationOutbox).one()
    assert job.event_type == "password_reset_request"
    assert job.state == "retry"
    assert job.last_error == "outbox_payload_full"


@pytest.mark.parametrize(
    ("purpose", "confirmed", "target", "template"),
    (
        (
            "verify_registration",
            False,
            "registration-delivery@example.org",
            WelcomeVerificationEmail,
        ),
        (
            "change_email",
            True,
            "changed-delivery@example.org",
            VerificationEmail,
        ),
    ),
)
def test_email_account_action_delivery_derives_bearer_from_committed_action(
    app, purpose, confirmed, target, template
):
    user = User(
        email="registration-delivery@example.org",
        fs_uniquifier=f"{purpose}-delivery-session",
        active=True,
        confirmed_at=datetime.utcnow() if confirmed else None,
        password="Valid_password1",
    )
    app.db.session.add(user)
    app.db.session.commit()
    token = app.security_service.issue_account_action_token(
        app.db.session,
        user_id=user.id,
        purpose=purpose,
        target_email=target,
    )
    action = app.db.session.query(AccountActionToken).one()
    environment = notifications.request_environment("localhost")
    notifications.enqueue_notification(
        "account_action_delivery",
        {"action_id": action.delivery_id, **environment},
        dedupe_key=f"account-action-delivery:{action.delivery_id}",
        session=app.db.session,
        commit=False,
    )
    app.db.session.commit()

    job = app.db.session.query(NotificationOutbox).one()
    assert token not in str(job.payload)
    assert job.payload == {"action_id": action.delivery_id, **environment}
    accepted = DeliveryResult("email", DeliveryState.SENT, "sent")
    with mock.patch.object(
        notifications, "send_email", return_value=accepted
    ) as send:
        assert notifications.process_outbox_batch() == 1

    assert send.call_args.args[1] == target
    assert send.call_args.args[2] is template
    assert "24 hours" not in template.msg_plain
    assert "24 hours" not in template.msg_html
    delivery_url = send.call_args.kwargs["verification_url"]
    parsed = urlsplit(delivery_url)
    delivered_token = parsed.fragment.rsplit("/", 1)[1]
    assert delivered_token not in parsed.path
    assert delivered_token not in parsed.query
    flow = "register" if purpose == "verify_registration" else "change-email"
    assert parsed.fragment.endswith(f"/{flow}/{delivered_token}")
    verified_user, verified_action = (
        app.security_service.verify_account_action_token(
            app.db.session, delivered_token, purpose
        )
    )
    assert verified_user.id == user.id
    assert verified_action.id == action.id
    terminal = app.db.session.query(NotificationOutbox).one()
    assert terminal.payload == {}


def test_superseded_registration_delivery_is_suppressed(app):
    user = User(
        email="stale-registration@example.org",
        fs_uniquifier="stale-registration-session",
        active=True,
        confirmed_at=None,
        password="Valid_password1",
    )
    app.db.session.add(user)
    app.db.session.commit()
    app.security_service.issue_account_action_token(
        app.db.session,
        user_id=user.id,
        purpose="verify_registration",
        target_email=str(user.email),
    )
    first = app.db.session.query(AccountActionToken).one()
    environment = notifications.request_environment("localhost")
    notifications.enqueue_notification(
        "account_action_delivery",
        {"action_id": first.delivery_id, **environment},
        dedupe_key=f"account-action-delivery:{first.delivery_id}",
        session=app.db.session,
        commit=False,
    )
    app.db.session.commit()

    app.security_service.issue_account_action_token(
        app.db.session,
        user_id=user.id,
        purpose="verify_registration",
        target_email=str(user.email),
    )
    current = app.db.session.query(AccountActionToken).one()
    notifications.enqueue_notification(
        "account_action_delivery",
        {"action_id": current.delivery_id, **environment},
        dedupe_key=f"account-action-delivery:{current.delivery_id}",
        session=app.db.session,
        commit=False,
    )
    app.db.session.commit()

    accepted = DeliveryResult("email", DeliveryState.SENT, "sent")
    with mock.patch.object(
        notifications, "send_email", return_value=accepted
    ) as send:
        assert notifications.process_outbox_batch() == 2
    send.assert_called_once()
    states = [
        row.state
        for row in app.db.session.query(NotificationOutbox)
        .order_by(NotificationOutbox.id)
        .all()
    ]
    assert states == ["suppressed", "sent"]


def test_consumed_registration_delivery_is_suppressed(app):
    user = User(
        email="consumed-registration@example.org",
        fs_uniquifier="consumed-registration-session",
        active=True,
        confirmed_at=None,
        password="Valid_password1",
    )
    app.db.session.add(user)
    app.db.session.commit()
    app.security_service.issue_account_action_token(
        app.db.session,
        user_id=user.id,
        purpose="verify_registration",
        target_email=str(user.email),
    )
    action = app.db.session.query(AccountActionToken).one()
    notifications.enqueue_notification(
        "account_action_delivery",
        {
            "action_id": action.delivery_id,
            **notifications.request_environment("localhost"),
        },
        session=app.db.session,
        commit=False,
    )
    app.db.session.delete(action)
    app.db.session.commit()

    with mock.patch.object(notifications, "send_email") as send:
        assert notifications.process_outbox_batch() == 1
    send.assert_not_called()
    assert app.db.session.query(NotificationOutbox).one().state == "suppressed"
