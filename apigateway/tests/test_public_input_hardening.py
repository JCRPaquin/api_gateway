import json
from unittest import mock

import pytest
from marshmallow import ValidationError
from flask import Flask, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from apigateway import extensions, notifications, schemas, views
from apigateway.app import register_error_handlers
from apigateway.domains import canonicalize_domain, canonicalize_email, canonicalize_email_domain
from apigateway.email_templates import WelcomeVerificationEmail
from apigateway.utils import (
    DeliveryResult,
    DeliveryState,
    get_json_body,
    send_email,
)

def _queued(channel="email"):
    return DeliveryResult(channel, DeliveryState.QUEUED, "queued")


def test_streamed_feedback_overflow_short_circuits_all_downstream_work(app):
    body = b'{' + (b'"x":' + b'"' + b'a' * 262_144 + b'"}')
    with app.test_request_context(
        "/feedback", method="POST", data=body, content_type="application/json"
    ):
        # Exercise the streamed path rather than only the advertised-length check.
        request = views.request
        request.environ.pop("CONTENT_LENGTH", None)
        request.environ["wsgi.input_terminated"] = True
        with mock.patch.object(schemas, "validate_feedback_payload") as validate, mock.patch.object(
            views, "verify_recaptcha"
        ) as captcha, mock.patch.object(views, "make_json_diff") as diff, mock.patch.object(
            views, "render_template"
        ) as render, mock.patch.object(
            views, "enqueue_feedback_notifications"
        ) as notifications_queue, mock.patch.object(
            extensions.db.session, "query"
        ) as database:
            with pytest.raises(RequestEntityTooLarge):
                views.UserFeedbackView().post()
            for downstream in (validate, captcha, diff, render, notifications_queue, database):
                downstream.assert_not_called()


def test_account_advertised_overflow_short_circuits_captcha_and_database(app):
    with app.test_request_context(
        "/accounts/user",
        method="POST",
        data=b"x" * 16_385,
        content_type="application/json",
    ):
        with mock.patch.object(views, "verify_recaptcha") as captcha, mock.patch.object(
            extensions.db.session, "query"
        ) as database, mock.patch.object(views, "enqueue_notification") as mail:
            with pytest.raises(RequestEntityTooLarge):
                views.UserManagementView().post()
            captcha.assert_not_called()
            database.assert_not_called()
            mail.assert_not_called()


def test_api_oversize_error_has_stable_json_contract(app):
    client = app.test_client()
    with mock.patch.object(views, "verify_recaptcha") as captcha, mock.patch.object(
        views, "enqueue_feedback_notifications"
    ) as mail:
        response = client.post(
            "/feedback",
            data=b"x" * 262_145,
            content_type="application/json",
        )
    assert response.status_code == 413
    assert response.get_json() == {"message": "Request body too large"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.content_type == "application/json"
    assert response.content_length is not None
    captcha.assert_not_called()
    mail.assert_not_called()


def test_framework_max_content_length_uses_same_json_contract():
    framework_app = Flask(__name__)
    framework_app.config["MAX_CONTENT_LENGTH"] = 8
    register_error_handlers(framework_app)

    @framework_app.post("/bounded")
    def bounded():
        request.get_data()
        return {"message": "unreachable"}

    response = framework_app.test_client().post(
        "/bounded", data=b"x" * 9, content_type="application/octet-stream"
    )
    assert response.status_code == 413
    assert response.get_json() == {"message": "Request body too large"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.content_type == "application/json"
    assert response.content_length is not None


def test_decoded_root_must_be_mapping(app):
    with app.test_request_context(method="POST", data=b"[]", content_type="application/json"):
        with pytest.raises(BadRequest):
            get_json_body(views.request, 100)


@pytest.mark.parametrize(
    "body",
    [
        b'{"value":' + (b"[" * 1_100) + b"0" + (b"]" * 1_100) + b"}",
        b'{"value":' + (b"9" * 5_000) + b"}",
    ],
    ids=["decoder-recursion", "integer-digit-limit"],
)
def test_account_route_rejects_bounded_json_decoder_exhaustion(app, body):
    assert len(body) < app.config["ACCOUNT_MAX_REQUEST_BYTES"]
    with mock.patch.object(schemas.user_register_request, "load") as schema, mock.patch.object(
        views, "verify_recaptcha"
    ) as captcha:
        response = app.test_client().post(
            "/accounts/user", data=body, content_type="application/json"
        )

    assert response.status_code == 400
    schema.assert_not_called()
    captcha.assert_not_called()


def test_form_memory_and_part_limits_are_enforced(app):
    with app.test_request_context(
        method="POST",
        data="&".join(f"k{i}=v" for i in range(33)),
        content_type="application/x-www-form-urlencoded",
    ):
        with pytest.raises(RequestEntityTooLarge):
            get_json_body(views.request, 16_384)

    with app.test_request_context(
        method="POST",
        data=b"x" * 65_537,
        content_type="application/x-www-form-urlencoded",
    ):
        with pytest.raises(RequestEntityTooLarge):
            get_json_body(views.request, 262_144)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("email", f"{'a' * 245}@example.org"),
        ("password1", "Aa1" + "x" * 126),
        ("password2", "Aa1" + "x" * 126),
        ("given_name", "n" * 101),
        ("family_name", "n" * 101),
        ("g-recaptcha-response", "c" * 4097),
    ],
)
def test_registration_account_field_limits(field, value):
    payload = {
        "email": "person@example.org",
        "password1": "Valid_password1",
        "password2": "Valid_password1",
        "given_name": "Given",
        "family_name": "Family",
        "g-recaptcha-response": "token",
    }
    payload[field] = value
    if field in {"password1", "password2"}:
        payload["password1"] = value
        payload["password2"] = value
    with pytest.raises(ValidationError):
        schemas.user_register_request.load(payload)


def _feedback(subject, **values):
    payload = {
        "origin": "user_submission",
        "_subject": subject,
        "name": "Researcher",
        "email": "person@example.org",
        "g-recaptcha-response": "token",
    }
    payload.update(values)
    return payload


def test_feedback_origin_subject_discriminator_rejects_presentation_fields():
    payload = {
        "origin": "bbb_feedback",
        "_subject": "Bumblebee Feedback",
        "_replyto": "person@example.org",
        "comments": "safe",
        "g-recaptcha-response": "token",
        "channel": "#other",
    }
    with pytest.raises(ValidationError):
        schemas.validate_feedback_payload(payload, "user_submission", "bbb_feedback")
    payload.pop("channel")
    payload["_subject"] = "Updated Record"
    with pytest.raises(ValidationError):
        schemas.validate_feedback_payload(payload, "user_submission", "bbb_feedback")


def test_feedback_count_depth_and_record_byte_limits(app):
    with pytest.raises(ValidationError):
        schemas.validate_feedback_payload(
            _feedback("Missing References", references=[{}] * 501),
            "user_submission",
            "bbb_feedback",
        )

    nested = "value"
    for _ in range(9):
        nested = {"nested": nested}
    with pytest.raises(ValidationError):
        schemas.validate_feedback_payload(
            _feedback("New Record", new=nested), "user_submission", "bbb_feedback"
        )

    oversized = _feedback(
        "New Record",
        new={f"field{i}": "a" * 32_768 for i in range(5)},
    )
    with app.test_request_context(), pytest.raises(RequestEntityTooLarge):
        views.UserFeedbackView()._prepare_attachments(
            oversized, app.config["FEEDBACK_TEMPLATES"]["New Record"]
        )

def test_feedback_subject_nested_shapes_are_strict():
    with pytest.raises(ValidationError):
        schemas.validate_feedback_payload(
            _feedback(
                "Associated Articles",
                relationship="related",
                source="source",
                target="not-a-list",
            ),
            "user_submission",
            "bbb_feedback",
        )
    with pytest.raises(ValidationError):
        schemas.validate_feedback_payload(
            _feedback(
                "New Record",
                new={
                    "collection": ["astronomy"],
                    "bibcode": "2026Test",
                    "title": ["wrong type"],
                    "authors": [],
                    "publicationDate": "2026",
                    "publication": "Journal",
                    "abstract": "Abstract",
                },
            ),
            "user_submission",
            "bbb_feedback",
        )


def test_feedback_updated_record_attachments_use_updated_key_once(app):
    feedback = views.UserFeedbackView()
    updated = {"bibcode": "updated"}
    original = {"bibcode": "original"}
    with app.test_request_context():
        attachments = feedback._prepare_attachments(
            {"updated": updated, "original": original}, {"update": True}
        )
    assert attachments == [
        ("updated_record.json", b'{"bibcode":"updated"}'),
        ("original_record.json", b'{"bibcode":"original"}'),
    ]


def test_rendered_feedback_body_limit_is_enforced_before_notification(app):
    feedback = views.UserFeedbackView()
    with app.test_request_context(), mock.patch.object(
        views, "render_template", return_value="x" * 262_145
    ), mock.patch.object(views, "enqueue_feedback_notifications") as mail:
        with pytest.raises(RequestEntityTooLarge):
            feedback._prepare_email_body(
                {"_subject": "Bumblebee Feedback"}, {"file": "bumblebee_feedback.txt"}
            )
        mail.assert_not_called()


def test_registration_creation_and_notification_are_one_transaction(app):
    payload = {
        "email": "USER@Example.Org.",
        "password1": "Valid_password1",
        "password2": "Valid_password1",
        "given_name": "Given",
        "family_name": "Family",
        "g-recaptcha-response": "token",
    }
    with app.test_request_context("/accounts/user", method="POST", json=payload), mock.patch.object(
        views, "verify_recaptcha", return_value=True
    ), mock.patch.object(
        views, "enqueue_notification", return_value=_queued()
    ) as enqueue, mock.patch.object(
        views, "enqueue_template_email", return_value=_queued()
    ) as existing_enqueue:
        response = views.UserManagementView().post()
        existing_response = views.UserManagementView().post()

    assert response == ({"message": views.ACCOUNT_ACCEPTED_MESSAGE}, 202)
    assert existing_response == response
    user = extensions.db.session.query(views.User).filter_by(email="user@example.org").one()
    enqueue.assert_called_once()
    assert enqueue.call_args.args[0] == "welcome_email"
    assert enqueue.call_args.args[1]["user_id"] == user.id
    assert enqueue.call_args.kwargs["session"] is extensions.db.session
    assert enqueue.call_args.kwargs["commit"] is False
    existing_enqueue.assert_called_once()
    assert existing_enqueue.call_args.kwargs["dedupe_key"] == "registration:user@example.org"


def test_reset_and_resend_have_uniform_account_independent_responses(app):
    queued = _queued()
    with mock.patch.object(views, "verify_recaptcha", return_value=True), mock.patch.object(
        views, "enqueue_account_request", return_value=queued
    ) as enqueue, mock.patch.object(extensions.db.session, "query") as database:
        with app.test_request_context(
            method="POST", json={"g-recaptcha-response": "token"}
        ):
            reset_response = views.ResetPasswordView().post("USER@Example.Org.")
        with app.test_request_context(method="PUT"):
            resend_response = views.VerifyEmailView().put("USER@Example.Org.")

    assert reset_response == (
        {"message": views.ACCOUNT_ACCEPTED_MESSAGE},
        202,
    )
    assert resend_response == reset_response
    assert enqueue.call_args_list == [
        mock.call("password_reset_request", "user@example.org", "localhost"),
        mock.call("verification_resend_request", "user@example.org", "localhost"),
    ]
    database.assert_not_called()


def test_disposable_domain_canonicalization_is_idna_case_and_dot_stable():
    assert canonicalize_domain(" EXAMPLE.COM. ") == "example.com"
    assert canonicalize_domain("BÜCHER.example") == "xn--bcher-kva.example"
    assert canonicalize_email_domain("person@BÜCHER.example.") == "xn--bcher-kva.example"
    assert canonicalize_email("USER@Example.org") == "user@example.org"
    assert canonicalize_email("Straße@Example.org") == "Straße@example.org"
    with pytest.raises(ValueError):
        canonicalize_domain("bad..example")


def test_slack_payload_has_server_identity_no_markup_and_is_bounded(app):
    params = {
        "origin": app.config["BBB_FEEDBACK_ORIGIN"],
        "_replyto": "attacker@example.org",
        "channel": "#other",
        "username": "Administrator",
    }
    body = "<!channel> <@U123> <https://example.invalid|login> & `ticks`\x00"
    with app.test_request_context():
        payload = views.UserFeedbackView()._prepare_slack_data(
            params, "Bumblebee Feedback", body
        )
    assert payload["channel"] == app.config["FEEDBACK_SLACK_CHANNEL"]
    assert payload["username"] == app.config["FEEDBACK_SLACK_USERNAME"]
    assert payload["mrkdwn"] is False
    assert "<!channel>" not in payload["text"]
    assert "&lt;!channel&gt;" in payload["text"]
    assert "\x00" not in payload["text"]
    assert len(json.dumps(payload).encode("utf-8")) <= app.config[
        "FEEDBACK_SLACK_MAX_PAYLOAD_BYTES"
    ]


def test_slack_transport_contract_uses_json_timeout_and_no_redirects(app):
    response = mock.Mock(status_code=503)
    with app.test_request_context(), mock.patch.object(
        notifications.requests, "post", return_value=response
    ) as post:
        result = notifications._send_slack({"text": "safe", "mrkdwn": False})
    assert result.state == DeliveryState.RETRYABLE_FAILURE
    post.assert_called_once_with(
        app.config["FEEDBACK_SLACK_END_POINT"],
        json={"text": "safe", "mrkdwn": False},
        timeout=app.config["FEEDBACK_SLACK_TIMEOUT_SECONDS"],
        allow_redirects=False,
    )


def test_feedback_delivery_failures_are_explicit_atomic_results(app):
    params = {
        "origin": app.config["BBB_FEEDBACK_ORIGIN"],
        "_subject": "Bumblebee Feedback",
        "name": "Researcher",
        "_replyto": "person@example.org",
        "comments": "bounded",
        "g-recaptcha-response": "token",
    }
    feedback = views.UserFeedbackView()
    rejected = DeliveryResult("email", DeliveryState.REJECTED, "outbox_full")
    not_queued = DeliveryResult("slack", DeliveryState.REJECTED, "transaction_rejected")
    with app.test_request_context("/feedback", method="POST", json=params), mock.patch.object(
        schemas, "validate_feedback_payload", return_value=params
    ), mock.patch.object(views, "verify_recaptcha", return_value=True), mock.patch.object(
        feedback,
        "_prepare_email_and_attachments",
        return_value=("body", [], "person@example.org"),
    ), mock.patch.object(
        views,
        "enqueue_feedback_notifications",
        return_value=(rejected, not_queued),
    ):
        response, status = feedback.post()

    assert status == 503
    assert response == {
        "message": "Notification service unavailable",
        "delivery": {"email": "rejected", "slack": "rejected"},
    }


def test_enabled_mail_rejects_unauthenticated_or_cleartext_configuration(app):
    settings = {
        "TESTING": False,
        "MAIL_TEST_BYPASS": False,
        "MAIL_ENABLED": True,
        "MAIL_SERVER": "smtp.example.org",
        "MAIL_USERNAME": None,
        "MAIL_PASSWORD": None,
        "MAIL_USE_STARTTLS": False,
        "MAIL_USE_SSL": False,
    }
    with app.test_request_context(), mock.patch.dict(app.config, settings), mock.patch(
        "apigateway.utils.smtplib.SMTP"
    ) as smtp:
        result = send_email(
            "sender@example.org", "recipient@example.org", WelcomeVerificationEmail
        )
    assert result == DeliveryResult(
        "email", DeliveryState.REJECTED, "invalid_mail_configuration"
    )
    smtp.assert_not_called()


def test_final_mime_limit_rejects_before_smtp(app):
    settings = {
        "TESTING": False,
        "MAIL_TEST_BYPASS": False,
        "MAIL_ENABLED": True,
        "MAIL_MAX_MESSAGE_BYTES": 1,
        "MAIL_SERVER": "smtp.example.org",
        "MAIL_USERNAME": "gateway",
        "MAIL_PASSWORD": "secret",
        "MAIL_USE_STARTTLS": True,
    }
    with app.test_request_context(), mock.patch.dict(app.config, settings), mock.patch(
        "apigateway.utils.smtplib.SMTP"
    ) as smtp:
        result = send_email(
            "sender@example.org", "recipient@example.org", WelcomeVerificationEmail
        )
    assert result == DeliveryResult("email", DeliveryState.REJECTED, "message_too_large")
    smtp.assert_not_called()


def test_smtp_transport_failure_is_typed_and_not_swallowed(app):
    settings = {
        "TESTING": False,
        "MAIL_TEST_BYPASS": False,
        "MAIL_ENABLED": True,
        "MAIL_SERVER": "smtp.example.org",
        "MAIL_USERNAME": "gateway",
        "MAIL_PASSWORD": "secret",
        "MAIL_USE_STARTTLS": True,
        "MAIL_USE_SSL": False,
    }
    with app.test_request_context(), mock.patch.dict(app.config, settings), mock.patch(
        "apigateway.utils.smtplib.SMTP", side_effect=OSError("unreachable")
    ):
        result = send_email(
            "sender@example.org", "recipient@example.org", WelcomeVerificationEmail
        )
    assert result == DeliveryResult(
        "email", DeliveryState.RETRYABLE_FAILURE, "transport_error"
    )
