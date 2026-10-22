import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import List

import marshmallow.validate
import marshmallow_dataclass
from citext import CIText
from flask_marshmallow.sqla import SQLAlchemyAutoSchema
from marshmallow import ValidationError, fields, validates_schema
from marshmallow.validate import Length, Validator
from marshmallow_sqlalchemy import ModelConverter

from apigateway.domains import canonicalize_email
from apigateway.models import User



class PasswordValidator(Validator):
    """Validate a password."""

    PASSWORD_REGEX = re.compile(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$")

    def __call__(self, value: str) -> str:
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters long")
        if len(value) > 128:
            raise ValidationError("Password must be at most 128 characters long")

        if not self.PASSWORD_REGEX.match(value):
            raise ValidationError(
                "Password must contain at least one uppercase letter, one lowercase letter, and one number"
            )

        return value


class PublicEmailValidator(Validator):
    def __call__(self, value: str) -> str:
        if not isinstance(value, str) or len(value) > 254:
            raise ValidationError("Invalid email address")
        try:
            marshmallow.validate.Email()(canonicalize_email(value))
        except (ValueError, ValidationError) as exc:
            raise ValidationError("Invalid email address") from exc
        return value


class CITextField(fields.String):
    pass


class CustomModelConverter(ModelConverter):
    SQLA_TYPE_MAPPING = ModelConverter.SQLA_TYPE_MAPPING.copy()
    SQLA_TYPE_MAPPING[CIText] = CITextField


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True
        model_converter = CustomModelConverter


@dataclass
class BootstrapGetRequestSchema:
    scope: str = field(default=None)
    ratelimit: float = field(
        default=1.0, metadata={"validate": marshmallow.validate.Range(min=0.0)}
    )
    create_new: bool = field(default=False)
    redirect_uri: str = field(default=None)
    client_name: str = field(default=None)
    expires: datetime = field(default=datetime(2050, 1, 1))
    individual_ratelimits: dict = field(default=None)


@dataclass
class BootstrapGetResponseSchema:
    access_token: str = field(default=None)
    refresh_token: str = field(default=None)
    expires_at: str = field(default=None)
    token_type: str = field(default="Bearer")
    username: str = field(default=None)
    scopes: List[str] = field(default_factory=list)
    anonymous: bool = field(default=None)
    client_id: str = field(default=None)
    client_secret: str = field(default=None)
    ratelimit: float = field(default=None)
    client_name: str = field(default=None)
    individual_ratelimits: dict = field(default=None)
    given_name: str = field(default=None)
    family_name: str = field(default=None)


@dataclass
class UserAuthPostRequestSchema:
    email: str = field(metadata={"validate": PublicEmailValidator()})
    password: str = field(metadata={"validate": Length(min=8, max=128)})


@dataclass
class UserRegisterPostRequestSchema:
    email: str = field(metadata={"validate": PublicEmailValidator()})
    password1: str = field(metadata={"validate": PasswordValidator()})
    password2: str = field(metadata={"validate": PasswordValidator()})
    given_name: str = field(default=None, metadata={"validate": Length(max=100)})
    family_name: str = field(default=None, metadata={"validate": Length(max=100)})
    g_recaptcha_response: str = field(
        default=None,
        metadata={"data_key": "g-recaptcha-response", "validate": Length(max=4096)},
    )

    @validates_schema
    def validate_passwords_equal(self, data, **kwargs):
        if data["password1"] != data["password2"]:
            raise ValidationError("Passwords do not match", field_name="password2")


@dataclass
class CaptchaRequestSchema:
    g_recaptcha_response: str = field(
        default=None,
        metadata={
            "data_key": "g-recaptcha-response",
            "validate": Length(max=4096),
        },
    )


@dataclass
class ChangePasswordRequestSchema:
    old_password: str = field(metadata={"validate": Length(min=8, max=128)})
    new_password1: str = field(metadata={"validate": PasswordValidator()})
    new_password2: str = field(metadata={"validate": PasswordValidator()})

    @validates_schema
    def validate_passwords_equal(self, data, **kwargs):
        if data["new_password1"] != data["new_password2"]:
            raise ValidationError("Passwords do not match", field_name="new_password2")


@dataclass
class ChangeEmailRequestSchema:
    email: str = field(metadata={"validate": PublicEmailValidator()})
    password: str = field(metadata={"validate": Length(min=8, max=128)})


@dataclass
class ResetPasswordInitiateRequestSchema:
    email: str = field(metadata={"validate": PublicEmailValidator()})
    g_recaptcha_response: str = field(
        default=None, metadata={"data_key": "g-recaptcha-response"}
    )


@dataclass
class AccountActionTokenRequestSchema:
    token: str = field()


@dataclass
class ResetPasswordRequestSchema:
    token: str = field()
    password1: str = field(metadata={"validate": PasswordValidator()})
    password2: str = field(metadata={"validate": PasswordValidator()})

    @validates_schema
    def validate_passwords_equal(self, data, **kwargs):
        if data["password1"] != data["password2"]:
            raise ValidationError("Passwords do not match", field_name="password2")


@dataclass
class UpdateUserRequestSchema:
    given_name: str = field(default=None, metadata={"validate": Length(max=100)})
    family_name: str = field(default=None, metadata={"validate": Length(max=100)})


@dataclass
class ClearCacheRequestSchema:
    key: str = field()
    parameters: dict = None


@dataclass
class ClearLimitRequestSchema:
    key: str = field()
    scope: str = ""

    @validates_schema
    def validate_clear_all(self, data, **kwargs):
        if data["key"] == "*" and data["scope"] != "":
            raise ValidationError(
                "Do not provide a scope when clearing ALL limits", field_name="scope"
            )


@dataclass
class PersonalTokenViewGetResponseSchema:
    access_token: str = field(default=None)
    refresh_token: str = field(default=None)
    expires_at: str = field(default=None)
    token_type: str = field(default="Bearer")
    scopes: List[str] = field(default_factory=list)
    username: str = field(default=None)
    anonymous: bool = field(default=None)
    client_id: str = field(default=None)
    user_id: str = field(default=None)


def validate_public_email(email: str) -> str:
    return PublicEmailValidator()(email)


_FEEDBACK_COMMON_FIELDS = {
    "origin",
    "_subject",
    "name",
    "email",
    "_replyto",
    "comments",
    "g-recaptcha-response",
}
_FEEDBACK_SUBJECT_FIELDS = {
    "Missing References": {"references"},
    "Associated Articles": {"relationship", "custom_name", "source", "target"},
    "Updated Record": {"original", "updated", "diff"},
    "New Record": {"new"},
    "Bumblebee Feedback": set(),
}


_FEEDBACK_REQUIRED_FIELDS = {
    "Missing References": {"references"},
    "Associated Articles": {"relationship", "source", "target"},
    "Updated Record": {"original", "updated"},
    "New Record": {"new"},
    "Bumblebee Feedback": {"comments"},
}


def _feedback_string_limit(key: str) -> int:
    if key == "g-recaptcha-response":
        return 4096
    if key in {"email", "_replyto"}:
        return 254
    if key in {"name", "custom_name"}:
        return 200
    if key in {"bibcode", "relationship", "target", "source", "citing", "cited"}:
        return 64
    if key in {"comments", "abstract", "reference", "references", "refstring", "diff"}:
        return 16_384
    return 32_768


def _validate_feedback_value(value, key: str, depth: int = 1):
    if depth > 8:
        raise ValidationError("Feedback data exceeds maximum nesting depth")
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise ValidationError("Feedback object has too many keys")
        for child_key, child_value in value.items():
            if not isinstance(child_key, str) or len(child_key) > 64:
                raise ValidationError("Feedback object key is invalid")
            _validate_feedback_value(child_value, child_key, depth + 1)
        return
    if isinstance(value, list):
        limit = 2_000 if key == "authors" else 500 if key in {"references", "target"} else 1_000
        if len(value) > limit:
            raise ValidationError(f"Feedback field '{key}' has too many items")
        for item in value:
            if key in {"target", "authors"} and (
                not isinstance(item, str) or len(item) > (64 if key == "target" else 200)
            ):
                raise ValidationError(f"Feedback field '{key}' contains an invalid item")
            _validate_feedback_value(item, key, depth + 1)
        return
    if isinstance(value, str):
        if len(value) > _feedback_string_limit(key):
            raise ValidationError(f"Feedback field '{key}' is too long")
        if key in {"name", "custom_name", "email", "_replyto", "relationship"} and any(
            ord(char) < 32 or ord(char) == 127 for char in value
        ):
            raise ValidationError(f"Feedback field '{key}' contains a control character")
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError(f"Feedback field '{key}' has an invalid number")
    if value is not None and not isinstance(value, (bool, int, float)):
        raise ValidationError(f"Feedback field '{key}' has an invalid value")

def _require_feedback_string(mapping, key: str, context: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise ValidationError(f"Feedback field '{context}.{key}' must be a string")
    return value


def _validate_subject_shape(payload: dict, subject: str) -> None:
    if subject == "Missing References":
        references = payload["references"]
        if not isinstance(references, list):
            raise ValidationError("Feedback references must be a list")
        for reference in references:
            if (
                not isinstance(reference, Mapping)
                or set(reference) != {"citing", "cited", "refstring"}
                or not all(isinstance(value, str) for value in reference.values())
            ):
                raise ValidationError("Invalid missing-reference record")
        return
    if subject == "Associated Articles":
        relationship = _require_feedback_string(payload, "relationship", "associated")
        _require_feedback_string(payload, "source", "associated")
        targets = payload["target"]
        if (
            not isinstance(targets, list)
            or not targets
            or not all(isinstance(target, str) for target in targets)
        ):
            raise ValidationError("Associated-article targets must be a non-empty string list")
        if relationship == "other":
            _require_feedback_string(payload, "custom_name", "associated")
        return
    if subject == "Updated Record":
        original = payload["original"]
        updated = payload["updated"]
        if not isinstance(original, Mapping) or not isinstance(updated, Mapping):
            raise ValidationError("Updated-record values must be objects")
        _require_feedback_string(original, "bibcode", "original")
        return
    if subject == "New Record":
        record = payload["new"]
        if not isinstance(record, Mapping):
            raise ValidationError("Feedback field 'new' must be an object")
        collections = record.get("collection")
        if (
            not isinstance(collections, list)
            or not collections
            or not all(isinstance(collection, str) for collection in collections)
        ):
            raise ValidationError("New-record collection must be a non-empty string list")
        for key in ("bibcode", "title", "publicationDate", "publication", "abstract"):
            _require_feedback_string(record, key, "new")
        authors = record.get("authors")
        if not isinstance(authors, list) or not all(
            isinstance(author, str) for author in authors
        ):
            raise ValidationError("New-record authors must be a string list")



def validate_feedback_payload(data: dict, forms_origin: str, bbb_origin: str) -> dict:
    if not isinstance(data, Mapping):
        raise ValidationError("Feedback body must be an object")
    payload = dict(data)
    origin = payload.get("origin")
    subject = payload.get("_subject")
    if origin not in {forms_origin, bbb_origin}:
        raise ValidationError("No valid origin provided in feedback data")
    if subject not in _FEEDBACK_SUBJECT_FIELDS:
        raise ValidationError("Unsupported feedback subject")
    if origin == bbb_origin and subject != "Bumblebee Feedback":
        raise ValidationError("Invalid subject for feedback origin")
    if origin == forms_origin and subject == "Bumblebee Feedback":
        raise ValidationError("Invalid subject for feedback origin")
    if origin == forms_origin and "_replyto" in payload:
        raise ValidationError("Feedback reply-to is not accepted for this origin")
    if origin == bbb_origin and "email" in payload:
        raise ValidationError("Feedback email is not accepted for this origin")

    allowed = _FEEDBACK_COMMON_FIELDS | _FEEDBACK_SUBJECT_FIELDS[subject]
    unknown = set(payload) - allowed
    if unknown:
        raise ValidationError({"_schema": [f"Unknown fields: {', '.join(sorted(unknown))}"]})
    if "channel" in payload or "username" in payload:
        raise ValidationError("Feedback presentation fields are not accepted")
    missing = _FEEDBACK_REQUIRED_FIELDS[subject] - set(payload)
    if missing:
        raise ValidationError(
            {"_schema": [f"Missing fields: {', '.join(sorted(missing))}"]}
        )
    if not isinstance(payload.get("name"), str):
        raise ValidationError("Feedback name is required")
    if not isinstance(payload.get("comments", ""), str):
        raise ValidationError("Feedback comments must be a string")
    captcha_token = payload.get("g-recaptcha-response")
    if captcha_token is not None and not isinstance(captcha_token, str):
        raise ValidationError("CAPTCHA token is invalid")
    if origin == forms_origin:
        email = payload.get("email")
        if not isinstance(email, str):
            raise ValidationError("Feedback email is required")
        marshmallow.validate.Email()(email)
    else:
        reply_to = payload.get("_replyto")
        if not isinstance(reply_to, str):
            raise ValidationError("Feedback reply-to is required")
        marshmallow.validate.Email()(reply_to)

    _validate_feedback_value(payload, "feedback")
    _validate_subject_shape(payload, subject)
    return payload


bootstrap_request = marshmallow_dataclass.class_schema(BootstrapGetRequestSchema)()
bootstrap_response = marshmallow_dataclass.class_schema(BootstrapGetResponseSchema)()
user_auth_request = marshmallow_dataclass.class_schema(UserAuthPostRequestSchema)()
user_register_request = marshmallow_dataclass.class_schema(UserRegisterPostRequestSchema)()
change_password_request = marshmallow_dataclass.class_schema(ChangePasswordRequestSchema)()
update_user_request = marshmallow_dataclass.class_schema(UpdateUserRequestSchema)()
change_email_request = marshmallow_dataclass.class_schema(ChangeEmailRequestSchema)()
captcha_request = marshmallow_dataclass.class_schema(CaptchaRequestSchema)()
reset_password_initiate_request = marshmallow_dataclass.class_schema(
    ResetPasswordInitiateRequestSchema
)()
account_action_token_request = marshmallow_dataclass.class_schema(
    AccountActionTokenRequestSchema
)()
reset_password_request = marshmallow_dataclass.class_schema(ResetPasswordRequestSchema)()
clear_cache_request = marshmallow_dataclass.class_schema(ClearCacheRequestSchema)()
clear_limit_request = marshmallow_dataclass.class_schema(ClearLimitRequestSchema)()
personal_token_response = marshmallow_dataclass.class_schema(PersonalTokenViewGetResponseSchema)()
