import uuid

from datetime import datetime
from typing import List

import sqlalchemy as sa
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2TokenMixin
from citext import CIText
from flask import current_app
from flask_login import AnonymousUserMixin
from flask_security import RoleMixin, UserMixin
from flask_security.utils import hash_password, verify_password
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship
from werkzeug.datastructures import ImmutableList
from werkzeug.security import gen_salt

base_model = declarative_base()


roles_users = sa.Table(
    "roles_users",
    base_model.metadata,
    sa.Column("user_id", sa.ForeignKey("user.id"), primary_key=True),
    sa.Column("role_id", sa.ForeignKey("role.id"), primary_key=True),
)


class User(base_model, UserMixin):
    __tablename__ = "user"

    # 'fs_uniquifier' serves as the main identifier for a user
    # The 'id' column is maintained for data persistence as 'fs_uniquifier' can be altered.
    # the get_id() method of the UserMixin class returns the 'fs_uniquifier' value

    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(CIText(), unique=True)
    _password = sa.Column(sa.String(255), name="password")
    given_name = sa.Column(sa.String(255))
    family_name = sa.Column(sa.String(255))
    active = sa.Column(sa.Boolean())
    confirmed_at = sa.Column(sa.DateTime())
    last_login_at = sa.Column(sa.DateTime())
    login_count = sa.Column(sa.Integer)
    registered_at = sa.Column(sa.DateTime())
    ratelimit_quota = sa.Column(sa.Float)
    _allowed_scopes = sa.Column(sa.Text)
    fs_uniquifier = sa.Column(sa.String(64), unique=True, nullable=False)
    roles = relationship("Role", secondary=roles_users)

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, password):
        self._password = hash_password(password)

    password = sa.orm.synonym("_password", descriptor=password)

    @hybrid_property
    def is_anonymous_bootstrap_user(self) -> bool:
        return current_app.config["ANONYMOUS_BOOTSTRAP_USER_EMAIL"] == self.email

    @property
    def allowed_scopes(self) -> List[str]:
        if self._allowed_scopes:
            return self._allowed_scopes.split(" ")
        else:
            return current_app.config["USER_DEFAULT_SCOPES"]

    def validate_password(self, password) -> bool:
        return verify_password(password, self.password)


class AnonymousUser(AnonymousUserMixin):
    """AnonymousUser definition"""

    def __init__(self):
        self.roles = ImmutableList()

    def has_role(self, *args):
        """Returns `False`"""
        return False

    @hybrid_property
    def is_anonymous_bootstrap_user(self):
        return False


class Role(base_model, RoleMixin):
    __tablename__ = "role"

    id = sa.Column(sa.Integer(), primary_key=True)
    name = sa.Column(sa.String(80), unique=True)
    description = sa.Column(sa.String(255))

    def __eq__(self, other):
        return self.name == other or self.name == getattr(other, "name", None)

    def __ne__(self, other):
        return self.name != other and self.name != getattr(other, "name", None)


class OAuth2Client(base_model, OAuth2ClientMixin):
    __tablename__ = "oauth2client"
    __table_args__ = (
        sa.CheckConstraint(
            "credential_purpose IN ('anonymous', 'browser', 'personal', 'operator')",
            name="ck_oauth2client_credential_purpose",
        ),
        sa.CheckConstraint(
            "(credential_purpose = 'anonymous' AND binding_digest IS NOT NULL) "
            "OR (credential_purpose <> 'anonymous' AND binding_digest IS NULL)",
            name="ck_oauth2client_anonymous_binding",
        ),
        sa.Index(
            "uq_oauth2client_active_personal_owner",
            "user_id",
            unique=True,
            postgresql_where=sa.text("credential_purpose = 'personal'"),
            sqlite_where=sa.text("credential_purpose = 'personal'"),
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = sa.Column(
        sa.String,
        sa.ForeignKey("user.fs_uniquifier", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # This deployment is a bearer resource server; clients are public
    # identifiers and never have a stored or issued client secret.
    client_secret = None
    client_secret_expires_at = None
    ratelimit_multiplier = sa.Column(sa.Float, nullable=False, default=1.0)
    individual_ratelimit_multipliers = sa.Column(sa.JSON)
    last_activity = sa.Column(sa.DateTime, nullable=True)
    credential_purpose = sa.Column(sa.String(16), nullable=False, default="browser")
    binding_digest = sa.Column(sa.String(64), nullable=True, index=True)

    user = relationship("User")

    def gen_salt(self):
        self.reset_client_id()

    def reset_client_id(self):
        self.client_id = gen_salt(current_app.config.get("OAUTH2_CLIENT_ID_SALT_LEN"))


class OAuth2Token(base_model, OAuth2TokenMixin):
    __tablename__ = "oauth2token"
    __table_args__ = (
        sa.CheckConstraint(
            "credential_purpose IN ('anonymous', 'browser', 'personal', 'operator')",
            name="ck_oauth2token_credential_purpose",
        ),
        sa.CheckConstraint(
            "token_digest_version = 1", name="ck_oauth2token_digest_version"
        ),
        sa.CheckConstraint(
            (
                "(credential_delivery_pending AND credential_delivery_path IS NOT NULL) "
                "OR (NOT credential_delivery_pending AND credential_delivery_path IS NULL)"
            ),
            name="ck_oauth2token_delivery_state",
        ),
        sa.UniqueConstraint(
            "token_key_id",
            "access_token",
            name="uq_oauth2token_key_digest",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = sa.Column(
        sa.String,
        sa.ForeignKey("user.fs_uniquifier", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user = relationship("User")
    client_id = sa.Column(
        sa.Integer(),
        sa.ForeignKey("oauth2client.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    client = relationship("OAuth2Client")
    # OAuth2TokenMixin's access_token column stores only the keyed digest.
    # Raw bearer credentials exist only in the issuance response.
    access_token = sa.Column(sa.String(64), nullable=False)
    refresh_token = None
    refresh_token_revoked_at = None
    token_key_id = sa.Column(sa.String(64), nullable=False)
    token_digest_version = sa.Column(sa.SmallInteger, nullable=False, default=1)
    credential_purpose = sa.Column(sa.String(16), nullable=False, default="browser")
    is_personal = sa.Column(sa.Boolean, default=False, index=True)
    is_internal = sa.Column(sa.Boolean, default=False)
    expires_in = sa.Column(sa.BigInteger, nullable=False)
    credential_delivery_pending = sa.Column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )
    credential_delivery_path = sa.Column(sa.Text, nullable=True)

    def expires_at(self):
        if not self.expires_in:
            return 0

        return self.issued_at + self.expires_in



class AccountActionToken(base_model):
    __tablename__ = "account_action_token"
    __table_args__ = (
        sa.CheckConstraint(
            "purpose IN ('password_reset', 'verify_registration', 'change_email')",
            name="ck_account_action_token_purpose",
        ),
        sa.UniqueConstraint(
            "user_id", "purpose", name="uq_account_action_token_user_purpose"
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    delivery_id = sa.Column(
        sa.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4())
    )
    token_digest = sa.Column(sa.String(64), nullable=False, unique=True, index=True)
    user_id = sa.Column(
        sa.Integer,
        sa.ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
    )
    purpose = sa.Column(sa.String(32), nullable=False)
    target_email = sa.Column(sa.String(255), nullable=False)
    state_digest = sa.Column(sa.String(64), nullable=False)
    issued_at = sa.Column(sa.DateTime(timezone=True), nullable=False)
    expires_at = sa.Column(sa.DateTime(timezone=True), nullable=False)
    user = relationship("User")


class NotificationOutbox(base_model):
    __tablename__ = "notification_outbox"

    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    event_type = sa.Column(sa.String(64), nullable=False)
    payload = sa.Column(sa.JSON, nullable=False)
    payload_size = sa.Column(sa.Integer, nullable=False, default=0)
    state = sa.Column(sa.String(24), nullable=False, default="pending", index=True)
    attempts = sa.Column(sa.Integer, nullable=False, default=0)
    available_at = sa.Column(sa.DateTime, nullable=False, default=datetime.utcnow, index=True)
    claimed_at = sa.Column(sa.DateTime)
    ownership_token = sa.Column(sa.String(36), index=True)
    dedupe_key = sa.Column(sa.String(320), unique=True)
    last_error = sa.Column(sa.String(64))
    terminal_at = sa.Column(sa.DateTime, index=True)
    created_at = sa.Column(sa.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = sa.Column(
        sa.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
