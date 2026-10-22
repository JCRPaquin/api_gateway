"""Harden notification outbox, reset actions, and canonical account email.

Revision ID: 7f6e5d4c3b2a
Revises: 4a1b2c3d4e5f
Create Date: 2026-10-22
"""

import json

from typing import Sequence, Union
import unicodedata

import idna
import sqlalchemy as sa
from alembic import op

revision: str = "7f6e5d4c3b2a"
down_revision: Union[str, None] = "4a1b2c3d4e5f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _canonical_email(value: str) -> str:
    local, domain = value.rsplit("@", 1)
    local = unicodedata.normalize("NFC", local)
    if not local or any(ord(char) < 32 or ord(char) == 127 for char in local):
        raise ValueError("Invalid email address")
    if local.isascii():
        local = local.lower()
    domain = domain.strip()
    if domain.endswith("."):
        domain = domain[:-1]
    canonical_domain = idna.encode(domain, uts46=True, std3_rules=True).decode("ascii").lower()
    canonical = f"{local}@{canonical_domain}"
    if len(canonical) > 254:
        raise ValueError("Invalid email address")
    return canonical


def upgrade() -> None:
    bind = op.get_bind()
    rows = bind.execute(sa.text('SELECT id, email FROM "user" ORDER BY id')).fetchall()
    canonical_by_id = {}
    ids_by_email = {}
    for user_id, email in rows:
        if email is None:
            continue
        try:
            canonical = _canonical_email(email)
        except (ValueError, idna.IDNAError) as exc:
            raise RuntimeError(
                f"Invalid stored email must be resolved before upgrade; user ID: {user_id}"
            ) from exc
        canonical_by_id[user_id] = canonical
        ids_by_email.setdefault(canonical, []).append(user_id)
    collisions = [ids for ids in ids_by_email.values() if len(ids) > 1]
    if collisions:
        bounded_ids = [user_id for ids in collisions for user_id in ids][:20]
        raise RuntimeError(
            "Canonical email collisions must be resolved before upgrade; user IDs: "
            + ",".join(str(user_id) for user_id in bounded_ids)
        )

    # Reset bearers from the legacy workflow were stored in plaintext on the
    # action row. Invalidate them at cutover; new actions persist no bearer.
    bind.execute(sa.text("DELETE FROM password_change_request"))
    op.add_column(
        "password_change_request",
        sa.Column("delivery_id", sa.String(length=36), nullable=False),
    )
    op.create_unique_constraint(
        "uq_password_change_request_delivery_id",
        "password_change_request",
        ["delivery_id"],
    )
    op.drop_column("password_change_request", "token")

    op.add_column(
        "notification_outbox",
        sa.Column("payload_size", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("notification_outbox", sa.Column("ownership_token", sa.String(36)))
    op.add_column("notification_outbox", sa.Column("terminal_at", sa.DateTime()))
    op.create_index(
        op.f("ix_notification_outbox_ownership_token"),
        "notification_outbox",
        ["ownership_token"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notification_outbox_terminal_at"),
        "notification_outbox",
        ["terminal_at"],
        unique=False,
    )

    outbox = sa.table(
        "notification_outbox",
        sa.column("id", sa.Integer()),
        sa.column("payload", sa.JSON()),
        sa.column("payload_size", sa.Integer()),
        sa.column("dedupe_key", sa.String()),
        sa.column("terminal_at", sa.DateTime()),
        sa.column("state", sa.String()),
        sa.column("last_error", sa.String()),
        sa.column("claimed_at", sa.DateTime()),
        sa.column("ownership_token", sa.String()),
    )
    outbox_rows = bind.execute(
        sa.text(
            "SELECT id, payload, state, created_at, updated_at "
            "FROM notification_outbox ORDER BY id"
        )
    ).fetchall()
    sensitive_keys = {"password", "password_hash", "token", "verification_url"}
    for row_id, payload, state, created_at, updated_at in outbox_rows:
        if isinstance(payload, str):
            payload = json.loads(payload)
        has_sensitive_value = isinstance(payload, dict) and any(
            key in sensitive_keys for key in payload
        )
        if state in {"sent", "suppressed", "dead"} or has_sensitive_value:
            bind.execute(
                outbox.update()
                .where(outbox.c.id == row_id)
                .values(
                    payload={},
                    payload_size=0,
                    dedupe_key=None,
                    terminal_at=updated_at or created_at,
                    state="dead" if has_sensitive_value else state,
                    last_error=(
                        "sensitive_payload_removed"
                        if has_sensitive_value
                        else None
                    ),
                    claimed_at=None,
                    ownership_token=None,
                )
            )
        else:
            payload_size = len(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            bind.execute(
                sa.text(
                    "UPDATE notification_outbox SET payload_size=:payload_size "
                    "WHERE id=:id"
                ),
                {"payload_size": payload_size, "id": row_id},
            )
    for user_id, canonical in canonical_by_id.items():
        bind.execute(
            sa.text('UPDATE "user" SET email=:email WHERE id=:id'),
            {"email": canonical, "id": user_id},
        )


def downgrade() -> None:
    op.add_column(
        "password_change_request",
        sa.Column("token", sa.String(length=255), nullable=True),
    )
    op.create_unique_constraint(
        "uq_password_change_request_token",
        "password_change_request",
        ["token"],
    )
    op.drop_constraint(
        "uq_password_change_request_delivery_id",
        "password_change_request",
        type_="unique",
    )
    op.drop_column("password_change_request", "delivery_id")
    op.drop_index(op.f("ix_notification_outbox_terminal_at"), table_name="notification_outbox")
    op.drop_index(
        op.f("ix_notification_outbox_ownership_token"), table_name="notification_outbox"
    )
    op.drop_column("notification_outbox", "terminal_at")
    op.drop_column("notification_outbox", "ownership_token")
    op.drop_column("notification_outbox", "payload_size")
