"""creating default user accounts



Revision ID: 26889be04d70

Revises: 33d84dc97ea1

Create Date: 2014-09-10 00:08:49.335000



"""
import datetime
import os

from alembic import op
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.sql import column, table

# revision identifiers, used by Alembic.

revision = "26889be04d70"

down_revision = "51f3b3b5cd5d"


users = table(
    "users",
    column("id", Integer),
    column("email", String),
    column("active", Boolean),
    column("confirmed_at", DateTime),
    column("registered_at", DateTime),
)

roles = table(
    "roles",
    column("id", Integer),
    column("name", String),
    column("description", String),
)

permissions = table(
    "permissions",
    column("id", Integer),
    column("name", String),
    column("description", String),
)


def get_email():
    """Read the migration seed value without initializing the application."""
    return os.environ.get("ANONYMOUS_BOOTSTRAP_USER_EMAIL", "anonymous@ads")


def upgrade():
    email = get_email()
    op.bulk_insert(
        users,
        [
            {
                "email": email,
                "active": True,
                "confirmed_at": datetime.datetime.now(),
                "registered_at": datetime.datetime.now(),
            },
        ],
        multiinsert=False,
    )


def downgrade():
    email = get_email()
    op.execute(users.delete().where(users.c.email == op.inline_literal(email)))
