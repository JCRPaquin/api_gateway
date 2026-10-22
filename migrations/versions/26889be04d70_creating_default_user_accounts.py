"""creating default user accounts



Revision ID: 26889be04d70

Revises: 33d84dc97ea1

Create Date: 2014-09-10 00:08:49.335000



"""
import datetime

from alembic import op
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.sql import column, table

# revision identifiers, used by Alembic.

revision = "26889be04d70"

down_revision = "51f3b3b5cd5d"

SEED_EMAIL = "anonymous@ads"


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


def upgrade():
    timestamp = datetime.datetime.now()
    op.bulk_insert(
        users,
        [
            {
                "email": SEED_EMAIL,
                "active": True,
                "confirmed_at": timestamp,
                "registered_at": timestamp,
            },
        ],
        multiinsert=False,
    )


def downgrade():
    op.execute(users.delete().where(users.c.email == op.inline_literal(SEED_EMAIL)))
