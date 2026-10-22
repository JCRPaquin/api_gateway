import datetime
import math
import re
import time

import click
import sqlalchemy as sa
from flask import current_app
from flask.cli import FlaskGroup

from apigateway.app import create_app
from apigateway.models import OAuth2Client, OAuth2Token, User
from apigateway.notifications import cleanup_terminal_notifications, process_outbox_batch



class PositiveDuration(click.ParamType):
    name = "duration"
    _pattern = re.compile(
        r"^(weeks|days|hours|minutes|seconds|milliseconds|microseconds)=([^=]+)$"
    )

    def convert(self, value, param, ctx):
        if isinstance(value, datetime.timedelta):
            return value
        match = self._pattern.fullmatch(value or "")
        if not match:
            self.fail(
                "must contain exactly one supported unit and value, for example days=90",
                param,
                ctx,
            )
        try:
            amount = float(match.group(2))
        except (TypeError, ValueError):
            self.fail("duration value must be numeric", param, ctx)
        if not math.isfinite(amount) or amount <= 0:
            self.fail("duration value must be finite and greater than zero", param, ctx)
        try:
            duration = datetime.timedelta(**{match.group(1): amount})
        except OverflowError:
            self.fail("duration is out of range", param, ctx)
        if duration <= datetime.timedelta(0):
            self.fail("duration must resolve to more than zero", param, ctx)
        return duration


class NonnegativeFiniteFloat(click.ParamType):
    name = "nonnegative finite number"

    def convert(self, value, param, ctx):
        try:
            number = float(value)
        except (TypeError, ValueError):
            self.fail("must be numeric", param, ctx)
        if not math.isfinite(number) or number < 0:
            self.fail("must be finite and nonnegative", param, ctx)
        return number


POSITIVE_DURATION = PositiveDuration()
NONNEGATIVE_FLOAT = NonnegativeFiniteFloat()
BATCH_SIZE = 1000


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    pass


@cli.group("cleanup", short_help="Cleanup commands")
def cleanup():
    """Cleanup commands related to the app."""


def _confirm_cleanup(dry_run, assume_yes):
    if not dry_run and not assume_yes:
        click.confirm("Permanently delete all matching records?", abort=True)


def _delete_ids(session, model, ids, predicates):
    """Delete a selected batch only if every eligibility predicate still holds."""
    return (
        session.query(model)
        .filter(model.id.in_(ids), *predicates)
        .delete(synchronize_session=False)
    )


def _cleanup_rows(model, predicates, label, dry_run, assume_yes):
    session = current_app.db.session
    if dry_run:
        try:
            count = session.query(model.id).filter(*predicates).count()
            session.rollback()
        except Exception as error:
            session.rollback()
            current_app.logger.error("%s dry-run failed; transaction rolled back", label)
            raise click.ClickException(
                "Database cleanup dry-run failed; transaction rolled back"
            ) from error
        click.echo("Dry run: {0} {1} would be deleted".format(count, label))
        return count

    _confirm_cleanup(dry_run, assume_yes)
    total = 0
    while True:
        try:
            ids = [
                row[0]
                for row in (
                    session.query(model.id)
                    .filter(*predicates)
                    .order_by(model.id)
                    .limit(BATCH_SIZE)
                    .all()
                )
            ]
            if not ids:
                session.rollback()
                break

            deleted = _delete_ids(session, model, ids, predicates)
            session.commit()
        except Exception as error:
            session.rollback()
            current_app.logger.error("%s cleanup failed; transaction rolled back", label)
            raise click.ClickException(
                "Database cleanup failed; transaction rolled back"
            ) from error

        total += deleted

    current_app.logger.info("Deleted %d %s", total, label)
    click.echo("Deleted {0} {1}".format(total, label))
    return total


@cleanup.command("users")
@click.option(
    "--timedelta",
    "retention",
    type=POSITIVE_DURATION,
    default="hours=24",
    show_default=True,
)
@click.option("--dry-run", is_flag=True, help="Report eligible rows without deleting them.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip interactive confirmation.")
def cleanup_users(retention, dry_run, assume_yes):
    """Delete users that remained unconfirmed beyond the retention interval."""
    cutoff = datetime.datetime.utcnow() - retention
    predicates = (
        User.registered_at <= cutoff,
        User.confirmed_at.is_(None),
        User.email != current_app.config["ANONYMOUS_BOOTSTRAP_USER_EMAIL"],
        ~sa.exists().where(OAuth2Client.user_id == User.fs_uniquifier),
    )
    return _cleanup_rows(
        User, predicates, "stale unconfirmed users", dry_run, assume_yes
    )


@cleanup.command("tokens")
@click.option("--dry-run", is_flag=True, help="Report eligible rows without deleting them.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip interactive confirmation.")
def cleanup_tokens(dry_run, assume_yes):
    """Delete expired OAuth token rows, without deleting their parent clients."""
    cutoff = time.time()
    predicates = (
        OAuth2Token.issued_at.isnot(None),
        OAuth2Token.expires_in.isnot(None),
        OAuth2Token.issued_at + OAuth2Token.expires_in < cutoff,
        OAuth2Token.credential_delivery_pending.is_(False),
    )
    return _cleanup_rows(
        OAuth2Token, predicates, "expired OAuth tokens", dry_run, assume_yes
    )


@cleanup.command("clients")
@click.option(
    "--timedelta",
    "retention",
    type=POSITIVE_DURATION,
    default="days=90",
    show_default=True,
)
@click.option("--userid", default=None, help="Restrict deletion to one user ID.")
@click.option(
    "--ratelimit",
    type=NONNEGATIVE_FLOAT,
    default=1.0,
    show_default=True,
    help="Maximum client rate-limit multiplier eligible for deletion.",
)
@click.option("--dry-run", is_flag=True, help="Report eligible rows without deleting them.")
@click.option("--yes", "assume_yes", is_flag=True, help="Skip interactive confirmation.")
def cleanup_clients(retention, userid, ratelimit, dry_run, assume_yes):
    """Delete inactive OAuth clients satisfying every supplied restriction."""
    cutoff = datetime.datetime.utcnow() - retention
    predicates = [
        OAuth2Client.last_activity.isnot(None),
        OAuth2Client.last_activity <= cutoff,
        OAuth2Client.ratelimit_multiplier <= ratelimit,
        ~sa.exists().where(
            (OAuth2Token.client_id == OAuth2Client.id)
            & (
                OAuth2Token.credential_delivery_pending.is_(True)
                | (
                    OAuth2Token.issued_at + OAuth2Token.expires_in
                    >= int(time.time())
                )
            )
        ),
    ]
    if userid is not None:
        predicates.append(OAuth2Client.user_id == userid)
    return _cleanup_rows(
        OAuth2Client,
        tuple(predicates),
        "inactive OAuth clients",
        dry_run,
        assume_yes,
    )


@cli.group("notifications", short_help="Process durable notification outbox")
def notifications():
    """Notification delivery worker commands."""
    pass


@notifications.command("work")
@click.option("--once", is_flag=True, help="Process one claim batch and exit.")
def work_notifications(once):
    """Deliver queued notifications with bounded retries."""
    while True:
        processed = process_outbox_batch()
        if once:
            return
        if processed == 0:
            time.sleep(current_app.config.get("MAIL_OUTBOX_POLL_SECONDS", 1))


@notifications.command("cleanup")
def cleanup_notifications():
    """Delete one bounded batch of expired terminal notification rows."""
    deleted = cleanup_terminal_notifications()
    click.echo(f"Deleted {deleted} terminal notifications")


def parse_timedelta(value):
    """Parse one positive duration unit/value pair."""
    return POSITIVE_DURATION.convert(value, None, None)
