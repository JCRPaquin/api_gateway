import datetime
import time

import click
from flask import current_app
from flask.cli import FlaskGroup
from sqlalchemy import and_

from apigateway.app import create_app
from apigateway.models import OAuth2Client, OAuth2Token, User
from apigateway.notifications import cleanup_terminal_notifications, process_outbox_batch



@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    pass


@cli.group("cleanup", short_help="Cleanup commands")
def cleanup():
    """Cleanup commands related to the app"""
    pass


@cleanup.command("users")
@click.option("--timedelta", nargs=1, default="hours=24")
def cleanup_users(timedelta):
    """
    Deletes stale users from the database. Stale users are defined as users
    that have a registered_at value of `now`-`timedelta` but not confirmed_at
    value

    This is expected to coorespond to users that created an account but never
    verified it.

    :param timedelta: String representing the datetime.timedelta against which
            to compare user's registered_at ["hours=24"].
    :return: None
    """

    td = parse_timedelta(timedelta)

    with current_app.app_context():
        deletions = 0
        for user in (
            current_app.db.session.query(User)
            .filter(
                User.registered_at <= datetime.datetime.now() - td,
                User.confirmed_at == None,  # noqa
            )
            .yield_per(100)
        ):
            current_app.db.session.delete(user)
            deletions += 1
            current_app.logger.info("Deleted unverified user: {}".format(user.email))

        try:
            current_app.db.session.commit()
        except Exception as e:
            current_app.db.session.rollback()
            current_app.logger.error(
                "Could not cleanup stale users. " "Database error; rolled back: {0}".format(e)
            )
        current_app.logger.info("Deleted {0} stale users".format(deletions))


@cleanup.command("tokens")
def cleanup_tokens():
    """
    Cleans expired oauth2tokens from the database defined in
    app.config['SQLALCHEMY_DATABASE_URI']
    :return: None
    """

    with current_app.app_context():
        total = 0
        deletions = None
        while deletions != 0:
            deletions = 0
            # go through the expired tokens and delete the associated client
            # every client should have only one token (that's by design)
            # faster way - not portable though - would be to delete anything
            # selected by the following query:
            # select c.user_id, c.client_id from oauth2client AS c LEFT OUTER JOIN oauth2token AS t
            # ON c.client_id = t.client_id WHERE t.access_token is null
            for token in (
                current_app.db.session.query(OAuth2Token)
                .filter(
                    OAuth2Token.expires_in != None,  # noqa
                    (OAuth2Token.issued_at + OAuth2Token.expires_in) < time.time(),
                )
                .limit(1000)
                .yield_per(100)
            ):

                # for some odd reasons, even though clients-tokens are associated
                # the deletes didn't cascade on postgres; so let's delete them
                # explicitly
                if token.client:
                    current_app.db.session.delete(token.client)
                current_app.db.session.delete(token)
                deletions += 1
            try:
                current_app.db.session.commit()
                total += deletions
                current_app.logger.info(
                    "Deleted {0} expired oauth2tokens/oauth2clients".format(deletions)
                )
            except Exception as e:
                current_app.db.session.rollback()
                current_app.logger.error(
                    "Could not cleanup expired oauth2tokens. "
                    "Database error; rolled back: {0}".format(e)
                )
                total -= deletions

        current_app.logger.info(
            "Deleted total of {0} expired oauth2tokens/oauth2clients".format(total)
        )


@cleanup.command("clients")
@click.option("--timedelta", nargs=1, default="days=90")
@click.option("--userid", nargs=1, default=None)
@click.option("--ratelimit", nargs=1, default=1.0)
def cleanup_clients(timedelta, userid, ratelimit):
    """
    Cleans expired oauth2clients that are older than a specified date in the
    database defined in app.config['SQLALCHEMY_DATABASE_URI']

    WARNING: do not use this function lightly! For cleaning, use cleanup_tokens
    instead; that one will remove an oauth2token whose token has expired. This
    function, instead, will remove any client that wasn't used in past X days,
    even if it is still valid.

    :param timedelta: String representing the datetime.timedelta against which
            to compare client's last_activity ["days=365"].
    :type timedelta: basestring
    :param userid: numerical id of the user account, deletes will be limited
            only to clients of that user
    :param ratelimit: int, default=1; ony clients that have limit lower or
            equal to this value will be deleted
    :return: None
    """

    if ratelimit is None:
        ratelimit = 1.0
    else:
        ratelimit = float(ratelimit)

    td = parse_timedelta(timedelta)

    with current_app.app_context():
        deletions = 0
        if userid is not None:
            for client in (
                current_app.db.session.query(OAuth2Client)
                .filter(
                    and_(
                        OAuth2Client.last_activity <= datetime.datetime.now() - td,
                        OAuth2Client.user_id == userid,
                        OAuth2Client.ratelimit_multiplier <= ratelimit,
                    )
                )
                .yield_per(1000)
            ):

                current_app.db.session.delete(client)
                deletions += 1
        else:
            for client in (
                current_app.db.session.query(OAuth2Client)
                .filter(
                    OAuth2Client.last_activity <= datetime.datetime.now() - td,
                    OAuth2Client.ratelimit_multiplier <= ratelimit,
                )
                .yield_per(1000)
            ):

                current_app.db.session.delete(client)
                deletions += 1
        try:
            current_app.db.session.commit()
        except Exception as e:
            current_app.db.session.rollback()
            current_app.logger.error(
                "Could not cleanup expired oauth2clients. "
                "Database error; rolled back: {0}".format(e)
            )
            return
        current_app.logger.info(
            "Deleted {0} oauth2clients whose last_activity was "
            "at least {1} old and userid={2}".format(deletions, timedelta, userid)
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


def parse_timedelta(s):
    """
    Helper function which converts a string formatted timedelta into a
    datetime.timedelta object

    :param s: string formatted timedelta (e.g. "days=1")
    :return: parsed timedelta
    :rtype: datetime.timedelta
    """

    td = {s.split("=")[0]: float(s.split("=")[1])}
    return datetime.timedelta(**td)
