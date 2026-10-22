"""Helpers used by Alembic without exposing application configuration."""

from typing import Callable, Optional

from flask import Flask


def get_app_config(key: str, app_factory: Optional[Callable[[], Flask]] = None):
    """Resolve an application setting without writing its value to output."""
    if app_factory is None:
        from apigateway.app import create_app

        app_factory = create_app

    app = app_factory()
    with app.app_context():
        return app.config.get(key)
