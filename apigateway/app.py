from pathlib import Path

from adsmutils import ADSFlask
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
)
from flask import Flask, abort, current_app, jsonify, request, session
from flask_restful import Api
from marshmallow import ValidationError as MarshmallowValidationError
from werkzeug.middleware.proxy_fix import ProxyFix

from apigateway import config as gateway_config
from apigateway import exceptions, extensions, views
from apigateway.logging_utils import exception_log_fields
from apigateway.models import OAuth2Client, OAuth2Token, User

from opentelemetry.sdk.resources import SERVICE_NAME, Resource

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader, ConsoleMetricExporter


from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

_APP_NAME = __name__
_PROJECT_ROOT = Path(__file__).resolve().parent


def register_extensions(app: Flask):
    """Register extensions.

    Args:
        app (Flask): Application object
    """

    extensions.db.init_app(app)
    app.db = extensions.db
    extensions.ma.init_app(app)

    extensions.cors.init_app(
        app,
        origins=app.config.get("CORS_DOMAINS"),
        allow_headers=app.config.get("CORS_HEADERS"),
        methods=app.config.get("CORS_METHODS"),
        supports_credentials=True,
        intercept_exceptions=True,
    )

    extensions.oauth2_server.init_app(
        app,
        query_client=create_query_client_func(extensions.db.session, OAuth2Client),
        save_token=create_save_token_func(extensions.db.session, OAuth2Token),
    )

    extensions.login_manager.init_app(app)
    extensions.redis_service.init_app(app)
    extensions.security_service.init_app(app)
    extensions.auth_service.init_app(app)
    extensions.proxy_service.init_app(app)
    extensions.limiter_service.init_app(app)
    extensions.cache_service.init_app(app)
    extensions.kakfa_producer_service.init_app(app)
    extensions.storage_service.init_app(app, extensions.redis_service)
    extensions.talisman.init_app(
        app,
        force_https=app.config["HTTPS_ENFORCEMENT"],
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_http_only=app.config["SESSION_COOKIE_HTTPONLY"],
        strict_transport_security=True,
    )
    extensions.csrf.init_app(app)


def register_authority_guard(app: Flask):
    """Reject malformed or untrusted request authorities before route handlers."""

    @app.before_request
    def require_trusted_authority():
        host_headers = request.headers.getlist("Host")
        if len(host_headers) != 1:
            abort(400)
        try:
            authority = gateway_config.canonical_authority(host_headers[0])
        except ValueError:
            abort(400)
        if authority not in app.config["TRUSTED_HOSTS"]:
            abort(400)


def register_hooks(app: Flask):
    """Register hooks

    Args:
        app (Flask): Application object
    """

    @app.before_request
    def make_session_permanent():
        session.permanent = True

    @app.login_manager.user_loader
    def load_user(user_id):
        return User.query.filter_by(fs_uniquifier=user_id).first()

    @app.login_manager.unauthorized_handler
    def unauthorized():
        """
        flask_login callback when @login_required is not met.
        This overrides the default behavior or re-directing to a login view
        """
        abort(401)
        
    @app.teardown_request
    def teardown_request(exception=None):
        """This function will close active transaction, if there is one
        but only if the session is not dirty - we don't want to do any
        magic (instead of a developer)
        
        use expire_on_commit=False doesn't have the same effect
        http://docs.sqlalchemy.org/en/latest/orm/session_api.html#sqlalchemy.orm.session.Session.commit
        
        The problems we are facing is that a new transaction gets opened
        when session is committed; consequent access to the ORM objects
        opens a new transaction (which never gets closed and is rolled back)
        """
        a = current_app
        if 'sqlalchemy' in a.extensions: # could use self.db but let's be very careful
            sa = a.extensions['sqlalchemy']
            if hasattr(sa, 'db') and hasattr(sa.db, 'session') and sa.db.session.is_active:
                if bool(sa.db.session.dirty):
                    sa.db.session.close() # db server will do rollback
                else:
                    sa.db.session.commit() # normal situation        
    return app


def register_error_handlers(app: Flask):
    """Register error handlers for the Flask app.

    Args:
        app (Flask): The Flask app instance.
    """

    @app.errorhandler(MarshmallowValidationError)
    def marshmallow_validation_error(e):
        return jsonify({"message": e.normalized_messages()}), 400

    @app.errorhandler(exceptions.NotFoundError)
    def not_found_error(e):
        return jsonify({"message": e.value}), 404

    @app.errorhandler(exceptions.ValidationError)
    def validation_error(e):
        return jsonify({"message": e.value}), 400

    @app.errorhandler(exceptions.NoClientError)
    def no_client_error(e):
        return jsonify({"message": e.value}), 500

    @app.errorhandler(400)
    def on_400(e):
        return jsonify({"message": "Bad request"}), 400

    @app.errorhandler(401)
    def on_401(e):
        return jsonify({"message": "Unauthorized"}), 401

    @app.errorhandler(405)
    def on_405(e):
        return jsonify({"message": "Method not allowed"}), 405

    @app.errorhandler(404)
    def on_404(e):
        return jsonify({"message": "Not found"}), 404


def register_verbose_exception_logging(app: Flask):
    """Configure exception logging with an allowlisted request context."""

    def log_exception(exc_info):
        exception = exc_info[1]
        app.logger.error(
            "Unhandled request exception method=%s route=%s exception=%s",
            *exception_log_fields(exception),
        )

    app.log_exception = log_exception


def register_views(flask_api: Api):
    """Registers the views for the Flask application."""
    flask_api.add_resource(views.BootstrapView, "/accounts/bootstrap")
    flask_api.add_resource(views.CSRFView, "/accounts/csrf")
    flask_api.add_resource(views.StatusView, "/accounts/status")
    flask_api.add_resource(views.OAuthProtectedView, "/accounts/protected")
    flask_api.add_resource(views.UserAuthView, "/accounts/user/login")
    flask_api.add_resource(views.LogoutView, "/accounts/user/logout")
    flask_api.add_resource(views.UserManagementView, "/accounts/user")
    flask_api.add_resource(views.UserResolverView, "/accounts/user/<string:id>")
    flask_api.add_resource(views.PersonalTokenView, "/accounts/user/token")
    flask_api.add_resource(views.ChangePasswordView, "/accounts/user/change-password")
    flask_api.add_resource(views.ChangeEmailView, "/accounts/user/change-email")

    flask_api.add_resource(
        views.VerifyEmailView,
        "/accounts/verify/<string:token>",
        "/accounts/user/<string:email>/verify",
    )
    flask_api.add_resource(
        views.ResetPasswordView,
        "/accounts/user/reset-password/<string:token_or_email>",
    )
    flask_api.add_resource(views.UserInfoView, "/accounts/info/<string:account_data>")
    flask_api.add_resource(views.ChacheManagementView, "/admin/cache")
    flask_api.add_resource(views.LimiterManagementView, "/admin/limit")
    flask_api.add_resource(views.UserFeedbackView, "/feedback")
    flask_api.add_resource(views.Resources, "/resources")


def create_app(*, allow_insecure_test_config=False, **local_config):
    """Create the application and initialize its dependencies.

    ``allow_insecure_test_config`` is a factory-only escape for explicit
    network-facing test bypasses. It is accepted only together with
    ``TESTING=True`` and cannot be supplied through application configuration.
    """
    effective_config = {
        key: value for key, value in vars(gateway_config).items() if key.isupper()
    }
    effective_config.update(local_config)
    database_uri = effective_config.get("SQLALCHEMY_DATABASE_URI")

    # ADSFlask v2 creates its own Flask-SQLAlchemy extension whenever a
    # database URI is present. Suppress that initialization so the gateway's
    # extension, which owns base_model, remains the sole database extension.
    adsmutils_config = dict(effective_config)
    adsmutils_config["SQLALCHEMY_DATABASE_URI"] = None

    # ADSFlask v2 always invokes its legacy config loader. The repository root
    # intentionally has no config.py, so pointing it there prevents a second
    # environment pass from retyping values or logging secrets. The complete
    # application configuration is supplied explicitly below.
    app = ADSFlask(
        _APP_NAME,
        static_folder=None,
        template_folder="templates",
        proj_home=str(_PROJECT_ROOT.parent),
        local_config=adsmutils_config,
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = database_uri

    gateway_config.validate_runtime_config(
        app.config,
        allow_insecure_test_config=allow_insecure_test_config,
    )
    trusted_proxy_hops = app.config["TRUSTED_PROXY_HOPS"]
    if trusted_proxy_hops:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=trusted_proxy_hops)
    register_authority_guard(app)

    # Service name is required for most backends,
    # and although it's not necessary for console export,
    # it's good to set service name anyways.
    if app.config.get('ENABLE_OTEL', False):
        resource = Resource(attributes={
            SERVICE_NAME: app.config.get('OTEL_SERVICE_NAME')
        })
        if app.config.get('ENABLE_OTEL') == 'EXPORTER':
            tracerProvider = TracerProvider(resource=resource)
            processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=app.config.get('OTEL_TRACES_ENDPOINT','http://localhost:4318/v1/traces')))
            tracerProvider.add_span_processor(processor)
            trace.set_tracer_provider(tracerProvider)

            if app.config.get('OTEL_ENABLE_METRICS'):
                reader = PeriodicExportingMetricReader(
                    OTLPMetricExporter(endpoint=app.config.get('OTEL_METRICS_ENDPOINT', 'http://localhost:9091/v1/metrics'))
                )
                meterProvider = MeterProvider(resource=resource, metric_readers=[reader])
                metrics.set_meter_provider(meterProvider)

        elif app.config.get('ENABLE_OTEL') == 'CONSOLE':
            tracerProvider = TracerProvider(resource=resource)
            processor = BatchSpanProcessor(ConsoleSpanExporter())
            tracerProvider.add_span_processor(processor)
            trace.set_tracer_provider(tracerProvider)
            
            if app.config.get('OTEL_ENABLE_METRICS'):
                reader = PeriodicExportingMetricReader(ConsoleMetricExporter())
                meterProvider = MeterProvider(resource=resource, metric_readers=[reader])
                metrics.set_meter_provider(meterProvider)

    flask_api = Api(app)
    register_verbose_exception_logging(app)
    register_extensions(app)
    register_hooks(app)
    register_error_handlers(app)
    register_views(flask_api)

    extensions.proxy_service.register_services()

    return app
