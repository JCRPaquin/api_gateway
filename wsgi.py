from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

from apigateway.app import create_app

_gateway = create_app()
FlaskInstrumentor.instrument_app(_gateway)

with _gateway.app_context():
    SQLAlchemyInstrumentor().instrument(engine=_gateway.db.engine)

application = DispatcherMiddleware(Response("Not Found", status=404), {"/v1": _gateway})
del _gateway
