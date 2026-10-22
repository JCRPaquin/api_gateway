from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

from apigateway.app import create_app

app = create_app()
FlaskInstrumentor.instrument_app(app)

with app.app_context():
    SQLAlchemyInstrumentor().instrument(engine=app.db.engine)

application = DispatcherMiddleware(Response("Not Found", status=404), {"/v1": app})
