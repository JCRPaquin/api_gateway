from apigateway import extensions


def test_create_app_uses_gateway_database_extension(app):
    assert app.db is extensions.db
    assert app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///:memory:"
