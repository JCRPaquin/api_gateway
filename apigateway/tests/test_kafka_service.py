from unittest.mock import MagicMock

import pytest
from flask import Flask, Response
from kafka.errors import KafkaTimeoutError

from apigateway import services
from apigateway.services import KafkaProducerService


def _response_snapshot(response):
    return response.status_code, response.get_data(), response.headers["X-Test"]


def _app_with_producer(monkeypatch, producer, user=None, token=None):
    app = Flask(__name__)
    app.config["KAFKA_PRODUCER_SERVICE_REQUEST_TOPIC"] = "test-requests"

    @app.get("/telemetry-test")
    def telemetry_test():
        return Response("original body", status=207, headers={"X-Test": "preserved"})

    service = KafkaProducerService()
    monkeypatch.setattr(service, "_init_producer", lambda: producer)
    service.init_app(app)

    if user is None:
        user = MagicMock()
        user.get_id.return_value = "user-1"
    user._get_current_object.return_value = user
    monkeypatch.setattr(services, "current_user", user)
    monkeypatch.setattr(services, "current_token", token)
    return app, service


class TestKafkaProducerService:
    def test_constructor_uses_immediate_admission_and_fire_and_forget(self, monkeypatch):
        producer_constructor = MagicMock()
        monkeypatch.setattr(services, "KafkaProducer", producer_constructor)
        app = Flask(__name__)
        app.config.update(
            KAFKA_PRODUCER_SERVICE_BOOTSTRAP_SERVERS=["kafka-a:9092", "kafka-b:9092"],
            KAFKA_PRODUCER_SERVICE_REQUEST_TIMEOUT_MS=321,
            KAFKA_PRODUCER_SERVICE_MAX_BLOCK_MS=0,
        )

        service = KafkaProducerService()
        service.init_app(app)

        producer_constructor.assert_called_once()
        options = producer_constructor.call_args.kwargs
        assert options["bootstrap_servers"] == "kafka-a:9092,kafka-b:9092"
        assert options["request_timeout_ms"] == 321
        assert options["max_block_ms"] == 0
        assert options["acks"] == 0

    @pytest.mark.parametrize("failure", [KafkaTimeoutError("metadata"), RuntimeError("secret")])
    def test_synchronous_send_failure_preserves_response(
        self, monkeypatch, caplog, failure
    ):
        producer = MagicMock()
        producer.send.side_effect = failure
        app, _ = _app_with_producer(monkeypatch, producer)

        response = app.test_client().get("/telemetry-test")

        assert _response_snapshot(response) == (207, b"original body", "preserved")
        assert "Kafka request telemetry dropped" in caplog.text
        assert str(failure) not in caplog.text

    def test_event_construction_failure_preserves_response(self, monkeypatch):
        producer = MagicMock()
        user = MagicMock()
        user.get_id.side_effect = ValueError("private user data")
        app, _ = _app_with_producer(monkeypatch, producer, user=user)

        response = app.test_client().get("/telemetry-test")

        assert _response_snapshot(response) == (207, b"original body", "preserved")
        producer.send.assert_not_called()

    def test_serialization_failure_preserves_response(self, monkeypatch):
        class SerializingProducer:
            def send(self, topic, event):
                services.json.dumps(event)

        monkeypatch.setattr(
            services.json, "dumps", MagicMock(side_effect=TypeError("unserializable"))
        )
        app, _ = _app_with_producer(monkeypatch, SerializingProducer())

        response = app.test_client().get("/telemetry-test")

        assert _response_snapshot(response) == (207, b"original body", "preserved")

    def test_no_producer_is_noop(self, monkeypatch):
        app, service = _app_with_producer(monkeypatch, None)

        response = app.test_client().get("/telemetry-test")

        assert _response_snapshot(response) == (207, b"original body", "preserved")
        assert service._producer is None

    def test_successful_send_occurs_once_without_wait_or_flush(self, monkeypatch):
        producer = MagicMock()
        future = MagicMock()
        producer.send.return_value = future
        token = MagicMock()
        token.client = MagicMock()
        token.client_id = "client-1"
        app, _ = _app_with_producer(monkeypatch, producer, token=token)

        response = app.test_client().get("/telemetry-test")

        assert _response_snapshot(response) == (207, b"original body", "preserved")
        producer.send.assert_called_once()
        topic, event = producer.send.call_args.args
        assert topic == "test-requests"
        assert event["user_id"] == "user-1"
        assert event["client_id"] == "client-1"
        assert event["endpoint"] == "telemetry_test"
        assert event["method"] == "GET"
        assert event["status_code"] == 207
        assert isinstance(event["timestamp"], str)
        future.get.assert_not_called()
        producer.flush.assert_not_called()
