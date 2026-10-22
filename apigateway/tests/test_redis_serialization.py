import math
from unittest.mock import MagicMock, call

import pytest
from flask import Flask, Response

from apigateway.redis_serialization import (
    RedisJsonCodec,
    RedisSerializationError,
    SafeRedisCache,
    dumps_storage_value,
    loads_storage_value,
)
from apigateway.services import CacheService, StorageService


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        False,
        0,
        -12345678901234567890,
        1.25,
        -0.0,
        "GWJ1:user data",
        "snowman: ☃",
        b"\x00\xffpayload",
        [None, True, 3, "value"],
        (b"body", 200, {"Content-Type": "application/json"}),
        {
            "/example": {
                "description": "A description",
                "methods": ["OPTIONS", "GET", "HEAD"],
                "scopes": ["api"],
                "rate_limit": [300, 86400],
            }
        },
    ],
)
def test_codec_round_trips_supported_values(value):
    codec = RedisJsonCodec()

    encoded = codec.dumps(value)

    assert encoded.startswith(b"GWJ1:")
    assert codec.loads(encoded) == value
    if isinstance(value, float) and value == 0:
        assert math.copysign(1, codec.loads(encoded)) == math.copysign(1, value)


def test_codec_distinguishes_boolean_from_integer():
    codec = RedisJsonCodec()

    assert codec.dumps(True) != codec.dumps(1)
    assert codec.loads(codec.dumps(True)) is True
    assert type(codec.loads(codec.dumps(1))) is int


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_codec_rejects_non_finite_floats(value):
    with pytest.raises(RedisSerializationError):
        RedisJsonCodec().dumps(value)


@pytest.mark.parametrize(
    "wire_value",
    [
        b"",
        b"!legacy-pickle",
        b"GWJ0:[\"none\"]",
        b"GWJ2:[\"none\"]",
        b"GWJ1:\xff",
        b"GWJ1:not-json",
        b"GWJ1:[\"unknown\"]",
        b"GWJ1:[\"float\",\"NaN\"]",
        b"GWJ1:[\"bytes\",\"not base64!\"]",
        b"GWJ1:[\"dict\",[[\"duplicate\",[\"none\"]],[\"duplicate\",[\"none\"]]]]",
    ],
)
def test_codec_rejects_malformed_unknown_and_legacy_values(wire_value):
    with pytest.raises(RedisSerializationError):
        RedisJsonCodec().loads(wire_value)


def test_legacy_marker_never_calls_pickle(monkeypatch):
    pickle_loads = MagicMock(side_effect=AssertionError("pickle.loads must not be called"))
    monkeypatch.setattr("pickle.loads", pickle_loads)

    with pytest.raises(RedisSerializationError):
        RedisJsonCodec().loads(b"!legacy-pickle")

    pickle_loads.assert_not_called()


@pytest.mark.parametrize("value", [set(), object(), {1: "non-string key"}])
def test_codec_rejects_unsupported_values(value):
    with pytest.raises(RedisSerializationError):
        RedisJsonCodec().dumps(value)


def test_storage_numeric_values_use_strict_redis_native_ascii():
    codec = RedisJsonCodec()

    assert dumps_storage_value(codec, 42) == b"42"
    assert dumps_storage_value(codec, -1.25) == b"-1.25"
    assert loads_storage_value(codec, b"42") == 42
    assert loads_storage_value(codec, b"-1.25") == -1.25
    for invalid in (
        b"+1",
        b"-0",
        b"01",
        b"1.00",
        b"1e01",
        b" 1",
        b"1 ",
        b"nan",
        b"inf",
        b"True",
    ):
        with pytest.raises(RedisSerializationError):
            loads_storage_value(codec, invalid)


def make_storage_service():
    app = Flask(__name__)
    redis_service = MagicMock()
    service = StorageService()
    service.init_app(app, redis_service)
    return service, redis_service


def test_storage_prefixes_set_get_delete_has_and_atomic_operations():
    service, redis_service = make_storage_service()
    prefix = "gateway:storage:v1:counter"

    redis_service.set.return_value = True
    assert service.set("counter", 4) is True
    redis_service.set.assert_called_once_with(prefix, b"4")

    redis_service.get.return_value = b"4"
    assert service.get("counter") == 4
    assert service.has("counter") is True
    assert redis_service.get.call_args_list[-2:] == [call(prefix), call(prefix)]

    redis_service.delete.return_value = 1
    assert service.delete("counter") is True
    redis_service.delete.assert_called_with(prefix)

    service.incr("counter")
    service.incrby("counter", 3)
    service.incrbyfloat("counter", 0.5)
    redis_service.incr.assert_called_once_with(prefix)
    redis_service.incrby.assert_called_once_with(prefix, 3)
    redis_service.incrbyfloat.assert_called_once_with(prefix, 0.5)


def test_storage_prefixes_setex():
    service, redis_service = make_storage_service()
    redis_service.setex.return_value = True

    assert service.set("resource", {"resources": []}, timeout=60) is True

    key, timeout, encoded = redis_service.setex.call_args.args
    assert key == "gateway:storage:v1:resource"
    assert timeout == 60
    assert RedisJsonCodec().loads(encoded) == {"resources": []}


def test_storage_invalid_value_is_deleted_and_becomes_a_miss():
    service, redis_service = make_storage_service()
    redis_service.get.return_value = b"!legacy-pickle"

    assert service.get("resource-url") is None
    assert service.has("resource-url") is False
    assert redis_service.delete.call_args_list == [
        call("gateway:storage:v1:resource-url"),
        call("gateway:storage:v1:resource-url"),
    ]


def test_fallback_transfer_preserves_resource_document_type_and_prefix():
    service, redis_service = make_storage_service()
    resource_document = {
        "/example": {
            "description": "A description",
            "methods": ["OPTIONS", "GET", "HEAD"],
            "scopes": ["api"],
            "rate_limit": [300, 86400],
        }
    }
    service._redis_down = True

    service.set("https://example.test/resources", resource_document)
    service._redis_down = False
    service._transfer_to_redis()

    key, encoded = redis_service.set.call_args.args
    assert key == "gateway:storage:v1:https://example.test/resources"
    assert RedisJsonCodec().loads(encoded) == resource_document
    assert isinstance(RedisJsonCodec().loads(encoded), dict)
    assert service._fallback_storage == {}


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.deleted = []

    def get(self, key):
        return self.values.get(key)

    def mget(self, keys):
        return [self.values.get(key) for key in keys]

    def set(self, key, value, **kwargs):
        if kwargs.get("nx") and key in self.values:
            return False
        self.values[key] = value
        return True

    def setex(self, name, time, value):
        self.values[name] = value
        return True

    def delete(self, *keys):
        self.deleted.extend(keys)
        return sum(self.values.pop(key, None) is not None for key in keys)

    def flushdb(self):
        self.values.clear()
        return True


def make_cache_service():
    app = Flask(__name__)
    app.config.update(
        CACHE_SERVICE_REDIS_URI="redis://localhost:6379/1",
        CACHE_SERVICE_CACHE_TYPE="apigateway.redis_serialization.SafeRedisCache",
        CACHE_SERVICE_KEY_PREFIX="gateway:cache:v1:",
    )
    service = CacheService()
    service.init_app(app)
    backend = app.extensions["cache"][service]
    fake_redis = FakeRedis()
    backend._read_client = fake_redis
    backend._write_client = fake_redis
    return app, service, backend, fake_redis


def test_cache_uses_explicit_safe_backend_serializer_and_prefix():
    app, service, backend, fake_redis = make_cache_service()

    assert isinstance(backend, SafeRedisCache)
    assert isinstance(backend.serializer, RedisJsonCodec)
    assert app.config["CACHE_REDIS_URL"].endswith("/1")
    assert app.config["CACHE_KEY_PREFIX"] == "gateway:cache:v1:"
    with app.app_context():
        assert service.set("proxy", (b"body", 200, {"X-Test": "yes"})) is True
        assert service.get("proxy") == (b"body", 200, {"X-Test": "yes"})
    assert list(fake_redis.values) == ["gateway:cache:v1:proxy"]


def test_cache_legacy_value_is_deleted_and_becomes_a_miss():
    app, service, _, fake_redis = make_cache_service()
    key = "gateway:cache:v1:proxy"
    fake_redis.values[key] = b"!legacy-pickle"

    with app.app_context():
        assert service.get("proxy") is None
    assert fake_redis.deleted == [key]
    assert key not in fake_redis.values


def test_cache_bulk_read_removes_only_invalid_values():
    app, _, backend, fake_redis = make_cache_service()
    codec = RedisJsonCodec()
    valid_key = "gateway:cache:v1:valid"
    invalid_key = "gateway:cache:v1:invalid"
    fake_redis.values[valid_key] = codec.dumps({"status": 200})
    fake_redis.values[invalid_key] = b"!legacy-pickle"

    with app.app_context():
        assert backend.get_many("valid", "invalid", "missing") == [
            {"status": 200},
            None,
            None,
        ]

    assert fake_redis.deleted == [invalid_key]
    assert valid_key in fake_redis.values


def test_unsupported_cache_write_does_not_replace_live_response():
    app, service, _, fake_redis = make_cache_service()

    @service.cached()
    def live_view():
        return Response(b"live response", status=202, headers={"X-Live": "yes"})

    with app.test_request_context("/live"):
        response = live_view()

    assert response.status_code == 202
    assert response.data == b"live response"
    assert response.headers["X-Live"] == "yes"
    assert fake_redis.values == {}
