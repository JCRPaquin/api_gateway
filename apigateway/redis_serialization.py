"""Safe, application-owned serialization for Redis-backed state."""

import base64
import binascii
import json
import math
import re
from typing import Any

from flask_caching.backends import RedisCache


class RedisSerializationError(ValueError):
    """Raised when a value is not part of the Redis serialization contract."""


class RedisJsonCodec:
    """Encode the gateway's supported values as versioned, tagged JSON."""

    PREFIX = b"GWJ1:"

    def dumps(self, value: Any) -> bytes:
        """Return the versioned wire representation for ``value``."""
        try:
            node = self._encode_node(value)
            payload = json.dumps(
                node, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
        except RedisSerializationError:
            raise
        except (
            TypeError,
            ValueError,
            OverflowError,
            UnicodeEncodeError,
            RecursionError,
        ) as exc:
            raise RedisSerializationError("value cannot be serialized safely") from exc
        return self.PREFIX + payload

    def loads(self, value: bytes) -> Any:
        """Decode a versioned value, rejecting every unversioned representation."""
        if value is None:
            return None
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise RedisSerializationError("serialized value must be bytes")

        wire_value = bytes(value)
        if not wire_value.startswith(self.PREFIX):
            raise RedisSerializationError("unknown or missing serialization version")

        try:
            payload = wire_value[len(self.PREFIX) :].decode("utf-8")
            node = json.loads(payload, parse_constant=self._reject_json_constant)
            return self._decode_node(node)
        except RedisSerializationError:
            raise
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            OverflowError,
            ValueError,
            RecursionError,
        ) as exc:
            raise RedisSerializationError("malformed serialized value") from exc

    @staticmethod
    def _reject_json_constant(value: str):
        raise RedisSerializationError(f"unsupported JSON constant: {value}")

    def _encode_node(self, value: Any) -> list:
        if value is None:
            return ["none"]
        if isinstance(value, bool):
            return ["bool", value]
        if isinstance(value, int):
            return ["int", str(value)]
        if isinstance(value, float):
            if not math.isfinite(value):
                raise RedisSerializationError("non-finite floats are not supported")
            return ["float", repr(value)]
        if isinstance(value, str):
            return ["string", value]
        if isinstance(value, bytes):
            return ["bytes", base64.b64encode(value).decode("ascii")]
        if isinstance(value, list):
            return ["list", [self._encode_node(item) for item in value]]
        if isinstance(value, tuple):
            return ["tuple", [self._encode_node(item) for item in value]]
        if isinstance(value, dict):
            encoded_items = []
            for key, item in value.items():
                if not isinstance(key, str):
                    raise RedisSerializationError("dictionary keys must be strings")
                encoded_items.append([key, self._encode_node(item)])
            return ["dict", encoded_items]
        raise RedisSerializationError(f"unsupported value type: {type(value).__name__}")

    def _decode_node(self, node: Any) -> Any:
        if not isinstance(node, list) or not node or not isinstance(node[0], str):
            raise RedisSerializationError("malformed tagged node")

        tag = node[0]
        if tag == "none" and len(node) == 1:
            return None
        if tag == "bool" and len(node) == 2 and isinstance(node[1], bool):
            return node[1]
        if tag == "int" and len(node) == 2 and isinstance(node[1], str):
            if not _INTEGER_PATTERN.fullmatch(node[1]):
                raise RedisSerializationError("malformed integer node")
            value = int(node[1])
            if str(value) != node[1]:
                raise RedisSerializationError("non-canonical integer node")
            return value
        if tag == "float" and len(node) == 2 and isinstance(node[1], str):
            if not _FLOAT_PATTERN.fullmatch(node[1]):
                raise RedisSerializationError("malformed float node")
            value = float(node[1])
            if not math.isfinite(value) or repr(value) != node[1]:
                raise RedisSerializationError("non-finite or non-canonical float node")
            return value
        if tag == "string" and len(node) == 2 and isinstance(node[1], str):
            try:
                node[1].encode("utf-8")
            except UnicodeEncodeError as exc:
                raise RedisSerializationError("malformed string node") from exc
            return node[1]
        if tag == "bytes" and len(node) == 2 and isinstance(node[1], str):
            try:
                encoded = node[1].encode("ascii")
                value = base64.b64decode(encoded, validate=True)
            except (UnicodeEncodeError, binascii.Error) as exc:
                raise RedisSerializationError("malformed base64 node") from exc
            if base64.b64encode(value) != encoded:
                raise RedisSerializationError("non-canonical base64 node")
            return value
        if tag in ("list", "tuple") and len(node) == 2 and isinstance(node[1], list):
            values = [self._decode_node(item) for item in node[1]]
            return values if tag == "list" else tuple(values)
        if tag == "dict" and len(node) == 2 and isinstance(node[1], list):
            value = {}
            for item in node[1]:
                if (
                    not isinstance(item, list)
                    or len(item) != 2
                    or not isinstance(item[0], str)
                    or item[0] in value
                ):
                    raise RedisSerializationError("malformed dictionary node")
                try:
                    item[0].encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise RedisSerializationError("malformed dictionary key") from exc
                value[item[0]] = self._decode_node(item[1])
            return value
        raise RedisSerializationError("unknown or malformed tagged node")


_INTEGER_PATTERN = re.compile(r"-?(?:0|[1-9][0-9]*)")
_FLOAT_PATTERN = re.compile(
    r"-?(?:(?:0|[1-9][0-9]*)\.(?:0|[0-9]*[1-9])|"
    r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?e"
    r"(?:\+(?:[1-9][0-9]*)|-(?:0[1-9]|[1-9][0-9]*)))"
)


def dumps_storage_value(codec: RedisJsonCodec, value: Any) -> bytes:
    """Encode top-level numbers as Redis-native canonical ASCII values."""
    if isinstance(value, bool):
        return codec.dumps(value)
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RedisSerializationError("non-finite floats are not supported")
        return repr(value).encode("ascii")
    return codec.dumps(value)


def loads_storage_value(codec: RedisJsonCodec, value: bytes) -> Any:
    """Decode a storage value without accepting arbitrary unversioned bytes."""
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RedisSerializationError("serialized value must be bytes")

    wire_value = bytes(value)
    if wire_value.startswith(codec.PREFIX):
        return codec.loads(wire_value)

    try:
        numeric_value = wire_value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RedisSerializationError("invalid storage value") from exc

    if _INTEGER_PATTERN.fullmatch(numeric_value):
        try:
            parsed_integer = int(numeric_value)
        except ValueError as exc:
            raise RedisSerializationError("invalid storage integer") from exc
        if str(parsed_integer) == numeric_value:
            return parsed_integer
    if _FLOAT_PATTERN.fullmatch(numeric_value):
        parsed_value = float(numeric_value)
        if math.isfinite(parsed_value):
            return parsed_value
    raise RedisSerializationError("invalid storage value")


class SafeRedisCache(RedisCache):
    """Redis cache backend that fails closed for unsafe cache values."""

    def _decode_value(self, key: str, value: bytes) -> tuple[bool, Any]:
        if value is None:
            return False, None
        try:
            return True, self.serializer.loads(value)
        except RedisSerializationError:
            try:
                super().delete(key)
            except Exception:  # A failed cleanup must still remain a cache miss.
                pass
            return False, None

    def get(self, key: str) -> Any:
        value = self._read_client.get(self._get_prefix() + key)
        return self._decode_value(key, value)[1]

    def get_many(self, *keys: str) -> list[Any]:
        if not keys:
            return []
        prefix = self._get_prefix()
        values = self._read_client.mget([prefix + key for key in keys])
        return [self._decode_value(key, value)[1] for key, value in zip(keys, values)]

    def has(self, key: str) -> bool:
        value = self._read_client.get(self._get_prefix() + key)
        return self._decode_value(key, value)[0]

    def set(self, key: str, value: Any, timeout: int = None) -> bool:
        try:
            return super().set(key, value, timeout=timeout)
        except RedisSerializationError:
            return False

    def add(self, key: str, value: Any, timeout: int = None) -> bool:
        try:
            return super().add(key, value, timeout=timeout)
        except RedisSerializationError:
            return False

    def set_many(self, mapping: dict, timeout: int = None) -> list:
        try:
            return super().set_many(mapping, timeout=timeout)
        except RedisSerializationError:
            return list(mapping)
