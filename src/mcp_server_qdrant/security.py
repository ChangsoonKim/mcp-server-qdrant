from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from mcp_server_qdrant.settings import SecuritySettings

INTERNAL_METADATA_KEY = "__mcp"

_METADATA_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_COLLECTION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$")
_BIDI_CONTROL = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
_SENSITIVE_KEY = re.compile(
    r"(?:^|[_.-])(?:api_?key|access_?token|refresh_?token|password|passwd|secret|private_?key)(?:$|[_.-])",
    re.IGNORECASE,
)


class InputRejectedError(ValueError):
    """Raised for input that is unsafe or exceeds the configured boundary."""


def _validate_unicode(value: str, field_name: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if not normalized.strip():
        raise InputRejectedError(f"{field_name} must not be empty")
    if _BIDI_CONTROL.search(normalized):
        raise InputRejectedError(
            f"{field_name} contains disallowed bidirectional controls"
        )
    for character in normalized:
        codepoint = ord(character)
        if (codepoint < 32 and character not in "\n\r\t") or codepoint == 127:
            raise InputRejectedError(
                f"{field_name} contains disallowed control characters"
            )
    return normalized


def _contains_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in _SECRET_PATTERNS)


def validate_text(
    value: str,
    *,
    field_name: str,
    max_chars: int,
    reject_secrets: bool,
) -> str:
    if not isinstance(value, str):
        raise InputRejectedError(f"{field_name} must be text")
    value = _validate_unicode(value, field_name)
    if len(value) > max_chars:
        raise InputRejectedError(
            f"{field_name} exceeds the {max_chars} character limit"
        )
    if len(value.encode("utf-8")) > max_chars * 4:
        raise InputRejectedError(f"{field_name} exceeds the encoded size limit")
    if reject_secrets and _contains_secret(value):
        raise InputRejectedError(f"{field_name} appears to contain a secret")
    return value


def validate_information(value: str, settings: SecuritySettings) -> str:
    return validate_text(
        value,
        field_name="information",
        max_chars=settings.max_information_chars,
        reject_secrets=settings.reject_secrets,
    )


def validate_query(value: str, settings: SecuritySettings) -> str:
    return validate_text(
        value,
        field_name="query",
        max_chars=settings.max_query_chars,
        reject_secrets=False,
    )


def validate_collection_name(value: str) -> str:
    if not isinstance(value, str) or not _COLLECTION_NAME.fullmatch(value):
        raise InputRejectedError(
            "collection_name must be 1-255 letters, digits, underscores, or hyphens"
        )
    return value


def _walk_json(
    value: Any,
    *,
    depth: int,
    settings: SecuritySettings,
    key_counter: list[int],
    reject_sensitive_keys: bool,
) -> None:
    if depth > settings.max_metadata_depth:
        raise InputRejectedError("JSON input exceeds the nesting depth limit")
    if value is None or isinstance(value, str | bool | int):
        if isinstance(value, str):
            _validate_unicode(value, "JSON string")
            if settings.reject_secrets and _contains_secret(value):
                raise InputRejectedError("JSON input appears to contain a secret")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InputRejectedError("JSON input contains a non-finite number")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or not _METADATA_KEY.fullmatch(key):
                raise InputRejectedError(f"Invalid JSON object key: {key!r}")
            if reject_sensitive_keys and _SENSITIVE_KEY.search(key):
                raise InputRejectedError("JSON input contains a sensitive key name")
            key_counter[0] += 1
            if key_counter[0] > settings.max_metadata_keys:
                raise InputRejectedError("JSON input exceeds the key count limit")
            _walk_json(
                child,
                depth=depth + 1,
                settings=settings,
                key_counter=key_counter,
                reject_sensitive_keys=reject_sensitive_keys,
            )
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for child in value:
            _walk_json(
                child,
                depth=depth + 1,
                settings=settings,
                key_counter=key_counter,
                reject_sensitive_keys=reject_sensitive_keys,
            )
        return
    raise InputRejectedError("Input must contain JSON-compatible values only")


def validate_json_object(
    value: dict[str, Any] | None,
    settings: SecuritySettings,
    *,
    reject_reserved_key: bool = False,
    reject_sensitive_keys: bool = False,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InputRejectedError("Input must be a JSON object")
    if reject_reserved_key and INTERNAL_METADATA_KEY in value:
        raise InputRejectedError(
            f"The {INTERNAL_METADATA_KEY!r} metadata key is reserved"
        )
    _walk_json(
        value,
        depth=1,
        settings=settings,
        key_counter=[0],
        reject_sensitive_keys=reject_sensitive_keys,
    )
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError) as exc:
        raise InputRejectedError("Input must be valid JSON") from exc
    if len(encoded.encode("utf-8")) > settings.max_metadata_bytes:
        raise InputRejectedError(
            f"JSON input exceeds the {settings.max_metadata_bytes} byte limit"
        )
    return json.loads(encoded)


def public_metadata(metadata: dict[str, Any] | None) -> dict[str, Any] | None:
    if metadata is None:
        return None
    return {
        key: value for key, value in metadata.items() if key != INTERNAL_METADATA_KEY
    }
