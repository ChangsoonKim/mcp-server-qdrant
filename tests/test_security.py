import pytest

from mcp_server_qdrant.security import (
    INTERNAL_METADATA_KEY,
    InputRejectedError,
    public_metadata,
    validate_collection_name,
    validate_information,
    validate_json_object,
    validate_query,
)
from mcp_server_qdrant.settings import SecuritySettings


@pytest.fixture
def settings():
    return SecuritySettings(
        INPUT_MAX_INFORMATION_CHARS=32,
        INPUT_MAX_QUERY_CHARS=16,
        INPUT_MAX_METADATA_BYTES=256,
        INPUT_MAX_METADATA_DEPTH=3,
        INPUT_MAX_METADATA_KEYS=4,
    )


def test_information_is_normalized_and_bounded(settings):
    assert validate_information("cafe\u0301", settings) == "café"
    with pytest.raises(InputRejectedError, match="character limit"):
        validate_information("x" * 33, settings)
    with pytest.raises(InputRejectedError, match="control"):
        validate_information("hello\x00world", settings)


def test_likely_secrets_are_rejected_without_echoing_them(settings):
    candidate = "sk-abcdefghijklmnopqrstuvwxyz123456"
    with pytest.raises(InputRejectedError) as exc_info:
        validate_information(candidate, settings)
    assert candidate not in str(exc_info.value)


def test_search_query_does_not_apply_secret_heuristics(settings):
    assert validate_query("find sk-key", settings) == "find sk-key"


def test_metadata_rejects_reserved_and_sensitive_keys(settings):
    with pytest.raises(InputRejectedError, match="reserved"):
        validate_json_object(
            {INTERNAL_METADATA_KEY: {}}, settings, reject_reserved_key=True
        )
    with pytest.raises(InputRejectedError, match="sensitive key"):
        validate_json_object({"api_key": "value"}, settings, reject_sensitive_keys=True)


def test_metadata_rejects_depth_key_count_and_non_finite_numbers(settings):
    with pytest.raises(InputRejectedError, match="nesting"):
        validate_json_object({"a": {"b": {"c": {"d": 1}}}}, settings)
    with pytest.raises(InputRejectedError, match="key count"):
        validate_json_object(
            {key: index for index, key in enumerate(("a", "b", "c", "d", "e"))},
            settings,
        )
    with pytest.raises(InputRejectedError, match="non-finite"):
        validate_json_object({"number": float("nan")}, settings)


def test_collection_names_are_restricted():
    assert validate_collection_name("coding-memory_2026") == "coding-memory_2026"
    with pytest.raises(InputRejectedError):
        validate_collection_name("../../another-collection")


def test_internal_metadata_is_not_returned_to_the_model():
    assert public_metadata(
        {"topic": "python", INTERNAL_METADATA_KEY: {"tenant_id": "private"}}
    ) == {"topic": "python"}
