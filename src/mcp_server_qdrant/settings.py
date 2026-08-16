from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings

from mcp_server_qdrant.embeddings.types import EmbeddingProviderType

DEFAULT_TOOL_STORE_DESCRIPTION = (
    "Keep the memory for later use, when you are asked to remember something."
)
DEFAULT_TOOL_FIND_DESCRIPTION = (
    "Look up memories in Qdrant. Use this tool when you need to: \n"
    " - Find memories by their content \n"
    " - Access memories for further analysis \n"
    " - Get some personal information about the user"
)

METADATA_PATH = "metadata"


class AuthMode(str, Enum):
    NONE = "none"
    GOOGLE = "google"
    OIDC = "oidc"
    JWT = "jwt"


class TenancyMode(str, Enum):
    USER = "user"
    SHARED = "shared"


def _csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


class AuthSettings(BaseSettings):
    """OAuth and authorization configuration for remote MCP transports."""

    mode: AuthMode = Field(default=AuthMode.NONE, validation_alias="AUTH_MODE")
    base_url: str | None = Field(default=None, validation_alias="AUTH_BASE_URL")
    resource_base_url: str | None = Field(
        default=None, validation_alias="AUTH_RESOURCE_BASE_URL"
    )
    client_id: str | None = Field(default=None, validation_alias="AUTH_CLIENT_ID")
    client_secret: SecretStr | None = Field(
        default=None, validation_alias="AUTH_CLIENT_SECRET"
    )
    oidc_config_url: str | None = Field(
        default=None, validation_alias="AUTH_OIDC_CONFIG_URL"
    )
    oidc_audience: str | None = Field(
        default=None, validation_alias="AUTH_OIDC_AUDIENCE"
    )
    oidc_algorithm: str | None = Field(
        default=None, validation_alias="AUTH_OIDC_ALGORITHM"
    )
    oidc_verify_id_token: bool = Field(
        default=False, validation_alias="AUTH_OIDC_VERIFY_ID_TOKEN"
    )
    scopes: str = Field(default="openid,email,profile", validation_alias="AUTH_SCOPES")
    jwt_signing_key: SecretStr | None = Field(
        default=None, validation_alias="AUTH_JWT_SIGNING_KEY"
    )
    state_redis_url: SecretStr | None = Field(
        default=None, validation_alias="AUTH_STATE_REDIS_URL"
    )
    allow_local_state: bool = Field(
        default=False, validation_alias="AUTH_ALLOW_LOCAL_STATE"
    )
    storage_encryption_key: SecretStr | None = Field(
        default=None, validation_alias="AUTH_STORAGE_ENCRYPTION_KEY"
    )
    allowed_client_redirect_uris: str | None = Field(
        default=None, validation_alias="AUTH_ALLOWED_CLIENT_REDIRECT_URIS"
    )
    allowed_emails: str | None = Field(
        default=None, validation_alias="AUTH_ALLOWED_EMAILS"
    )
    allowed_domains: str | None = Field(
        default=None, validation_alias="AUTH_ALLOWED_DOMAINS"
    )
    allowed_subjects: str | None = Field(
        default=None, validation_alias="AUTH_ALLOWED_SUBJECTS"
    )
    allow_any_user: bool = Field(default=False, validation_alias="AUTH_ALLOW_ANY_USER")
    allow_insecure_base_url: bool = Field(
        default=False, validation_alias="AUTH_ALLOW_INSECURE_BASE_URL"
    )
    authorization_server_url: str | None = Field(
        default=None, validation_alias="AUTH_AUTHORIZATION_SERVER_URL"
    )
    jwks_url: str | None = Field(default=None, validation_alias="AUTH_JWKS_URL")
    issuer: str | None = Field(default=None, validation_alias="AUTH_ISSUER")
    audience: str | None = Field(default=None, validation_alias="AUTH_AUDIENCE")
    jwt_algorithm: str = Field(default="RS256", validation_alias="AUTH_JWT_ALGORITHM")
    jwks_allow_private_network: bool = Field(
        default=False, validation_alias="AUTH_JWKS_ALLOW_PRIVATE_NETWORK"
    )

    @property
    def scope_list(self) -> list[str]:
        return _csv(self.scopes)

    @property
    def email_allowlist(self) -> set[str]:
        return {item.lower() for item in _csv(self.allowed_emails)}

    @property
    def domain_allowlist(self) -> set[str]:
        return {item.lower().lstrip("@") for item in _csv(self.allowed_domains)}

    @property
    def subject_allowlist(self) -> set[str]:
        return set(_csv(self.allowed_subjects))

    @property
    def redirect_uri_patterns(self) -> list[str] | None:
        values = _csv(self.allowed_client_redirect_uris)
        return values or None

    @model_validator(mode="after")
    def validate_auth_configuration(self) -> "AuthSettings":
        if self.mode == AuthMode.NONE:
            return self

        if not self.base_url:
            raise ValueError("AUTH_BASE_URL is required when authentication is enabled")
        if (
            not self.base_url.startswith("https://")
            and not self.allow_insecure_base_url
        ):
            raise ValueError(
                "AUTH_BASE_URL must use HTTPS; set AUTH_ALLOW_INSECURE_BASE_URL=true only for local development"
            )
        if not self.allow_any_user and not (
            self.email_allowlist or self.domain_allowlist or self.subject_allowlist
        ):
            raise ValueError(
                "Configure AUTH_ALLOWED_EMAILS, AUTH_ALLOWED_DOMAINS, or AUTH_ALLOWED_SUBJECTS; "
                "AUTH_ALLOW_ANY_USER=true is an explicit opt-out"
            )

        if self.mode in (AuthMode.GOOGLE, AuthMode.OIDC):
            if not self.client_id or not self.client_secret:
                raise ValueError("AUTH_CLIENT_ID and AUTH_CLIENT_SECRET are required")
            if not self.jwt_signing_key:
                raise ValueError(
                    "AUTH_JWT_SIGNING_KEY is required for stable OAuth tokens"
                )
            if len(self.jwt_signing_key.get_secret_value()) < 32:
                raise ValueError("AUTH_JWT_SIGNING_KEY must be at least 32 characters")
            if not self.state_redis_url and not self.allow_local_state:
                raise ValueError(
                    "AUTH_STATE_REDIS_URL is required for durable OAuth state; "
                    "set AUTH_ALLOW_LOCAL_STATE=true only for a single replica "
                    "with a persistent writable FASTMCP_HOME"
                )
            if self.state_redis_url and not self.storage_encryption_key:
                raise ValueError(
                    "AUTH_STORAGE_ENCRYPTION_KEY is required when Redis OAuth state storage is used"
                )
            if (
                self.storage_encryption_key
                and len(self.storage_encryption_key.get_secret_value()) < 32
            ):
                raise ValueError(
                    "AUTH_STORAGE_ENCRYPTION_KEY must be at least 32 characters"
                )

        if self.mode == AuthMode.OIDC and not self.oidc_config_url:
            raise ValueError("AUTH_OIDC_CONFIG_URL is required for OIDC mode")

        if self.mode == AuthMode.JWT and not all(
            (
                self.authorization_server_url,
                self.jwks_url,
                self.issuer,
                self.audience,
            )
        ):
            raise ValueError(
                "JWT mode requires AUTH_AUTHORIZATION_SERVER_URL, AUTH_JWKS_URL, "
                "AUTH_ISSUER, and AUTH_AUDIENCE"
            )
        return self


class SecuritySettings(BaseSettings):
    max_information_chars: int = Field(
        default=16_384,
        ge=1,
        le=1_000_000,
        validation_alias="INPUT_MAX_INFORMATION_CHARS",
    )
    max_query_chars: int = Field(
        default=2_048, ge=1, le=100_000, validation_alias="INPUT_MAX_QUERY_CHARS"
    )
    max_metadata_bytes: int = Field(
        default=16_384, ge=2, le=1_000_000, validation_alias="INPUT_MAX_METADATA_BYTES"
    )
    max_metadata_depth: int = Field(
        default=6, ge=1, le=20, validation_alias="INPUT_MAX_METADATA_DEPTH"
    )
    max_metadata_keys: int = Field(
        default=128, ge=1, le=10_000, validation_alias="INPUT_MAX_METADATA_KEYS"
    )
    reject_secrets: bool = Field(default=True, validation_alias="INPUT_REJECT_SECRETS")
    tenancy_mode: TenancyMode = Field(
        default=TenancyMode.USER, validation_alias="TENANCY_MODE"
    )
    max_requests_per_second: float = Field(
        default=10.0, gt=0, le=10_000, validation_alias="RATE_LIMIT_PER_SECOND"
    )
    rate_limit_burst: int = Field(
        default=20, ge=1, le=100_000, validation_alias="RATE_LIMIT_BURST"
    )


class AuditSettings(BaseSettings):
    enabled: bool = Field(default=True, validation_alias="AUDIT_LOG_ENABLED")
    path: str | None = Field(default=None, validation_alias="AUDIT_LOG_PATH")
    max_bytes: int = Field(
        default=10_485_760, ge=1_024, validation_alias="AUDIT_LOG_MAX_BYTES"
    )
    backup_count: int = Field(
        default=5, ge=1, le=100, validation_alias="AUDIT_LOG_BACKUP_COUNT"
    )


class ServerSettings(BaseSettings):
    host: str = Field(default="127.0.0.1", validation_alias="SERVER_HOST")
    port: int = Field(default=8000, ge=1, le=65_535, validation_alias="SERVER_PORT")
    path: str = Field(default="/mcp", pattern=r"^/", validation_alias="SERVER_PATH")
    allowed_hosts: str | None = Field(
        default=None, validation_alias="HTTP_ALLOWED_HOSTS"
    )
    allowed_origins: str | None = Field(
        default=None, validation_alias="HTTP_ALLOWED_ORIGINS"
    )
    max_request_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=100_000_000,
        validation_alias="HTTP_MAX_REQUEST_BYTES",
    )
    allow_insecure_http: bool = Field(
        default=False, validation_alias="ALLOW_INSECURE_HTTP"
    )

    @property
    def allowed_host_list(self) -> list[str] | None:
        values = _csv(self.allowed_hosts)
        return values or None

    @property
    def allowed_origin_list(self) -> list[str] | None:
        values = _csv(self.allowed_origins)
        return values or None


class ToolSettings(BaseSettings):
    """
    Configuration for all the tools.
    """

    tool_store_description: str = Field(
        default=DEFAULT_TOOL_STORE_DESCRIPTION,
        validation_alias="TOOL_STORE_DESCRIPTION",
    )
    tool_find_description: str = Field(
        default=DEFAULT_TOOL_FIND_DESCRIPTION,
        validation_alias="TOOL_FIND_DESCRIPTION",
    )


class EmbeddingProviderSettings(BaseSettings):
    """
    Configuration for the embedding provider.
    """

    provider_type: EmbeddingProviderType = Field(
        default=EmbeddingProviderType.FASTEMBED,
        validation_alias="EMBEDDING_PROVIDER",
    )
    model_name: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        validation_alias="EMBEDDING_MODEL",
    )
    cache_dir: str | None = Field(default=None, validation_alias="EMBEDDING_CACHE_DIR")


class FilterableField(BaseModel):
    name: str = Field(description="The name of the field payload field to filter on")
    description: str = Field(
        description="A description for the field used in the tool description"
    )
    field_type: Literal["keyword", "integer", "float", "boolean"] = Field(
        description="The type of the field"
    )
    condition: Literal["==", "!=", ">", ">=", "<", "<=", "any", "except"] | None = (
        Field(
            default=None,
            description=(
                "The condition to use for the filter. If not provided, the field will be indexed, but no "
                "filter argument will be exposed to MCP tool."
            ),
        )
    )
    required: bool = Field(
        default=False,
        description="Whether the field is required for the filter.",
    )


class QdrantSettings(BaseSettings):
    """
    Configuration for the Qdrant connector.
    """

    location: str | None = Field(default=None, validation_alias="QDRANT_URL")
    api_key: str | None = Field(default=None, validation_alias="QDRANT_API_KEY")
    collection_name: str | None = Field(
        default=None, validation_alias="COLLECTION_NAME"
    )
    local_path: str | None = Field(default=None, validation_alias="QDRANT_LOCAL_PATH")
    search_limit: int = Field(default=10, validation_alias="QDRANT_SEARCH_LIMIT")
    read_only: bool = Field(default=False, validation_alias="QDRANT_READ_ONLY")
    auto_create_collection: bool = Field(
        default=True, validation_alias="QDRANT_AUTO_CREATE_COLLECTION"
    )
    shard_number: int = Field(
        default=1, ge=1, validation_alias="QDRANT_COLLECTION_SHARDS"
    )
    replication_factor: int = Field(
        default=1, ge=1, validation_alias="QDRANT_COLLECTION_REPLICATION_FACTOR"
    )
    write_consistency_factor: int = Field(
        default=1, ge=1, validation_alias="QDRANT_COLLECTION_WRITE_CONSISTENCY_FACTOR"
    )

    filterable_fields: list[FilterableField] | None = Field(default=None)

    allow_arbitrary_filter: bool = Field(
        default=False, validation_alias="QDRANT_ALLOW_ARBITRARY_FILTER"
    )

    def filterable_fields_dict(self) -> dict[str, FilterableField]:
        if self.filterable_fields is None:
            return {}
        return {field.name: field for field in self.filterable_fields}

    def filterable_fields_dict_with_conditions(self) -> dict[str, FilterableField]:
        if self.filterable_fields is None:
            return {}
        return {
            field.name: field
            for field in self.filterable_fields
            if field.condition is not None
        }

    @model_validator(mode="after")
    def check_local_path_conflict(self) -> "QdrantSettings":
        if self.local_path:
            if self.location is not None or self.api_key is not None:
                raise ValueError(
                    "If 'local_path' is set, 'location' and 'api_key' must be None."
                )
        if self.write_consistency_factor > self.replication_factor:
            raise ValueError(
                "QDRANT_COLLECTION_WRITE_CONSISTENCY_FACTOR cannot exceed "
                "QDRANT_COLLECTION_REPLICATION_FACTOR"
            )
        return self
