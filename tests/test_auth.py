import httpx
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken
from pydantic import ValidationError

from mcp_server_qdrant.auth import (
    create_auth_provider,
    identity_from_token,
    identity_is_allowed,
)
from mcp_server_qdrant.settings import AuthSettings, TenancyMode


def _token(**claims):
    return AccessToken(
        token="not-a-real-token",
        client_id="client",
        scopes=["openid", "email"],
        claims=claims,
    )


def test_nested_upstream_identity_is_hashed_and_tenant_scoped():
    token = _token(
        upstream_claims={
            "iss": "https://accounts.example.test",
            "sub": "user-123",
            "email": "USER@EXAMPLE.COM",
            "email_verified": True,
        }
    )

    identity = identity_from_token(token)

    assert identity is not None
    assert identity.subject == "user-123"
    assert identity.email == "user@example.com"
    assert identity.actor_id.startswith("actor:")
    assert identity.tenant_id.startswith("user:")
    assert "user-123" not in identity.actor_id


def test_shared_tenancy_uses_one_authenticated_namespace():
    identity = identity_from_token(_token(sub="user-123"), TenancyMode.SHARED)

    assert identity is not None
    assert identity.tenant_id == "shared"


def test_email_and_domain_allowlists_require_verified_email():
    settings = AuthSettings(
        AUTH_MODE="google",
        AUTH_BASE_URL="https://memory.example.com",
        AUTH_CLIENT_ID="client",
        AUTH_CLIENT_SECRET="secret",
        AUTH_JWT_SIGNING_KEY="a-stable-signing-key-with-enough-entropy",
        AUTH_ALLOWED_DOMAINS="example.com",
        AUTH_ALLOW_LOCAL_STATE=True,
    )

    assert identity_is_allowed(
        _token(sub="one", email="one@example.com", email_verified=True), settings
    )
    assert not identity_is_allowed(
        _token(sub="two", email="two@example.com", email_verified=False), settings
    )


def test_subject_allowlist_does_not_depend_on_email_claims():
    settings = AuthSettings(
        AUTH_MODE="jwt",
        AUTH_BASE_URL="https://memory.example.com",
        AUTH_AUTHORIZATION_SERVER_URL="https://auth.example.com",
        AUTH_JWKS_URL="https://auth.example.com/.well-known/jwks.json",
        AUTH_ISSUER="https://auth.example.com",
        AUTH_AUDIENCE="https://memory.example.com/mcp",
        AUTH_ALLOWED_SUBJECTS="service-account-1",
    )

    assert identity_is_allowed(_token(sub="service-account-1"), settings)
    assert not identity_is_allowed(_token(sub="service-account-2"), settings)


def test_authentication_requires_https_and_an_explicit_identity_policy():
    common = {
        "AUTH_MODE": "google",
        "AUTH_CLIENT_ID": "client",
        "AUTH_CLIENT_SECRET": "secret",
        "AUTH_JWT_SIGNING_KEY": "a-stable-signing-key-with-enough-entropy",
    }
    with pytest.raises(ValidationError, match="must use HTTPS"):
        AuthSettings(
            **common,
            AUTH_BASE_URL="http://memory.example.com",
            AUTH_ALLOWED_EMAILS="me@example.com",
        )
    with pytest.raises(ValidationError, match="AUTH_ALLOWED"):
        AuthSettings(**common, AUTH_BASE_URL="https://memory.example.com")


def test_redis_oauth_state_requires_a_separate_encryption_key():
    with pytest.raises(ValidationError, match="AUTH_STORAGE_ENCRYPTION_KEY"):
        AuthSettings(
            AUTH_MODE="google",
            AUTH_BASE_URL="https://memory.example.com",
            AUTH_CLIENT_ID="client",
            AUTH_CLIENT_SECRET="secret",
            AUTH_JWT_SIGNING_KEY="a-stable-signing-key-with-enough-entropy",
            AUTH_STATE_REDIS_URL="redis://redis:6379/0",
            AUTH_ALLOWED_EMAILS="me@example.com",
        )


def test_remote_oauth_rejects_process_local_state_by_default():
    with pytest.raises(ValidationError, match="AUTH_STATE_REDIS_URL is required"):
        AuthSettings(
            AUTH_MODE="google",
            AUTH_BASE_URL="https://memory.example.com",
            AUTH_CLIENT_ID="client",
            AUTH_CLIENT_SECRET="secret",
            AUTH_JWT_SIGNING_KEY="a-stable-signing-key-with-enough-entropy",
            AUTH_ALLOWED_EMAILS="me@example.com",
        )


def test_single_replica_can_explicitly_accept_local_oauth_state():
    settings = AuthSettings(
        AUTH_MODE="google",
        AUTH_BASE_URL="https://memory.example.com",
        AUTH_CLIENT_ID="client",
        AUTH_CLIENT_SECRET="secret",
        AUTH_JWT_SIGNING_KEY="a-stable-signing-key-with-enough-entropy",
        AUTH_ALLOWED_EMAILS="me@example.com",
        AUTH_ALLOW_LOCAL_STATE=True,
    )

    assert settings.allow_local_state is True
    assert settings.state_redis_url is None


@pytest.mark.asyncio
async def test_google_proxy_publishes_mcp_oauth_metadata_and_challenge():
    settings = AuthSettings(
        AUTH_MODE="google",
        AUTH_BASE_URL="https://memory.example.com",
        AUTH_CLIENT_ID="client",
        AUTH_CLIENT_SECRET="client-secret",
        AUTH_JWT_SIGNING_KEY="x" * 48,
        AUTH_ALLOWED_EMAILS="me@example.com",
        AUTH_STATE_REDIS_URL="redis://redis:6379/0",
        AUTH_STORAGE_ENCRYPTION_KEY="y" * 48,
    )
    server = FastMCP("oauth-test", auth=create_auth_provider(settings))
    app = server.http_app(
        path="/mcp",
        host_origin_protection=True,
        allowed_hosts=["memory.example.com"],
        allowed_origins=["https://memory.example.com"],
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://memory.example.com",
    ) as client:
        resource = await client.get("/.well-known/oauth-protected-resource/mcp")
        authorization_server = await client.get(
            "/.well-known/oauth-authorization-server"
        )
        challenge = await client.post("/mcp", json={})

    assert resource.status_code == 200
    assert resource.json()["resource"] == "https://memory.example.com/mcp"
    assert authorization_server.status_code == 200
    metadata = authorization_server.json()
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["registration_endpoint"] == "https://memory.example.com/register"
    assert challenge.status_code == 401
    assert "resource_metadata=" in challenge.headers["www-authenticate"]
