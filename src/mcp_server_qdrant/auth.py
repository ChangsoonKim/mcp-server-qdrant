from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet
from fastmcp.server.auth import AccessToken, AuthProvider
from fastmcp.server.auth.auth import RemoteAuthProvider
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.utilities.authorization import AuthCheck, AuthContext
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.redis import RedisStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from pydantic import AnyHttpUrl

from mcp_server_qdrant.settings import AuthMode, AuthSettings, TenancyMode


@dataclass(frozen=True)
class Identity:
    subject: str
    actor_id: str
    tenant_id: str
    email: str | None
    email_verified: bool
    issuer: str


def _secret_value(value: Any) -> str | None:
    return value.get_secret_value() if value is not None else None


def _claims(token: AccessToken) -> dict[str, Any]:
    claims = dict(token.claims or {})
    upstream = claims.get("upstream_claims")
    if isinstance(upstream, dict):
        claims.update(upstream)
    return claims


def _is_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() == "true")


def identity_from_token(
    token: AccessToken | None,
    tenancy_mode: TenancyMode = TenancyMode.USER,
) -> Identity | None:
    if token is None:
        return None

    claims = _claims(token)
    subject = str(claims.get("sub") or token.subject or token.client_id or "").strip()
    if not subject:
        return None
    issuer = str(claims.get("iss") or "unknown-issuer")
    email_value = claims.get("email")
    email = str(email_value).strip().lower() if email_value else None
    email_verified = _is_true(claims.get("email_verified")) or _is_true(
        claims.get("verified_email")
    )
    digest = hashlib.sha256(f"{issuer}\x00{subject}".encode()).hexdigest()
    actor_id = f"actor:{digest[:32]}"
    tenant_id = (
        "shared" if tenancy_mode == TenancyMode.SHARED else f"user:{digest[:32]}"
    )
    return Identity(
        subject=subject,
        actor_id=actor_id,
        tenant_id=tenant_id,
        email=email,
        email_verified=email_verified,
        issuer=issuer,
    )


def identity_is_allowed(token: AccessToken | None, settings: AuthSettings) -> bool:
    identity = identity_from_token(token)
    if identity is None:
        return False
    if settings.allow_any_user:
        return True
    if identity.subject in settings.subject_allowlist:
        return True

    if identity.email and identity.email_verified:
        if identity.email in settings.email_allowlist:
            return True
        domain = identity.email.rsplit("@", maxsplit=1)[-1]
        if domain in settings.domain_allowlist:
            return True
    return False


def make_identity_auth_check(settings: AuthSettings) -> AuthCheck:
    def require_allowed_identity(context: AuthContext) -> bool:
        return identity_is_allowed(context.token, settings)

    return require_allowed_identity


def _oauth_state_store(settings: AuthSettings) -> AsyncKeyValue | None:
    redis_url = _secret_value(settings.state_redis_url)
    if not redis_url:
        return None

    encryption_material = _secret_value(settings.storage_encryption_key)
    if not encryption_material:  # protected by settings validation
        raise ValueError("Missing OAuth state encryption key")
    fernet_key = base64.urlsafe_b64encode(
        hashlib.sha256(encryption_material.encode()).digest()
    )
    return FernetEncryptionWrapper(
        key_value=RedisStore(url=redis_url),
        fernet=Fernet(fernet_key),
        raise_on_decryption_error=True,
    )


def create_auth_provider(settings: AuthSettings) -> AuthProvider | None:
    if settings.mode == AuthMode.NONE:
        return None

    assert settings.base_url is not None
    if settings.mode == AuthMode.JWT:
        assert settings.jwks_url is not None
        assert settings.issuer is not None
        assert settings.audience is not None
        assert settings.authorization_server_url is not None
        verifier = JWTVerifier(
            jwks_uri=settings.jwks_url,
            issuer=settings.issuer,
            audience=settings.audience,
            algorithm=settings.jwt_algorithm,
            required_scopes=settings.scope_list or None,
            base_url=settings.base_url,
            ssrf_safe=not settings.jwks_allow_private_network,
        )
        return RemoteAuthProvider(
            token_verifier=verifier,
            authorization_servers=[AnyHttpUrl(settings.authorization_server_url)],
            base_url=settings.base_url,
            resource_base_url=settings.resource_base_url,
            scopes_supported=settings.scope_list or None,
            resource_name="Qdrant shared memory",
        )

    common: dict[str, Any] = {
        "client_id": settings.client_id,
        "client_secret": _secret_value(settings.client_secret),
        "base_url": settings.base_url,
        "resource_base_url": settings.resource_base_url,
        "allowed_client_redirect_uris": settings.redirect_uri_patterns,
        "client_storage": _oauth_state_store(settings),
        "jwt_signing_key": _secret_value(settings.jwt_signing_key),
        "require_authorization_consent": True,
        "fastmcp_access_token_expiry_seconds": 3600,
        "token_expiry_threshold_seconds": 30,
        "enable_cimd": True,
    }

    if settings.mode == AuthMode.GOOGLE:
        return GoogleProvider(
            **common,
            required_scopes=settings.scope_list or ["openid", "email", "profile"],
            valid_scopes=settings.scope_list or ["openid", "email", "profile"],
        )

    assert settings.oidc_config_url is not None
    return OIDCProxy(
        **common,
        config_url=settings.oidc_config_url,
        audience=settings.oidc_audience,
        algorithm=settings.oidc_algorithm,
        required_scopes=settings.scope_list or None,
        verify_id_token=settings.oidc_verify_id_token,
    )
