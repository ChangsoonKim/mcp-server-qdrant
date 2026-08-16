import argparse
from urllib.parse import urlsplit


def main():
    """
    Main entry point for the mcp-server-qdrant script defined
    in pyproject.toml. It runs the MCP server with a specific transport
    protocol.
    """

    # Parse the command-line arguments to determine the transport protocol.
    parser = argparse.ArgumentParser(description="mcp-server-qdrant")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
    )
    args = parser.parse_args()

    # Import is done here to make sure environment variables are loaded
    # only after we make the changes.
    from starlette.middleware import Middleware

    from mcp_server_qdrant.http_security import (
        HttpAuditMiddleware,
        RequestSizeLimitMiddleware,
    )
    from mcp_server_qdrant.server import auth_settings, mcp
    from mcp_server_qdrant.settings import AuthMode, ServerSettings

    server_settings = ServerSettings()

    if args.transport == "sse":
        parser.error(
            "SSE is disabled because it lacks the hardened Host/Origin path; use streamable-http"
        )
    if args.transport == "stdio" and auth_settings.mode != AuthMode.NONE:
        parser.error(
            "OAuth is only available over streamable-http; use AUTH_MODE=none for stdio"
        )
    if (
        args.transport == "streamable-http"
        and auth_settings.mode == AuthMode.NONE
        and not server_settings.allow_insecure_http
    ):
        parser.error(
            "Unauthenticated remote MCP is disabled. Configure AUTH_MODE or explicitly set "
            "ALLOW_INSECURE_HTTP=true for local development."
        )

    if args.transport == "stdio":
        mcp.run(transport="stdio", show_banner=False)
        return

    allowed_hosts = server_settings.allowed_host_list
    allowed_origins = server_settings.allowed_origin_list
    if auth_settings.base_url:
        public_url = urlsplit(auth_settings.base_url)
        if allowed_hosts is None and public_url.netloc:
            allowed_hosts = [
                public_url.netloc,
                public_url.hostname or public_url.netloc,
            ]
        if allowed_origins is None and public_url.scheme and public_url.netloc:
            allowed_origins = [f"{public_url.scheme}://{public_url.netloc}"]

    http_middleware = [
        Middleware(HttpAuditMiddleware, audit=mcp.audit_logger),
        Middleware(
            RequestSizeLimitMiddleware,
            max_bytes=server_settings.max_request_bytes,
        ),
    ]

    mcp.run(
        transport="streamable-http",
        host=server_settings.host,
        port=server_settings.port,
        path=server_settings.path,
        middleware=http_middleware,
        host_origin_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
        uvicorn_config={"proxy_headers": False, "server_header": False},
        show_banner=False,
    )
