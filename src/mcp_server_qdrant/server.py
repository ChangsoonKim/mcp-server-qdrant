from starlette.responses import JSONResponse

from mcp_server_qdrant.auth import create_auth_provider
from mcp_server_qdrant.mcp_server import QdrantMCPServer
from mcp_server_qdrant.settings import (
    AuditSettings,
    AuthSettings,
    EmbeddingProviderSettings,
    QdrantSettings,
    SecuritySettings,
    ToolSettings,
)

auth_settings = AuthSettings()

mcp = QdrantMCPServer(
    tool_settings=ToolSettings(),
    qdrant_settings=QdrantSettings(),
    embedding_provider_settings=EmbeddingProviderSettings(),
    auth_settings=auth_settings,
    security_settings=SecuritySettings(),
    audit_settings=AuditSettings(),
    auth_provider=create_auth_provider(auth_settings),
)


@mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
async def healthz(_request):
    return JSONResponse({"status": "ok"})
