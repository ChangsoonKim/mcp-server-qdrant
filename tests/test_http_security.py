import json

import httpx
import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from mcp_server_qdrant.audit import AuditLogger
from mcp_server_qdrant.http_security import (
    HttpAuditMiddleware,
    RequestSizeLimitMiddleware,
)
from mcp_server_qdrant.settings import AuditSettings


async def echo(request: Request):
    return PlainTextResponse(await request.body())


@pytest.mark.asyncio
async def test_http_body_limit_security_headers_and_safe_audit(tmp_path):
    audit_path = tmp_path / "http-audit.jsonl"
    audit = AuditLogger(AuditSettings(AUDIT_LOG_PATH=str(audit_path)))
    app = Starlette(
        routes=[Route("/mcp", echo, methods=["POST"])],
        middleware=[
            Middleware(HttpAuditMiddleware, audit=audit),
            Middleware(RequestSizeLimitMiddleware, max_bytes=8),
        ],
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://memory.example.com"
    ) as client:
        accepted = await client.post(
            "/mcp?never=logged",
            content=b"12345678",
            headers={"x-request-id": "safe-id"},
        )
        rejected = await client.post("/mcp", content=b"123456789")

    for handler in audit._logger.handlers:
        handler.flush()
    records = [json.loads(line) for line in audit_path.read_text().splitlines()]

    assert accepted.status_code == 200
    assert accepted.headers["x-content-type-options"] == "nosniff"
    assert accepted.headers["x-request-id"] == "safe-id"
    assert rejected.status_code == 413
    assert [record["status"] for record in records] == [200, 413]
    assert [record["outcome"] for record in records] == ["success", "error"]
    assert all(record["security_category"] == "transport" for record in records)
    assert all(record["path"] == "/mcp" for record in records)
    assert "never=logged" not in audit_path.read_text()
    audit.close()
