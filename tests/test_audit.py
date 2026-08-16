import json

import pytest
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.tools.base import ToolResult
from mcp.types import CallToolRequestParams

from mcp_server_qdrant.audit import AuditLogger, ToolAuditMiddleware
from mcp_server_qdrant.settings import AuditSettings


def test_default_audit_stream_does_not_corrupt_mcp_stdout(capsys):
    audit = AuditLogger(AuditSettings())
    audit.record("test_event", outcome="success")
    captured = capsys.readouterr()
    audit.close()

    assert captured.out == ""
    assert json.loads(captured.err)["event"] == "test_event"


@pytest.mark.asyncio
async def test_tool_audit_records_only_input_shape(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(AuditSettings(AUDIT_LOG_PATH=str(audit_path)))
    middleware = ToolAuditMiddleware(audit)
    secret_memory = "private memory body"
    context = MiddlewareContext(
        message=CallToolRequestParams(
            name="qdrant-store",
            arguments={
                "information": secret_memory,
                "metadata": {"topic": "security"},
                "collection_name": "coding-memory",
            },
        ),
        method="tools/call",
    )

    async def succeed(_context):
        return ToolResult(content="ok")

    await middleware.on_call_tool(context, succeed)
    for handler in audit._logger.handlers:
        handler.flush()

    raw_line = audit_path.read_text().strip()
    record = json.loads(raw_line)
    assert record["event"] == "mcp_tool_call"
    assert record["outcome"] == "success"
    assert record["information_chars"] == len(secret_memory)
    assert record["metadata_keys"] == ["topic"]
    assert secret_memory not in raw_line
    assert "security" not in raw_line
    audit.close()


@pytest.mark.asyncio
async def test_tool_errors_are_audited_without_exception_messages(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLogger(AuditSettings(AUDIT_LOG_PATH=str(audit_path)))
    middleware = ToolAuditMiddleware(audit)
    context = MiddlewareContext(
        message=CallToolRequestParams(name="qdrant-find", arguments={"query": "x"}),
        method="tools/call",
    )

    async def fail(_context):
        raise RuntimeError("sensitive backend details")

    with pytest.raises(RuntimeError):
        await middleware.on_call_tool(context, fail)
    for handler in audit._logger.handlers:
        handler.flush()

    raw_line = audit_path.read_text().strip()
    record = json.loads(raw_line)
    assert record["outcome"] == "error"
    assert record["error_type"] == "RuntimeError"
    assert "sensitive backend details" not in raw_line
    audit.close()
