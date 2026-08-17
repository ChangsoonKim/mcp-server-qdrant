from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import mcp.types as mt
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools.base import ToolResult

from mcp_server_qdrant.auth import identity_from_token
from mcp_server_qdrant.settings import AuditSettings


class AuditLogger:
    def __init__(self, settings: AuditSettings):
        self.enabled = settings.enabled
        self._logger = logging.getLogger("mcp_server_qdrant.audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        for previous_handler in list(self._logger.handlers):
            self._logger.removeHandler(previous_handler)
            previous_handler.close()
        if settings.path:
            path = Path(settings.path)
            handler: logging.Handler = logging.handlers.RotatingFileHandler(
                path,
                maxBytes=settings.max_bytes,
                backupCount=settings.backup_count,
                encoding="utf-8",
            )
        else:
            # stdout is reserved for the MCP stdio transport.
            handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def record(self, event: str, **fields: Any) -> None:
        if not self.enabled:
            return
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        self._logger.info(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
        )

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            handler.flush()
            handler.close()
            self._logger.removeHandler(handler)


def _argument_summary(arguments: dict[str, Any] | None) -> dict[str, Any]:
    arguments = arguments or {}
    summary: dict[str, Any] = {"argument_names": sorted(arguments)}
    information = arguments.get("information")
    query = arguments.get("query")
    metadata = arguments.get("metadata")
    if isinstance(information, str):
        summary["information_chars"] = len(information)
        summary["information_bytes"] = len(information.encode("utf-8"))
    if isinstance(query, str):
        summary["query_chars"] = len(query)
    if isinstance(metadata, dict):
        summary["metadata_keys"] = sorted(str(key) for key in metadata)
        summary["metadata_bytes"] = len(
            json.dumps(metadata, default=str, separators=(",", ":")).encode("utf-8")
        )
    collection = arguments.get("collection_name")
    if isinstance(collection, str):
        summary["collection"] = collection
    return summary


class ToolAuditMiddleware(Middleware):
    def __init__(self, audit: AuditLogger):
        self.audit = audit

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        started = time.perf_counter()
        token = get_access_token()
        identity = identity_from_token(token)
        request_id = None
        if context.fastmcp_context is not None:
            request_id = str(context.fastmcp_context.request_id)
        fields = {
            "request_id": request_id,
            "actor_id": identity.actor_id if identity else "local",
            "tool": context.message.name,
            **_argument_summary(context.message.arguments),
        }
        try:
            result = await call_next(context)
        except AuthorizationError:
            self.audit.record(
                "mcp_tool_call",
                **fields,
                outcome="denied",
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            raise
        except Exception as exc:
            self.audit.record(
                "mcp_tool_call",
                **fields,
                outcome="error",
                error_type=type(exc).__name__,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            raise

        self.audit.record(
            "mcp_tool_call",
            **fields,
            outcome="error" if result.is_error else "success",
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return result
