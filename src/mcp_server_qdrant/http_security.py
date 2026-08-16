from __future__ import annotations

import re
import time
import uuid

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_server_qdrant.audit import AuditLogger
from mcp_server_qdrant.auth import identity_from_token

_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_AUTH_PATHS = {
    "/authorize",
    "/token",
    "/register",
    "/auth/callback",
}


class RequestSizeLimitMiddleware:
    """Reject oversized request bodies before OAuth or MCP parsers consume them."""

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {
            "POST",
            "PUT",
            "PATCH",
        }:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        content_length = headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await PlainTextResponse("Request body too large", status_code=413)(
                        scope, receive, send
                    )
                    return
            except ValueError:
                await PlainTextResponse("Invalid Content-Length", status_code=400)(
                    scope, receive, send
                )
                return

        messages: list[Message] = []
        size = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > self.max_bytes:
                    await PlainTextResponse("Request body too large", status_code=413)(
                        scope, receive, send
                    )
                    return
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break

        async def replay() -> Message:
            if messages:
                return messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay, send)


class HttpAuditMiddleware:
    """Emit request metadata without headers, query strings, bodies, or tokens."""

    def __init__(self, app: ASGIApp, audit: AuditLogger):
        self.app = app
        self.audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        supplied_request_id = Headers(scope=scope).get("x-request-id", "")
        request_id = (
            supplied_request_id
            if _REQUEST_ID.fullmatch(supplied_request_id)
            else uuid.uuid4().hex
        )
        status_code = 500

        async def capture(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                headers = MutableHeaders(scope=message)
                headers["x-content-type-options"] = "nosniff"
                headers["referrer-policy"] = "no-referrer"
                headers["x-request-id"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            token = None
            user = scope.get("user")
            if user is not None:
                token = getattr(user, "access_token", None)
            identity = identity_from_token(token)
            path = str(scope.get("path") or "")
            authentication_event = (
                path in _AUTH_PATHS
                or path.startswith("/.well-known/")
                or status_code in {401, 403}
            )
            if status_code in {401, 403}:
                outcome = "denied"
            elif status_code >= 400:
                outcome = "error"
            else:
                outcome = "success"
            self.audit.record(
                "http_request",
                request_id=request_id,
                method=scope.get("method"),
                path=path,
                status=status_code,
                security_category=(
                    "authentication" if authentication_event else "transport"
                ),
                outcome=outcome,
                actor_id=identity.actor_id if identity else None,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
