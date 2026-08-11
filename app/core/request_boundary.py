"""Ранняя граница безопасности для ``POST /insights``.

FastAPI читает и валидирует body до вызова endpoint-функции. Поэтому проверка
токена внутри router защищала Anthropic, но не JSON parser и Pydantic: запрос
без токена мог получить 422 и потратить ресурсы на разбор тела. Проверка
``Content-Length`` тоже не ограничивала chunked body без этого заголовка.

Этот ASGI middleware работает до маршрутизации: сначала проверяет вызывающего,
затем ограничивает и объявленный, и фактически прочитанный размер.
"""

from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.caller_auth import is_authorized

MAX_REQUEST_BODY_BYTES = 100_000


class RequestBodyTooLarge(Exception):
    """Внутренний сигнал от ограниченного ASGI receive."""


def _header(scope: Scope, name: bytes) -> str | None:
    """Читает последний заголовок как latin-1, как это делает Starlette."""
    value: bytes | None = None
    for header_name, header_value in scope.get("headers", []):
        if header_name.lower() == name:
            value = header_value
    return value.decode("latin-1") if value is not None else None


class InsightsBoundaryMiddleware:
    """Аутентифицирует и потоково ограничивает только endpoint инсайтов."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") not in {
            "/insights",
            "/insights/",
        }:
            await self.app(scope, receive, send)
            return

        authorization = _header(scope, b"authorization") or ""
        if not is_authorized(authorization):
            await JSONResponse(
                status_code=403,
                content={"detail": "Forbidden"},
            )(scope, receive, send)
            return

        content_length = _header(scope, b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                await JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length"},
                )(scope, receive, send)
                return
            if declared_size < 0:
                await JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length"},
                )(scope, receive, send)
                return
            if declared_size > MAX_REQUEST_BODY_BYTES:
                await JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )(scope, receive, send)
                return

        received_size = 0

        async def limited_receive() -> Message:
            nonlocal received_size
            message = await receive()
            if message["type"] == "http.request":
                received_size += len(message.get("body", b""))
                if received_size > MAX_REQUEST_BODY_BYTES:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )(scope, receive, send)
