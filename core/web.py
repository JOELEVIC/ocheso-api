"""
What every Ocheso API function shares: CORS and how a database refusal
becomes an HTTP answer. core/main.py (tournaments, play, accounts) and
agents_main.py (agents) are separate Vercel functions built the same way.

Every error answers {detail, code}: `detail` a sentence for people, `code` a
stable word for programs (db.py CODES, or one a route chose - wrong_token,
server_only, session_required, ...). Validation errors keep FastAPI's list in
`detail` and say code "invalid".
"""

from __future__ import annotations

import re

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from postgrest import APIError
from starlette.exceptions import HTTPException as StarletteHTTPException

from config import settings
from db import CODES, fail

# The embed reads anyone may make from any page (spec D3): a partner's own UI,
# a server rendering a schedule, the loader on a page that is not ours. They
# carry no credentials and nothing personal, so they answer
# `Access-Control-Allow-Origin: *`. Everything that acts for someone - a
# session, a sign-in token, an org key - stays behind the ALLOWED_ORIGINS list.
PUBLIC_EMBED_GET = re.compile(
    r"^/v1/embed/(policy|t/[^/]+|o/[^/]+|o/[^/]+/series/[^/]+|g/[^/]+|handoff/[0-9a-f]{64})$"
)
EMBED_PING = "/v1/embed/ping"
_PUBLIC_HEADERS = "Authorization, Content-Type, X-Ocheso-Session"


class PublicEmbedCors:
    """Outermost, so it sees a preflight before CORSMiddleware turns away an
    origin that is not on the list. Plain ASGI: it only rewrites headers."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path, method = scope["path"], scope["method"]
        public = bool(PUBLIC_EMBED_GET.match(path))
        ping = path == EMBED_PING
        if not (public or ping):
            return await self.app(scope, receive, send)
        if method == "OPTIONS":
            await send({"type": "http.response.start", "status": 204, "headers": [
                (b"access-control-allow-origin", b"*"),
                (b"access-control-allow-methods", b"POST, OPTIONS" if ping else b"GET, HEAD, OPTIONS"),
                (b"access-control-allow-headers", _PUBLIC_HEADERS.encode()),
                (b"access-control-max-age", b"600"),
            ]})
            await send({"type": "http.response.body", "body": b""})
            return
        if not ((public and method in ("GET", "HEAD")) or (ping and method == "POST")):
            return await self.app(scope, receive, send)

        async def starred(message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.lower() not in (b"access-control-allow-origin", b"access-control-allow-credentials")]
                headers.append((b"access-control-allow-origin", b"*"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, starred)


def make_app(**kwargs) -> FastAPI:
    app = FastAPI(version="2.0.0", **kwargs)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        # Bearer tokens in a header, never cookies - so no credentials, and a
        # stolen page cannot ride a session it does not hold the token for.
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        # X-Ocheso-Session carries an embed session (oche_...), Idempotency-Key
        # makes a platform's retried POST safe (routers/platform.py).
        allow_headers=["Authorization", "Content-Type", "X-Ocheso-Key", "X-Ocheso-Session", "Idempotency-Key"],
    )
    app.add_middleware(PublicEmbedCors)

    @app.exception_handler(APIError)
    async def database_refused(_: Request, error: APIError) -> JSONResponse:
        # The database is where "no" is decided; this is where it becomes the
        # right HTTP status. The old API answered 400 to everything, so a full
        # event, an expired session and a mistyped slug all looked the same.
        http = fail(error)
        return JSONResponse(status_code=http.status_code, content={"detail": http.detail, "code": http.code},
                            headers=http.headers)

    @app.exception_handler(StarletteHTTPException)
    async def refused(_: Request, error: StarletteHTTPException) -> Response:
        headers = getattr(error, "headers", None)
        if error.status_code < 200 or error.status_code in (204, 304):
            return Response(status_code=error.status_code, headers=headers)
        code = getattr(error, "code", None) or CODES.get(error.status_code, "error")
        return JSONResponse({"detail": error.detail, "code": code}, status_code=error.status_code, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def invalid(_: Request, error: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(error.errors()), "code": "invalid"})

    return app
