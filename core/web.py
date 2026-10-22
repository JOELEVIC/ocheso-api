"""
What every Ocheso API function shares: CORS and how a database refusal
becomes an HTTP answer. core/main.py (tournaments, play, accounts) and
agents_main.py (agents) are separate Vercel functions built the same way.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from postgrest import APIError

from config import settings
from db import fail


def make_app(**kwargs) -> FastAPI:
    app = FastAPI(version="2.0.0", **kwargs)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        # Bearer tokens in a header, never cookies - so no credentials, and a
        # stolen page cannot ride a session it does not hold the token for.
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Ocheso-Key"],
    )

    @app.exception_handler(APIError)
    async def database_refused(_: Request, error: APIError) -> JSONResponse:
        # The database is where "no" is decided; this is where it becomes the
        # right HTTP status. The old API answered 400 to everything, so a full
        # event, an expired session and a mistyped slug all looked the same.
        http = fail(error)
        return JSONResponse(status_code=http.status_code, content={"detail": http.detail})

    return app
