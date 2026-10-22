"""
Ocheso API.

Authorisation is not in this file or any router. Every request runs as its
caller against row level security (db.py, db/schema.sql), so the routes here
shape requests and responses and the database decides what is allowed.

Removed from the previous version, each for a reason recorded in
docs/OCHESO_BUILD.md:
  * /supabase/query/{table}  - read any table, unauthenticated
  * /supabase/test-connection - reported "connected" without connecting
  * /auth/*                  - proxied passwords through this API; the site
                               signs in with Supabase Auth directly
  * /functions/v1/send-invite - told organisers invitations were emailed
                               and sent nothing. Invite links are returned by
                               /v1/tournaments/{slug}/access for the organiser
                               to share, which is what actually happens.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from postgrest import APIError

from config import settings
from db import fail
from routers import agents, connect, participants, play, profiles, staff, tournaments

app = FastAPI(
    title="Ocheso API",
    description=(
        "Tournaments for chess and checkers, and agents: human-like opponents to build, hire and plug into "
        "your own platform. Every request runs as its caller; row level security decides."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

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
    # The database is where "no" is decided; this is where it becomes the right
    # HTTP status. The old API answered 400 to everything, so a full event, an
    # expired session and a mistyped slug all looked the same to the site.
    http = fail(error)
    return JSONResponse(status_code=http.status_code, content={"detail": http.detail})


app.include_router(tournaments.router)
app.include_router(participants.router)
app.include_router(staff.router)
app.include_router(profiles.router)
app.include_router(play.router)
app.include_router(agents.router)
app.include_router(connect.router)


@app.get("/", tags=["Health"], include_in_schema=False)
def root():
    return {"service": "ocheso-api", "docs": "/docs"}


@app.get("/health", tags=["Health"], summary="Liveness")
def health():
    # Says the process is up. It deliberately does not claim the database is,
    # which is the claim the old test-connection route made without checking.
    return {"ok": True, "service": "ocheso-api"}
