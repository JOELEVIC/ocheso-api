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
                               (Invitations by email came back in Ocheso for
                               Platforms - routers/invites.py - sent for real,
                               through core/mail.py, and reported as sent only
                               once Resend has them.)

Ocheso for Platforms (docs/OCHESO_PLATFORMS.md D) lives here too:
  * routers/orgs.py      Studio: organisations, team, keys, webhooks, series
  * routers/invites.py   players by email, and the invite links
  * routers/platform.py  a partner's server, with an ochs_ secret key
  * routers/embed.py     the embed frame: public reads and oche_ sessions
  * routers/internal.py  the autopilot's tick, signed by the database
The org key, the player token and the embed session never reach PostgREST as
bearers (db.py); each travels as a hash inside a request this API signs.
"""

from __future__ import annotations

from config import settings
from routers import embed, internal, invites, orgs, participants, platform, play, profiles, staff, tournaments
from web import make_app

# The light function. Agents (/v1/agents, /v1/agent-keys, /v1/connect) are a
# separate one - agents_main.py at the repo root - so a tournament page never
# loads Stockfish, Maia or numpy. vercel.json routes between them.
app = make_app(
    title="Ocheso API",
    description=(
        "Tournaments for chess and checkers. Every request runs as its caller; row level security decides. "
        "Agents are documented at /v1/agents/docs."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

app.include_router(tournaments.router)
app.include_router(participants.router)
app.include_router(staff.router)
app.include_router(profiles.router)
app.include_router(play.router)
app.include_router(invites.router)
app.include_router(orgs.router)
app.include_router(platform.router)
app.include_router(embed.router)
app.include_router(internal.router)


@app.get("/", tags=["Health"], include_in_schema=False)
def root():
    return {"service": "ocheso-api", "docs": "/docs", "agents": "/v1/agents/docs"}


@app.get("/health", tags=["Health"], summary="Liveness")
def health():
    # Says the process is up. It deliberately does not claim the database is,
    # which is the claim the old test-connection route made without checking.
    # `mail` is whether this process CAN send (both Resend settings present):
    # off means invitations wait in the outbox, not that they were sent.
    return {"ok": True, "service": "ocheso-api", "mail": "on" if settings.mail_on else "off"}
