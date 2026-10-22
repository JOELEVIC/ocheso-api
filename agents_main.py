"""
Ocheso API - agents: the heavy function (Stockfish, and Maia on numpy).

Served on the same domain as the rest of the API: vercel.json sends
/v1/agents, /v1/agent-keys and /v1/connect here and everything else to
core/main.py, so tournaments never load what only agents need. The path
arrives unchanged, so the routers keep their prefixes.
"""

from __future__ import annotations

import sys
from pathlib import Path

# config, db and play live in core/ (the light function's root). This
# function's root is the repository, so core/ is in its bundle too.
sys.path.insert(0, str(Path(__file__).resolve().parent / "core"))

from agent_routes import agents, connect  # noqa: E402
from web import make_app  # noqa: E402

app = make_app(
    title="Ocheso API - agents",
    description=(
        "Human-like opponents to build, hire and plug into your own platform: owners under /v1/agents and "
        "/v1/agent-keys, platforms holding an agent key under /v1/connect."
    ),
    docs_url="/v1/agents/docs",
    openapi_url="/v1/agents/openapi.json",
    redoc_url=None,
)

app.include_router(agents.router)
app.include_router(connect.router)
