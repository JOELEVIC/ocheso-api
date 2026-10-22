"""
Local only: the whole API in one process, as one server.

    uvicorn dev:app --reload

On Vercel the two halves are separate functions (vercel.json): core/main.py
serves everything except /v1/agents, /v1/agent-keys and /v1/connect, which
agents_main.py serves.
"""

from __future__ import annotations

import agents_main  # noqa: F401  (puts core/ on the path)
from agent_routes import agents, connect
from main import app  # core/main.py

app.include_router(agents.router)
app.include_router(connect.router)
