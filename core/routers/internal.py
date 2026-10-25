"""
Internal: the autopilot's tick (docs/OCHESO_PLATFORMS.md C8, D4).

Only the database calls this. private.autopilot_kick() posts
{"kind":"tick","ts":...,"nonce":...} with X-Ocheso-Tick: the HMAC of those exact
bytes under hmac_sha256(REFEREE_SECRET, 'ocheso:v1:tick') (tokens.py). The
signature is checked over the RAW body before anything is parsed, in constant
time, and a tick more than 90 s from our clock is refused, so a captured tick
cannot be replayed later. Duplicate ticks inside the window are harmless: the
lease in `sys-work` hands each due tournament to one of them.

A refused tick answers 401 with no reason beyond "bad tick": the caller is a
database that either has the key or does not.
"""

from __future__ import annotations

import logging
from typing import Annotated, Optional

from fastapi import APIRouter, Header, Request
from fastapi.concurrency import run_in_threadpool

import autopilot
from db import Refusal
from tokens import BadTick, verify_tick

router = APIRouter(prefix="/v1/internal", tags=["Internal"])
log = logging.getLogger("ocheso.tick")


@router.post("/tick", summary="The autopilot's tick (signed by the database)")
async def tick(request: Request, x_ocheso_tick: Annotated[Optional[str], Header(alias="X-Ocheso-Tick")] = None):
    raw = await request.body()
    if len(raw) > 4096:
        raise Refusal(413, "bad tick", code="bad_tick")
    try:
        verify_tick(raw, x_ocheso_tick)
    except BadTick as e:
        log.warning("tick refused: %s", e)
        raise Refusal(401, "bad tick", code="bad_tick") from None
    # Blocking I/O (PostgREST, Resend) for up to the 40 s budget: off the loop.
    return await run_in_threadpool(autopilot.run_tick)
