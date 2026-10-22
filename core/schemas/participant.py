from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from schemas.tournament import Person

ParticipantStatus = Literal["pending", "approved", "rejected", "withdrawn"]


class JoinIn(BaseModel):
    # No user_id and no status. Who you are comes from your token; whether you
    # are approved comes from the tournament's rules. The old endpoint took
    # both from this body, so anyone could join as anyone and approve
    # themselves.
    model_config = ConfigDict(extra="forbid")
    code: Optional[str] = Field(None, max_length=12)
    invite: Optional[str] = Field(None, max_length=64)


class AddIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # With or without the @.
    username: str = Field(pattern=r"^@?[A-Za-z0-9_]{3,24}$")


class ParticipantOut(BaseModel):
    id: str
    tournament_id: str
    user_id: str
    status: ParticipantStatus
    rating_at_entry: Optional[int] = None
    seed: Optional[int] = None
    joined_via: Literal["open", "code", "invite", "added"]
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime
    profile: Optional[Person] = None


class RosterEntry(BaseModel):
    """The public view of an entrant: approved, with a name and no email."""

    participant_id: str
    user_id: str
    display_name: Optional[str] = None
    username: Optional[str] = None
    avatar_url: Optional[str] = None
    country: Optional[str] = None
    rating_at_entry: Optional[int] = None
    seed: Optional[int] = None
    joined_at: datetime
