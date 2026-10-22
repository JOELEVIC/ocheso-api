from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.tournament import Person

Role = Literal["co_admin", "moderator"]


class StaffIn(BaseModel):
    # By username, not email. Adding by email would need the API to confirm
    # whether an address has an account - a user-enumeration oracle.
    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[a-z0-9_]{3,24}$")
    role: Role = "moderator"


class StaffRoleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Role


class StaffOut(BaseModel):
    id: str
    tournament_id: str
    user_id: str
    role: Role
    created_at: datetime
    profile: Person | None = None
