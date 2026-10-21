from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ProfileOut(BaseModel):
    id: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    country: Optional[str] = None
    chess_rating: int
    checkers_rating: int
    created_at: datetime
    updated_at: datetime


class ProfileUpdate(BaseModel):
    # No ratings. They are earned in rated games, not typed in - the old model
    # let anyone set their own.
    model_config = ConfigDict(extra="forbid")
    username: Optional[str] = Field(None, pattern=r"^[a-z0-9_]{3,24}$")
    display_name: Optional[str] = Field(None, min_length=1, max_length=60)
    avatar_url: Optional[str] = Field(None, max_length=500)
    country: Optional[str] = Field(None, pattern=r"^[A-Z]{2}$")
