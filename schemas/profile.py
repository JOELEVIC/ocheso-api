from pydantic import BaseModel, ConfigDict
from typing import Optional

class ProfileBase(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None
    chess_rating: int = 1200
    checkers_rating: int = 1200
    avatar_url: Optional[str] = None

class ProfileCreate(ProfileBase):
    id: str  # auth user id

class ProfileUpdate(BaseModel):
    username: Optional[str] = None
    full_name: Optional[str] = None
    chess_rating: Optional[int] = None
    checkers_rating: Optional[int] = None
    avatar_url: Optional[str] = None

class ProfileResponse(ProfileBase):
    id: str
    updated_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
