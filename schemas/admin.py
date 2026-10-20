from pydantic import BaseModel, ConfigDict
from typing import Optional, Literal

class TournamentAdminCreate(BaseModel):
    tournament_id: str
    user_id: str
    role: Literal['co-admin', 'moderator'] = 'moderator'

class TournamentAdminResponse(BaseModel):
    id: str
    tournament_id: str
    user_id: str
    role: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
