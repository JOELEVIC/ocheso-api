from pydantic import BaseModel, ConfigDict
from typing import Optional, Literal

class ParticipantCreate(BaseModel):
    tournament_id: str
    user_id: str
    email: str
    status: Literal['Approved', 'Pending'] = 'Pending'

class ParticipantUpdate(BaseModel):
    status: Literal['Approved', 'Pending']

class ParticipantResponse(BaseModel):
    id: str
    tournament_id: str
    user_id: str
    email: str
    status: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class InviteRequest(BaseModel):
    email: str
    tournament_id: str
    invite_link: str
