from pydantic import BaseModel, ConfigDict
from typing import Optional, Literal

class TournamentCreate(BaseModel):
    title: str
    game_type: str  # e.g., 'chess', 'checkers'
    format: str     # e.g., 'swiss', 'knockout', 'robin'
    time_control: str # e.g., '5+0', '10+2'
    start_date: str
    start_time: str
    rounds_count: int
    is_public: bool = True
    max_participants: int = 32
    entry_code: Optional[str] = None
    code_enabled: bool = False
    auto_join: bool = True

class TournamentUpdate(BaseModel):
    title: Optional[str] = None
    game_type: Optional[str] = None
    format: Optional[str] = None
    time_control: Optional[str] = None
    start_date: Optional[str] = None
    start_time: Optional[str] = None
    rounds_count: Optional[int] = None
    is_public: Optional[bool] = None
    max_participants: Optional[int] = None
    entry_code: Optional[str] = None
    code_enabled: Optional[bool] = None
    auto_join: Optional[bool] = None

class TournamentResponse(TournamentCreate):
    id: str
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
