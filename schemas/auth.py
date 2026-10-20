from pydantic import BaseModel
from typing import Optional, Dict, Any

class UserSignUp(BaseModel):
    email: str
    password: str
    data: Optional[Dict[str, Any]] = None

class UserSignIn(BaseModel):
    email: str
    password: str

class AuthResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: Optional[str] = None
    user: Optional[Dict[str, Any]] = None
    message: str
