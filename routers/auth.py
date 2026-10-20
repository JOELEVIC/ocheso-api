from fastapi import APIRouter, HTTPException, Header
from database import supabase
from schemas.auth import UserSignUp, UserSignIn, AuthResponse

router = APIRouter(prefix="/auth", tags=["Authentication & Session"])

@router.post("/signup", response_model=AuthResponse, summary="Sign Up", description="Register a new user account with Supabase Auth.")
def sign_up(payload: UserSignUp):
    try:
        response = supabase.auth.sign_up({
            "email": payload.email,
            "password": payload.password,
            "options": {"data": payload.data or {}}
        })
        if response.user is None:
            raise HTTPException(status_code=400, detail="Sign up failed")

        session = response.session
        token = session.access_token if session else None
        return {
            "access_token": token,
            "token_type": "bearer" if token else None,
            "user": response.user.model_dump() if hasattr(response.user, "model_dump") else dict(response.user),
            "message": "User signed up successfully. Please check your email for verification if required."
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/signin", response_model=AuthResponse, summary="Sign In", description="Authenticate user with email and password to receive a JWT Bearer session token.")
def sign_in(payload: UserSignIn):
    try:
        response = supabase.auth.sign_in_with_password({
            "email": payload.email,
            "password": payload.password
        })
        session = response.session
        if not session:
            raise HTTPException(status_code=401, detail="Invalid credentials or email not confirmed")

        return {
            "access_token": session.access_token,
            "token_type": "bearer",
            "user": response.user.model_dump() if hasattr(response.user, "model_dump") else dict(response.user),
            "message": "Signed in successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@router.get("/me", summary="Get Current User", description="Verify JWT Bearer token and retrieve the currently authenticated user.")
def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    try:
        user_response = supabase.auth.get_user(token)
        if not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid token or session expired")
        return {"user": user_response.user}
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
