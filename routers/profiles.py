from fastapi import APIRouter, HTTPException, Header, Depends, Query
from database import supabase
from schemas.profile import ProfileUpdate, ProfileResponse
from typing import List, Optional

router = APIRouter(prefix="/rest/v1/profiles", tags=["Profiles API (/rest/v1/profiles)"])

def get_authenticated_user_id(authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    try:
        user_response = supabase.auth.get_user(token)
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Authentication failed")
        return user_response.user.id
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

@router.get("", response_model=List[ProfileResponse], summary="Get Profiles", description="Retrieve user profiles. Supports filtering by ?id=eq.{user_id}.")
def get_profiles(
    id: Optional[str] = Query(None, description="Filter by eq.{user_id} or direct ID"),
    select: str = Query("*", description="Columns to select")
):
    try:
        query = supabase.table("profiles").select(select)
        if id:
            clean_id = id.replace("eq.", "") if "eq." in id else id
            query = query.eq("id", clean_id)
        response = query.execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("", summary="Update Profile", description="Update user profile attributes (full_name, chess_rating, checkers_rating, avatar_url) filtered by ?id=eq.{user_id}.")
def patch_profile(
    payload: ProfileUpdate,
    id: Optional[str] = Query(None, description="Filter by eq.{user_id}"),
    user_id: str = Depends(get_authenticated_user_id)
):
    target_id = user_id
    if id:
        target_id = id.replace("eq.", "") if "eq." in id else id

    try:
        update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
        response = supabase.table("profiles").update(update_data).eq("id", target_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Profile not found or update failed")
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/me", response_model=ProfileResponse, summary="Get My Profile", description="Convenience endpoint to get authenticated user's profile.")
def get_my_profile(user_id: str = Depends(get_authenticated_user_id)):
    response = supabase.table("profiles").select("*").eq("id", user_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Profile not found")
    return response.data[0]

@router.put("/me", response_model=ProfileResponse, summary="Update My Profile", description="Convenience endpoint to update authenticated user's profile.")
def update_my_profile(payload: ProfileUpdate, user_id: str = Depends(get_authenticated_user_id)):
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    response = supabase.table("profiles").update(update_data).eq("id", user_id).execute()
    if not response.data:
        raise HTTPException(status_code=404, detail="Profile not found")
    return response.data[0]
