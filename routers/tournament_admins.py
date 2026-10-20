from fastapi import APIRouter, HTTPException, Header, Depends, Query
from database import supabase
from schemas.admin import TournamentAdminCreate, TournamentAdminResponse
from typing import List, Optional

router = APIRouter(prefix="/rest/v1/tournament_admins", tags=["Tournament Administrators (/rest/v1/tournament_admins)"])

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

@router.get("", response_model=List[TournamentAdminResponse], summary="List Tournament Admins", description="List tournament administrators assigned to a tournament filtered by ?tournament_id=eq.{tournament_id}.")
def get_tournament_admins(
    tournament_id: Optional[str] = Query(None, description="Filter by eq.{tournament_id}"),
    select: str = Query("*", description="Columns to select")
):
    try:
        query = supabase.table("tournament_admins").select(select)
        if tournament_id:
            clean_tid = tournament_id.replace("eq.", "") if "eq." in tournament_id else tournament_id
            query = query.eq("tournament_id", clean_tid)
        response = query.execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("", response_model=TournamentAdminResponse, summary="Assign Tournament Admin", description="Assign an admin or moderator to a tournament ('co-admin' | 'moderator').")
def create_tournament_admin(
    payload: TournamentAdminCreate,
    user_id: str = Depends(get_authenticated_user_id)
):
    try:
        data = payload.model_dump()
        response = supabase.table("tournament_admins").insert(data).execute()
        if not response.data:
            raise HTTPException(status_code=400, detail="Failed to assign tournament admin")
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("", summary="Revoke Admin Privileges", description="Revoke tournament administrator privileges filtered by ?id=eq.{admin_id}.")
def delete_tournament_admin(
    id: Optional[str] = Query(None, description="Filter by eq.{admin_id}"),
    user_id: str = Depends(get_authenticated_user_id)
):
    if not id:
        raise HTTPException(status_code=400, detail="Missing id query parameter")
    clean_id = id.replace("eq.", "") if "eq." in id else id
    try:
        response = supabase.table("tournament_admins").delete().eq("id", clean_id).execute()
        return {"message": "Admin privileges revoked successfully", "data": response.data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
