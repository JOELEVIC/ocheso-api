from fastapi import APIRouter, HTTPException, Header, Depends, Query
from database import supabase
from schemas.tournament import TournamentCreate, TournamentUpdate, TournamentResponse
from typing import List, Optional

router = APIRouter(prefix="/rest/v1/tournaments", tags=["Tournaments API (/rest/v1/tournaments)"])

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

@router.post("", response_model=TournamentResponse, summary="Create Tournament", description="Create a new tournament with game settings, time control, format, and entry codes.")
def create_tournament(
    payload: TournamentCreate,
    user_id: str = Depends(get_authenticated_user_id)
):
    try:
        data = payload.model_dump()
        response = supabase.table("tournaments").insert(data).execute()
        if not response.data:
            raise HTTPException(status_code=400, detail="Failed to create tournament")
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("", response_model=List[TournamentResponse], summary="List Tournaments", description="List tournaments visible to the user (filtered by RLS policies or ?id=eq.{tournament_id}).")
def get_tournaments(
    id: Optional[str] = Query(None, description="Filter by eq.{tournament_id}"),
    select: str = Query("*", description="Columns to select")
):
    try:
        query = supabase.table("tournaments").select(select)
        if id:
            clean_id = id.replace("eq.", "") if "eq." in id else id
            query = query.eq("id", clean_id)
        response = query.execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{tournament_id}", response_model=TournamentResponse, summary="Get Tournament by ID", description="Get single tournament details by ID.")
def get_tournament_by_id(tournament_id: str):
    try:
        response = supabase.table("tournaments").select("*").eq("id", tournament_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Tournament not found")
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("", summary="Update Tournament", description="Update tournament configuration filtered by ?id=eq.{tournament_id}.")
def patch_tournament(
    payload: TournamentUpdate,
    id: Optional[str] = Query(None, description="Filter by eq.{tournament_id}"),
    user_id: str = Depends(get_authenticated_user_id)
):
    if not id:
        raise HTTPException(status_code=400, detail="Missing id query parameter for update")
    clean_id = id.replace("eq.", "") if "eq." in id else id
    try:
        update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
        response = supabase.table("tournaments").update(update_data).eq("id", clean_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Tournament not found or update failed")
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("", summary="Delete / Archive Tournament", description="Archive or soft-delete a tournament filtered by ?id=eq.{tournament_id}.")
def delete_tournament(
    id: Optional[str] = Query(None, description="Filter by eq.{tournament_id}"),
    user_id: str = Depends(get_authenticated_user_id)
):
    if not id:
        raise HTTPException(status_code=400, detail="Missing id query parameter for deletion")
    clean_id = id.replace("eq.", "") if "eq." in id else id
    try:
        response = supabase.table("tournaments").delete().eq("id", clean_id).execute()
        return {"message": "Tournament archived/deleted successfully", "data": response.data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
