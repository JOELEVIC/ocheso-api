from fastapi import APIRouter, HTTPException, Header, Depends, Query
from database import supabase
from schemas.participant import ParticipantCreate, ParticipantUpdate, ParticipantResponse, InviteRequest
from typing import List, Optional

router = APIRouter(tags=["Participants & Invites (/rest/v1/participants)"])

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

@router.post("/rest/v1/participants", response_model=ParticipantResponse, summary="Add Participant", description="Register a participant for a tournament with status ('Approved' | 'Pending').")
def create_participant(
    payload: ParticipantCreate,
    user_id: str = Depends(get_authenticated_user_id)
):
    try:
        data = payload.model_dump()
        response = supabase.table("participants").insert(data).execute()
        if not response.data:
            raise HTTPException(status_code=400, detail="Failed to add participant")
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/rest/v1/participants", response_model=List[ParticipantResponse], summary="Get Participant Roster", description="Retrieve participant roster feed filtered by ?tournament_id=eq.{tournament_id}.")
def get_participants(
    tournament_id: Optional[str] = Query(None, description="Filter by eq.{tournament_id}"),
    select: str = Query("*", description="Columns to select")
):
    try:
        query = supabase.table("participants").select(select)
        if tournament_id:
            clean_tid = tournament_id.replace("eq.", "") if "eq." in tournament_id else tournament_id
            query = query.eq("tournament_id", clean_tid)
        response = query.execute()
        return response.data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/rest/v1/participants", summary="Update Participant Status", description="Approve or update participant status (e.g. status: 'Approved') filtered by ?id=eq.{participant_id}.")
def patch_participant(
    payload: ParticipantUpdate,
    id: Optional[str] = Query(None, description="Filter by eq.{participant_id}"),
    user_id: str = Depends(get_authenticated_user_id)
):
    if not id:
        raise HTTPException(status_code=400, detail="Missing id query parameter")
    clean_id = id.replace("eq.", "") if "eq." in id else id
    try:
        update_data = payload.model_dump()
        response = supabase.table("participants").update(update_data).eq("id", clean_id).execute()
        if not response.data:
            raise HTTPException(status_code=404, detail="Participant not found or update failed")
        return response.data[0]
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/rest/v1/participants", summary="Remove Participant", description="Remove participant from roster filtered by ?id=eq.{participant_id}.")
def delete_participant(
    id: Optional[str] = Query(None, description="Filter by eq.{participant_id}"),
    user_id: str = Depends(get_authenticated_user_id)
):
    if not id:
        raise HTTPException(status_code=400, detail="Missing id query parameter")
    clean_id = id.replace("eq.", "") if "eq." in id else id
    try:
        response = supabase.table("participants").delete().eq("id", clean_id).execute()
        return {"message": "Participant removed successfully", "data": response.data}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/functions/v1/send-invite", summary="Send Tournament Invite", description="Dispatch tournament email invite via Supabase Edge Function simulation.")
def send_invite(
    payload: InviteRequest,
    user_id: str = Depends(get_authenticated_user_id)
):
    try:
        return {
            "status": "success",
            "message": f"Invite successfully dispatched to {payload.email}",
            "tournament_id": payload.tournament_id,
            "invite_link": payload.invite_link
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
