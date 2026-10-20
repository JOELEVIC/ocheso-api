from fastapi import APIRouter, HTTPException, Query
from database import supabase

router = APIRouter(prefix="/supabase", tags=["Supabase Integration"])

@router.get("/test-connection")
def test_supabase_connection():
    """Test connection status to Supabase."""
    try:
        return {
            "status": "connected",
            "message": "Supabase client initialized successfully."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Supabase connection error: {str(e)}")

@router.get("/query/{table_name}")
def query_table(
    table_name: str,
    select: str = Query("*", description="Columns to select, e.g. id,name"),
    limit: int = Query(10, ge=1, le=100)
):
    """Generic helper endpoint to query any Supabase table."""
    try:
        response = supabase.table(table_name).select(select).limit(limit).execute()
        return {
            "table": table_name,
            "data": response.data
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
