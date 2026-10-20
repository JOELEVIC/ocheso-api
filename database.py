from supabase import create_client, Client
from config import settings

def get_supabase_client() -> Client:
    url = settings.SUPABASE_URL or "https://placeholder.supabase.co"
    key = settings.SUPABASE_KEY or "placeholder-key"
    return create_client(url, key)

supabase: Client = get_supabase_client()
