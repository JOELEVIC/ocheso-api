import os
import sys
from pathlib import Path

# The light app lives in core/ and imports its modules top-level (config, db,
# play, routers), as it does on Vercel where core/ is its function's root.
_ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(_ROOT / "core"), str(_ROOT)]

# Settings are read at import, so the environment has to be in place first.
# A publishable key: the API refuses to start with anything privileged.
os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
os.environ.setdefault("SUPABASE_ANON_KEY", "sb_publishable_test_key_for_unit_tests")
os.environ.pop("SUPABASE_KEY", None)
