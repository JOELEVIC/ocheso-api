import os

# Settings are read at import, so the environment has to be in place first.
# A publishable key: the API refuses to start with anything privileged.
os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
os.environ.setdefault("SUPABASE_ANON_KEY", "sb_publishable_test_key_for_unit_tests")
os.environ.pop("SUPABASE_KEY", None)
