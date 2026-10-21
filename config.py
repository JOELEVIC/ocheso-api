from __future__ import annotations

import base64
import json

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    SUPABASE_URL: str = ""
    # The project's PUBLIC key (anon / sb_publishable_). Read from the old name
    # too, so the deployed environment keeps working without a rename.
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_KEY: str = ""

    # Bearer tokens, not cookies, so credentials are off and any listed origin
    # may call. The old config combined a wildcard origin with credentials,
    # which browsers refuse outright.
    ALLOWED_ORIGINS: str = (
        "https://www.ocheso.com,https://ocheso.com,"
        "http://localhost:3000,http://127.0.0.1:3000"
    )

    # Where invite links point.
    SITE_URL: str = "https://www.ocheso.com"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def _public_key_only(self) -> "Settings":
        # Checked in BOTH variables, not just the one in use. A service-role key
        # sitting unused in this API's environment is one refactor away from
        # being used, and the rule is easier to keep if it is simply "never here".
        if _is_privileged(self.SUPABASE_ANON_KEY) or _is_privileged(self.SUPABASE_KEY):
            # Refuse to start rather than run. An anonymous request is sent with
            # this key as its bearer; if it were the service-role key, every
            # anonymous visitor would bypass row level security entirely, and
            # every guarantee in db/schema.sql would stop applying without a
            # single error anywhere.
            raise ValueError(
                "A secret / service-role key is configured. This API must hold "
                "only the public key: authorisation lives in row level security, and "
                "a service-role key bypasses it for every caller."
            )
        self.SUPABASE_ANON_KEY = self.SUPABASE_ANON_KEY or self.SUPABASE_KEY
        return self

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]


def _is_privileged(key: str) -> bool:
    if not key:
        return False
    if key.startswith("sb_secret_"):
        return True
    if key.startswith("sb_publishable_"):
        return False
    # Legacy keys are JWTs carrying their role. Decoded, not verified: this only
    # asks what the key claims to be, which is exactly the mistake to catch.
    try:
        payload = key.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role") == "service_role"
    except Exception:
        return False


settings = Settings()
