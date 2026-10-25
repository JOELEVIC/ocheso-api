"""
Organisation payloads, checked the way db/schema.sql checks them.

The database is the guard - organizations' CHECKs, private.brand_ok and
private.origins_ok refuse anything else whatever sent it - so these models
exist for the answer, not the protection: a 422 naming `brand.colors.primary`
beats a 409 "that conflicts with the current state" from a CHECK. They mirror
the SQL rule for rule, and tests/test_brand.py holds the two side by side, so
a payload the API passes is one the database takes.
"""

from __future__ import annotations

import json
import re
from datetime import date, time
from typing import Annotated, Literal, Optional, Union
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr, field_validator, model_validator

RESERVED_SLUGS = frozenset({"www", "api", "embed", "admin", "o", "app", "studio", "platforms", "developers"})
SLUG = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
# https only, and nothing that could leave a quoted attribute or a url().
# Always fullmatch()ed: Python's `$` also matches before a final newline, which
# Postgres's `~` does not, and the mirror must not be looser than the CHECK.
SAFE_URL = re.compile(r"^https://[^\s\"'<>()\\]+$")
HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
COLOR_KEY = re.compile(r"^[a-z][a-z0-9_]{0,23}$")
EMAIL = re.compile(r"^[^@\s<>\",;]+@[^@\s<>\",;]+\.[^@\s<>\",;]+$")
ORIGIN = re.compile(r"^https://[a-z0-9-]+(\.[a-z0-9-]+)*(:[0-9]{1,5})?$")
WILDCARD_ORIGIN = re.compile(r"^https://\*\.[a-z0-9-]+(\.[a-z0-9-]+)+$")
LOCAL_ORIGIN = re.compile(r"^http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$")
BRAND_MAX_BYTES = 4096

Number = Union[StrictInt, StrictFloat]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# -----------------------------------------------------------------------------
# Rules shared by the models and by the routes that derive values
# -----------------------------------------------------------------------------
def slug_ok(slug: str) -> bool:
    return bool(SLUG.fullmatch(slug)) and 3 <= len(slug) <= 40 and slug not in RESERVED_SLUGS


def origin_ok(origin: str) -> bool:
    return len(origin) <= 200 and bool(ORIGIN.fullmatch(origin) or WILDCARD_ORIGIN.fullmatch(origin) or LOCAL_ORIGIN.fullmatch(origin))


def email_ok(email: str) -> bool:
    return 6 <= len(email) <= 254 and bool(EMAIL.fullmatch(email))


def timezone_ok(tz: str) -> bool:
    try:
        ZoneInfo(tz)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        pass
    try:
        ZoneInfo("UTC")
    except ZoneInfoNotFoundError:
        # No tz database on this machine at all: judge the shape and let
        # organizations_guard() decide.
        return bool(re.fullmatch(r"[A-Za-z_]+(/[A-Za-z0-9_+\-]+){0,2}", tz))
    return False


def check_url(v: Optional[str], limit: int = 500) -> Optional[str]:
    if v is not None and (len(v) > limit or not SAFE_URL.fullmatch(v)):
        raise ValueError("must be an https:// URL without spaces, quotes, brackets or parentheses")
    return v


def check_slug(v: Optional[str]) -> Optional[str]:
    if v is not None and not slug_ok(v):
        raise ValueError("3-40 lowercase letters, digits and single hyphens, and not a word the site uses")
    return v


def check_name(v: Optional[str]) -> Optional[str]:
    if v is not None:
        v = v.strip()
        if not 2 <= len(v) <= 80:
            raise ValueError("2 to 80 characters")
    return v


def check_timezone(v: Optional[str]) -> Optional[str]:
    if v is not None and not timezone_ok(v):
        raise ValueError("not an IANA timezone, e.g. Africa/Douala")
    return v


def check_email(v: Optional[str]) -> Optional[str]:
    if v is not None:
        v = v.strip().lower()
        if not email_ok(v):
            raise ValueError("not an email address")
    return v


def check_origins(v: Optional[list[str]]) -> Optional[list[str]]:
    if v is None:
        return v
    if len(v) > 50:
        raise ValueError("at most 50 origins")
    out = []
    for o in v:
        o = o.strip().rstrip("/").lower()
        if not origin_ok(o):
            raise ValueError(
                f"{o!r} is not an origin: https://host[:port] or https://*.host, http:// only for localhost"
            )
        out.append(o)
    return out


# -----------------------------------------------------------------------------
# Brand (private.brand_ok)
# -----------------------------------------------------------------------------
class Brand(_Strict):
    v: Optional[Number] = None
    name: Optional[StrictStr] = Field(None, min_length=1, max_length=80)
    logo_url: Optional[StrictStr] = None
    logo_dark_url: Optional[StrictStr] = None
    colors: Optional[dict[str, StrictStr]] = None
    font: Optional[Literal["system", "inter", "poppins", "manrope", "roboto"]] = None
    radius: Optional[Annotated[Number, Field(ge=0, le=24)]] = None
    theme: Optional[Literal["auto", "light", "dark"]] = None
    board: Optional[Literal["slate", "wood", "green", "brand", "contrast"]] = None
    locale: Optional[Literal["en", "fr", "both"]] = None
    # Hideable on federation only; the plan is the database's to check.
    badge: Optional[StrictBool] = None

    @field_validator("logo_url", "logo_dark_url")
    @classmethod
    def urls(cls, v: Optional[str]) -> Optional[str]:
        return check_url(v)

    @field_validator("colors")
    @classmethod
    def colours(cls, v: Optional[dict[str, str]]) -> Optional[dict[str, str]]:
        if v is None:
            return v
        if len(v) > 16:
            raise ValueError("at most 16 colours")
        for key, value in v.items():
            if not COLOR_KEY.fullmatch(key):
                raise ValueError(f"{key!r} is not a colour name (a-z, 0-9, _; up to 24)")
            if not HEX.fullmatch(value):
                raise ValueError(f"{key} must be #rrggbb")
        return v

    @model_validator(mode="after")
    def size(self) -> "Brand":
        # octet_length(brand::text) in SQL; jsonb prints ", " and ": " as
        # json.dumps does by default, and keeps non-ASCII as UTF-8.
        if len(self.as_json().encode()) > BRAND_MAX_BYTES:
            raise ValueError("a brand is at most 4 KB")
        return self

    def as_json(self) -> str:
        return json.dumps(self.model_dump(exclude_none=True), ensure_ascii=False)


# -----------------------------------------------------------------------------
# Organisations
# -----------------------------------------------------------------------------
class OrgCreate(_Strict):
    # Derived from the name or the website when absent (routers/orgs.py).
    slug: Optional[str] = None
    name: str = Field(min_length=2, max_length=80)
    website: Optional[str] = Field(None, max_length=300)
    brand: Optional[Brand] = None
    allowed_origins: Optional[list[str]] = None
    timezone: Optional[str] = Field(None, max_length=64)

    slug_rule = field_validator("slug")(check_slug)
    name_rule = field_validator("name")(check_name)
    website_rule = field_validator("website")(lambda v: check_url(v, 300))
    origins_rule = field_validator("allowed_origins")(check_origins)
    timezone_rule = field_validator("timezone")(check_timezone)


class OrgUpdate(_Strict):
    name: Optional[str] = Field(None, min_length=2, max_length=80)
    website: Optional[str] = Field(None, max_length=300)
    brand: Optional[Brand] = None
    allowed_origins: Optional[list[str]] = None
    support_email: Optional[str] = None
    timezone: Optional[str] = Field(None, max_length=64)

    name_rule = field_validator("name")(check_name)
    website_rule = field_validator("website")(lambda v: check_url(v, 300))
    origins_rule = field_validator("allowed_origins")(check_origins)
    email_rule = field_validator("support_email")(check_email)
    timezone_rule = field_validator("timezone")(check_timezone)


OrgRole = Literal["owner", "admin", "staff"]


class MemberInvite(_Strict):
    email: str = Field(max_length=254)
    # Ownership is transferred (POST .../transfer), never granted by invitation.
    role: Literal["admin", "staff"] = "staff"

    email_rule = field_validator("email")(check_email)


class MemberRole(_Strict):
    role: Literal["admin", "staff"]


class Transfer(_Strict):
    user_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")


class KeyCreate(_Strict):
    name: str = Field(min_length=1, max_length=60)
    scopes: Optional[list[Literal["players", "tournaments", "invites", "read"]]] = None


WebhookEvent = Literal[
    "tournament.created", "tournament.updated", "tournament.published", "tournament.started",
    "tournament.postponed", "tournament.finished", "tournament.archived",
    "participant.joined", "participant.approved", "participant.rejected", "participant.withdrawn",
    "participant.removed",
    "invite.claimed", "invite.declined", "invite.lapsed",
    "round.published", "round.started", "round.finished",
    "game.started", "game.finished",
    "autopilot.stalled", "install.first_seen", "webhook.test",
]

# private.webhook_url_ok has the full rule (no IP literals, no private names,
# port 443 only); the models only give the obvious answer early.


class WebhookCreate(_Strict):
    url: str = Field(max_length=500)
    events: list[WebhookEvent] = Field(min_length=1, max_length=32)
    description: Optional[str] = Field(None, max_length=200)

    url_rule = field_validator("url")(check_url)


class WebhookUpdate(_Strict):
    url: Optional[str] = Field(None, max_length=500)
    events: Optional[list[WebhookEvent]] = Field(None, min_length=1, max_length=32)
    description: Optional[str] = Field(None, max_length=200)
    active: Optional[bool] = None

    url_rule = field_validator("url")(check_url)


class BlockIn(_Strict):
    blocked: bool = True


# -----------------------------------------------------------------------------
# Series
# -----------------------------------------------------------------------------
def check_series_slug(v: Optional[str]) -> Optional[str]:
    if v is not None and not (SLUG.fullmatch(v) and 3 <= len(v) <= 60):
        raise ValueError("3-60 lowercase letters, digits and single hyphens")
    return v


# Weekdays as Postgres counts them (extract(dow ...)), which is what
# private.series_next compares with.
Weekday = Field(ge=0, le=6, description="0 = Sunday, 1 = Monday ... 6 = Saturday.")


class SeriesCreate(_Strict):
    slug: Optional[str] = None
    title: str = Field(min_length=3, max_length=120)
    # The tournament fields each instance copies (TournamentCreate's, less
    # starts_at, which the weekday and time decide).
    template: dict
    weekday: int = Weekday
    local_time: time
    timezone: Optional[str] = Field(None, max_length=64)

    slug_rule = field_validator("slug")(check_series_slug)
    timezone_rule = field_validator("timezone")(check_timezone)


class SeriesUpdate(_Strict):
    title: Optional[str] = Field(None, min_length=3, max_length=120)
    template: Optional[dict] = None
    weekday: Optional[int] = Field(None, ge=0, le=6, description="0 = Sunday ... 6 = Saturday.")
    local_time: Optional[time] = None
    timezone: Optional[str] = Field(None, max_length=64)
    # pause / resume
    active: Optional[bool] = None
    # Dates to skip (no instance that day), and dates to stop skipping.
    skip_dates: Optional[list[date]] = Field(None, max_length=100)
    unskip_dates: Optional[list[date]] = Field(None, max_length=100)
    stop: Optional[bool] = None

    timezone_rule = field_validator("timezone")(check_timezone)


class SeriesStart(_Strict):
    """The series part of POST /v1/orgs/bootstrap."""

    weekday: int = Weekday
    local_time: time
    slug: Optional[str] = None
    title: Optional[str] = Field(None, min_length=3, max_length=120)

    slug_rule = field_validator("slug")(check_series_slug)
