"""
Tournament payloads.

`extra="forbid"` throughout: a body carrying owner_id, status or anything else
the client may not set is refused with a 422 that names the field. Dropping
such fields quietly would let a site bug look like it worked. The database
refuses them too (column grants), so this is the clear error, not the guard.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

Game = Literal["chess", "checkers"]
# A rule set, not a pairing system - see db/schema.sql.
Variant = Literal["standard", "international", "brazilian"]
Format = Literal["swiss", "round_robin", "knockout", "arena"]
Status = Literal["draft", "registration", "live", "finished", "archived"]
Tiebreak = Literal["buchholz", "buchholz_cut1", "sonneborn_berger", "direct_encounter", "wins", "progressive"]
# Who can play (docs/OCHESO_PLATFORMS.md A3): Ocheso accounts, the
# organisation's own platform users, or both. Only an organisation has
# platform users, so a personal tournament is always "accounts".
IdentityMode = Literal["accounts", "platform", "any"]
ShortField = Literal["postpone", "wait", "cancel"]
Language = Literal["en", "fr", "both"]

_VARIANTS: dict[str, set[str]] = {"chess": {"standard"}, "checkers": {"international", "brazilian"}}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TournamentFields(_Strict):
    """Everything a new tournament may say about itself. TournamentCreate adds
    the organisation (by slug) for the console; the platform API and the
    onboarding bootstrap know the organisation already."""

    title: str = Field(min_length=3, max_length=120)
    description: Optional[str] = Field(None, max_length=2000)
    game: Game
    variant: Variant
    format: Format
    clock_base_s: int = Field(ge=15, le=10800, description="Starting time per player, in seconds.")
    clock_increment_s: int = Field(0, ge=0, le=180, description="Seconds added after each move.")
    starts_at: datetime
    rounds_count: Optional[int] = Field(None, ge=1, le=30)
    arena_minutes: Optional[int] = Field(None, ge=10, le=1440)
    tiebreaks: list[Tiebreak] = ["buchholz", "sonneborn_berger"]
    max_participants: Optional[int] = Field(None, ge=2, le=4096, description="Omit for unlimited.")
    is_listed: bool = True
    participants_visible: bool = True
    games_watchable: bool = True
    requires_code: bool = False
    auto_approve: bool = True
    # Not a tournament column: stored in tournament_secrets, readable by
    # organisers only. Accepted here so creating a coded event is one request.
    entry_code: Optional[str] = Field(None, pattern=r"^[A-Za-z0-9]{4,12}$")

    # Ocheso for Platforms (db/schema.sql, C2). Omitted means the database's
    # default - except `rated`, which an organisation's event leaves off
    # unless the organiser opts in (A9; routers/tournaments.py).
    identity_mode: Optional[IdentityMode] = None
    invite_only: Optional[bool] = None
    org_listed: Optional[bool] = None
    rated: Optional[bool] = None
    autopilot: Optional[bool] = None
    min_players: Optional[int] = Field(None, ge=2, le=4096)
    short_field: Optional[ShortField] = None
    postpone_min: Optional[int] = Field(None, ge=1, le=1440)
    max_postpones: Optional[int] = Field(None, ge=0, le=50)
    round_break_s: Optional[int] = Field(None, ge=0, le=3600)
    language: Optional[Language] = None

    @model_validator(mode="after")
    def _coherent(self) -> "TournamentFields":
        if self.variant not in _VARIANTS[self.game]:
            raise ValueError(f"{self.game} is played as {', '.join(sorted(_VARIANTS[self.game]))}, not {self.variant}.")
        if (self.format == "arena") != (self.arena_minutes is not None):
            raise ValueError("arena_minutes is set for an arena, and only for an arena.")
        if self.format == "swiss" and self.rounds_count is None:
            raise ValueError("A Swiss event needs rounds_count.")
        if self.format in ("round_robin", "knockout") and self.rounds_count is not None:
            # Follows from the field - n - 1 games, or log2 n rounds - so a number
            # here would be one the pairing engine has to ignore.
            raise ValueError(f"A {self.format.replace('_', ' ')} sets its own rounds from the field; omit rounds_count.")
        if self.requires_code and not self.entry_code:
            raise ValueError("A tournament that requires a code needs an entry_code.")
        if self.entry_code and not self.requires_code:
            # Stored and ignored is the worst outcome: the organiser believes the
            # event is protected while anyone can walk in. Found on the live
            # database, 2026-10-21.
            raise ValueError("An entry_code only gates entry when requires_code is true.")
        if self.min_players and self.max_participants and self.min_players > self.max_participants:
            raise ValueError("min_players can't be more than max_participants.")
        return self


class TournamentCreate(TournamentFields):
    # The organisation's slug. You must be its owner, an admin or staff; the
    # database checks (the org_id column grant and the tournaments insert policy).
    org: Optional[str] = Field(None, min_length=3, max_length=40)

    @model_validator(mode="after")
    def _identity_needs_org(self) -> "TournamentCreate":
        if self.identity_mode not in (None, "accounts") and not self.org:
            raise ValueError("Only an organisation's tournament can admit platform users: set org.")
        return self


class TournamentUpdate(_Strict):
    # game, variant and format are absent on purpose: changing what is being
    # played after people have entered would change the event they entered.
    title: Optional[str] = Field(None, min_length=3, max_length=120)
    description: Optional[str] = Field(None, max_length=2000)
    clock_base_s: Optional[int] = Field(None, ge=15, le=10800)
    clock_increment_s: Optional[int] = Field(None, ge=0, le=180)
    starts_at: Optional[datetime] = None
    rounds_count: Optional[int] = Field(None, ge=1, le=30)
    arena_minutes: Optional[int] = Field(None, ge=10, le=1440)
    tiebreaks: Optional[list[Tiebreak]] = None
    max_participants: Optional[int] = Field(None, ge=2, le=4096)
    is_listed: Optional[bool] = None
    participants_visible: Optional[bool] = None
    games_watchable: Optional[bool] = None
    requires_code: Optional[bool] = None
    auto_approve: Optional[bool] = None
    # Frozen by the database once anyone has entered or entries have closed
    # (guard_tournament_identity): identity_mode and rated.
    identity_mode: Optional[IdentityMode] = None
    rated: Optional[bool] = None
    invite_only: Optional[bool] = None
    org_listed: Optional[bool] = None
    language: Optional[Language] = None
    autopilot: Optional[bool] = None
    min_players: Optional[int] = Field(None, ge=2, le=4096)
    short_field: Optional[ShortField] = None
    postpone_min: Optional[int] = Field(None, ge=1, le=1440)
    max_postpones: Optional[int] = Field(None, ge=0, le=50)
    round_break_s: Optional[int] = Field(None, ge=0, le=3600)


class Person(BaseModel):
    id: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    country: Optional[str] = None


class TournamentOut(BaseModel):
    id: str
    slug: str
    owner_id: str
    title: str
    description: Optional[str] = None
    game: Game
    variant: Variant
    format: Format
    clock_base_s: int
    clock_increment_s: int
    starts_at: datetime
    rounds_count: Optional[int] = None
    arena_minutes: Optional[int] = None
    tiebreaks: list[str]
    max_participants: Optional[int] = None
    is_listed: bool
    participants_visible: bool
    games_watchable: bool
    requires_code: bool
    auto_approve: bool
    status: Status
    # When it actually went live (db/play.sql). Absent before play.sql is applied.
    started_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    # Ocheso for Platforms. Optional so a database without them still answers.
    org_id: Optional[str] = None
    identity_mode: Optional[IdentityMode] = None
    invite_only: Optional[bool] = None
    org_listed: Optional[bool] = None
    rated: Optional[bool] = None
    autopilot: Optional[bool] = None
    min_players: Optional[int] = None
    short_field: Optional[ShortField] = None
    postpone_min: Optional[int] = None
    max_postpones: Optional[int] = None
    round_break_s: Optional[int] = None
    autopilot_note: Optional[str] = None
    series_id: Optional[str] = None
    language: Optional[Language] = None


class MyTournament(BaseModel):
    tournament: TournamentOut
    my_role: Literal["owner", "co_admin", "moderator", "participant"]


class AccessOut(BaseModel):
    """Organisers only. Never part of the public tournament."""

    entry_code: Optional[str] = None
    invite_token: str
    invite_url: str
    rotated_at: datetime


class EntryCodeIn(_Strict):
    entry_code: Optional[str] = Field(None, pattern=r"^[A-Za-z0-9]{4,12}$", description="null clears it.")
