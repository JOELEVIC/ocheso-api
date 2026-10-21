-- =============================================================================
-- Ocheso — tournaments schema
-- =============================================================================
-- Applied by hand, idempotent: safe to run more than once. Nothing auto-migrates.
--
-- THE RULE THIS FILE IS BUILT AROUND: authorisation lives here, in row level
-- security, not in the API. ocheso-api forwards the caller's JWT, so every
-- query runs as that user and Postgres decides what they may see and change.
-- The API being wrong cannot then mean a stranger editing your tournament - it
-- can only mean a request that fails.
--
-- That matters because the previous API did authorisation in Python and got it
-- wrong in four places at once (see docs/OCHESO_BUILD.md). A rule written once,
-- next to the data, is a rule that holds for every client, including ones that
-- talk to PostgREST directly.
--
-- Three things clients can never set, enforced by column grants rather than by
-- trusting a request body:
--   * who owns a tournament           (owner_id defaults to auth.uid())
--   * whether they are approved       (only join_tournament() decides)
--   * their own rating                (written by the system, never the user)
-- =============================================================================

-- pgcrypto lives in `extensions` on Supabase, not `public`, so every call below
-- is written extensions.gen_random_bytes() rather than trusting a search_path.
-- Two separate things would otherwise break, only on Supabase: the SECURITY
-- DEFINER functions pin their search_path, and the session applying this file
-- may not have `extensions` on its path at all - in which case the column
-- default on tournament_secrets fails at CREATE TABLE.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- -----------------------------------------------------------------------------
-- Enums
-- -----------------------------------------------------------------------------
do $$ begin
  create type public.game_type as enum ('chess', 'checkers');
exception when duplicate_object then null; end $$;

-- A variant is a rule set; a format is a pairing system. The old wizard listed
-- "International Checkers" beside "Swiss System" as though they were the same
-- kind of choice. They are not: a Swiss tournament of Brazilian checkers is an
-- ordinary thing to want.
do $$ begin
  create type public.game_variant as enum ('standard', 'international', 'brazilian');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.tournament_format as enum ('swiss', 'round_robin', 'knockout', 'arena');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.tournament_status as enum ('draft', 'registration', 'live', 'finished', 'archived');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.admin_role as enum ('co_admin', 'moderator');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.participant_status as enum ('pending', 'approved', 'rejected', 'withdrawn');
exception when duplicate_object then null; end $$;

-- -----------------------------------------------------------------------------
-- Profiles
-- -----------------------------------------------------------------------------
-- No email column. Profiles are publicly readable (they are how you see who you
-- are playing), and the old model copied email into both profiles and
-- participants - which would have published every player's address beside
-- their name on every public roster.
create table if not exists public.profiles (
  id              uuid primary key references auth.users (id) on delete cascade,
  username        text unique check (username ~ '^[a-z0-9_]{3,24}$'),
  display_name    text check (char_length(display_name) between 1 and 60),
  avatar_url      text,
  country         text check (country ~ '^[A-Z]{2}$'),
  chess_rating    int not null default 1500 check (chess_rating between 100 and 3500),
  checkers_rating int not null default 1500 check (checkers_rating between 100 and 3500),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- Tournaments
-- -----------------------------------------------------------------------------
create table if not exists public.tournaments (
  id                   uuid primary key default gen_random_uuid(),
  slug                 text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' and char_length(slug) <= 72),
  -- Defaults to the caller and cannot be updated (see grants). Nobody creates a
  -- tournament on somebody else's behalf, and nobody takes one over by PATCH.
  -- References profiles rather than auth.users so PostgREST can embed the
  -- owner's name along this key; profiles itself cascades from auth.users.
  owner_id             uuid not null default auth.uid() references public.profiles (id) on delete cascade,

  title                text not null check (char_length(title) between 3 and 120),
  description          text check (char_length(description) <= 2000),

  game                 public.game_type not null,
  variant              public.game_variant not null,
  format               public.tournament_format not null,

  -- Structured, not "5+3 Blitz". Phase 2 runs a real clock off these numbers,
  -- and a clock cannot be driven from a label.
  clock_base_s         int not null check (clock_base_s between 15 and 10800),
  clock_increment_s    int not null default 0 check (clock_increment_s between 0 and 180),

  starts_at            timestamptz not null,
  -- Swiss / round robin / knockout use rounds; arena runs for a duration.
  rounds_count         int check (rounds_count between 1 and 30),
  arena_minutes        int check (arena_minutes between 10 and 1440),
  tiebreaks            text[] not null default array['buchholz', 'sonneborn_berger']
                         check (tiebreaks <@ array['buchholz', 'buchholz_cut1', 'sonneborn_berger', 'direct_encounter', 'wins', 'progressive']),

  -- null = unlimited, which the wizard offers.
  max_participants     int check (max_participants between 2 and 4096),

  -- Who can find it, and who can see inside it.
  is_listed            boolean not null default true,
  participants_visible boolean not null default true,
  games_watchable      boolean not null default true,

  -- How you get in. The two combine: a code can admit you straight in, or only
  -- into the queue for the organiser to approve.
  requires_code        boolean not null default false,
  auto_approve         boolean not null default true,

  status               public.tournament_status not null default 'draft',
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now(),

  constraint variant_matches_game check (
    (game = 'chess'    and variant = 'standard') or
    (game = 'checkers' and variant in ('international', 'brazilian'))
  ),
  constraint arena_has_duration check (
    (format = 'arena' and arena_minutes is not null) or
    (format <> 'arena' and rounds_count is not null)
  )
);

create index if not exists tournaments_owner_idx on public.tournaments (owner_id);
create index if not exists tournaments_listed_idx on public.tournaments (starts_at) where is_listed and status in ('registration', 'live');

-- -----------------------------------------------------------------------------
-- Tournament secrets
-- -----------------------------------------------------------------------------
-- In their own table because a column cannot be hidden from a row you can
-- read. The old API returned entry_code in the public tournament response, so
-- every code was readable by anyone who could list tournaments - the code
-- protected nothing. Here only the organisers can select it, and joining checks
-- it inside join_tournament(), which never returns it.
create table if not exists public.tournament_secrets (
  tournament_id uuid primary key references public.tournaments (id) on delete cascade,
  entry_code    text check (entry_code ~ '^[A-Z0-9]{4,12}$'),
  -- An invite link carries this token. It admits straight in, past both the
  -- code and the approval queue - that is what an organiser sending you a link
  -- is saying. Hex rather than base64url: encode() only learned base64url in
  -- Postgres 18, and on the 15 Supabase may be running, every tournament insert
  -- would have failed in this default.
  invite_token  text not null unique default encode(extensions.gen_random_bytes(16), 'hex'),
  rotated_at    timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- Staff
-- -----------------------------------------------------------------------------
-- The owner is not a row here; ownership is tournaments.owner_id. Keeping it
-- out means there is exactly one owner, always, and no row whose deletion could
-- leave a tournament with none.
create table if not exists public.tournament_admins (
  id            uuid primary key default gen_random_uuid(),
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  user_id       uuid not null references public.profiles (id) on delete cascade,
  role          public.admin_role not null default 'moderator',
  added_by      uuid not null default auth.uid() references public.profiles (id),
  created_at    timestamptz not null default now(),
  unique (tournament_id, user_id)
);

create index if not exists tournament_admins_user_idx on public.tournament_admins (user_id);

-- -----------------------------------------------------------------------------
-- Participants
-- -----------------------------------------------------------------------------
create table if not exists public.participants (
  id              uuid primary key default gen_random_uuid(),
  tournament_id   uuid not null references public.tournaments (id) on delete cascade,
  user_id         uuid not null references public.profiles (id) on delete cascade,
  status          public.participant_status not null default 'pending',
  -- Snapshotted at entry, so seeding and pairing use the rating the player had
  -- when they joined, not one that moves under the event while it runs.
  rating_at_entry int,
  seed            int check (seed >= 1),
  joined_via      text not null default 'open' check (joined_via in ('open', 'code', 'invite', 'added')),
  decided_by      uuid references public.profiles (id),
  decided_at      timestamptz,
  created_at      timestamptz not null default now(),
  unique (tournament_id, user_id)
);

create index if not exists participants_user_idx on public.participants (user_id);
create index if not exists participants_tournament_status_idx on public.participants (tournament_id, status);

-- =============================================================================
-- Role checks
-- =============================================================================
-- In a `private` schema, not `public`. RLS policies evaluate as the caller, so
-- the caller needs EXECUTE on these - which, in `public`, would also publish
-- each one as a PostgREST RPC endpoint anyone could call. Supabase exposes only
-- `public` over the API, so here they are usable by policies and unreachable
-- from outside.
create schema if not exists private;
grant usage on schema private to anon, authenticated;

-- SECURITY DEFINER, so a policy on tournaments can ask about tournament_admins
-- without that table's own policies being evaluated recursively. Each answers
-- one question about auth.uid() and nothing else, which is what makes it safe
-- to let them step around RLS.

create or replace function private.is_tournament_owner(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournaments where id = t and owner_id = auth.uid());
$$;

-- Owner or co-admin: may change settings, see secrets, manage the roster.
create or replace function private.is_tournament_manager(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournaments where id = t and owner_id = auth.uid())
      or exists (select 1 from tournament_admins
                  where tournament_id = t and user_id = auth.uid() and role = 'co_admin');
$$;

-- Any staff, moderators included: may see the full roster and decide entries.
create or replace function private.is_tournament_staff(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournaments where id = t and owner_id = auth.uid())
      or exists (select 1 from tournament_admins where tournament_id = t and user_id = auth.uid());
$$;

create or replace function private.is_tournament_participant(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from participants
                  where tournament_id = t and user_id = auth.uid() and status in ('pending', 'approved'));
$$;

-- Whether a tournament's approved roster is public. Listed events only: the
-- roster of an unlisted event would otherwise name it to anyone who listed
-- participants, defeating the point of not listing it.
create or replace function private.roster_is_public(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournaments
                  where id = t and is_listed and participants_visible and status <> 'draft');
$$;

-- =============================================================================
-- Triggers
-- =============================================================================

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

drop trigger if exists profiles_touch on public.profiles;
create trigger profiles_touch before update on public.profiles
  for each row execute function public.touch_updated_at();

drop trigger if exists tournaments_touch on public.tournaments;
create trigger tournaments_touch before update on public.tournaments
  for each row execute function public.touch_updated_at();

-- Every account gets a profile, so there is never a participant with no name to
-- show. SECURITY DEFINER because the insert happens inside auth's own
-- transaction, as a role with no rights on public.profiles.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  base text;
begin
  -- A username from the email's local part, with a random tail so two "joel"s
  -- never collide. Everyone gets one so organisers can add staff by name -
  -- looking people up by email instead would need a function that confirms
  -- whether an address has an account, which is a user-enumeration oracle.
  base := left(regexp_replace(lower(split_part(coalesce(new.email, ''), '@', 1)), '[^a-z0-9_]+', '', 'g'), 16);
  if char_length(base) < 3 then
    base := 'player';
  end if;

  insert into profiles (id, username, display_name, avatar_url)
  values (
    new.id,
    base || '_' || substr(encode(extensions.gen_random_bytes(3), 'hex'), 1, 5),
    nullif(left(coalesce(new.raw_user_meta_data ->> 'full_name',
                         new.raw_user_meta_data ->> 'name',
                         split_part(new.email, '@', 1)), 60), ''),
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Accounts that signed up before this file was applied never fired the trigger.
-- Without a profile they can sign in but not create, join or be added as
-- staff, since all three reference profiles. Same rules as handle_new_user();
-- a no-op once everyone has one, so re-applying this file is safe.
insert into profiles (id, username, display_name, avatar_url)
select
  u.id,
  coalesce(nullif(b.base, ''), 'player') || '_' || substr(encode(extensions.gen_random_bytes(3), 'hex'), 1, 5),
  nullif(left(coalesce(u.raw_user_meta_data ->> 'full_name',
                       u.raw_user_meta_data ->> 'name',
                       split_part(u.email, '@', 1)), 60), ''),
  u.raw_user_meta_data ->> 'avatar_url'
from auth.users u
cross join lateral (
  select case when char_length(s) < 3 then 'player' else s end as base
  from (select left(regexp_replace(lower(split_part(coalesce(u.email, ''), '@', 1)), '[^a-z0-9_]+', '', 'g'), 16) as s) raw
) b
where not exists (select 1 from profiles p where p.id = u.id)
on conflict (id) do nothing;

-- A slug from the title when none is given, with a short random tail so two
-- "Saturday Rapid" events never collide and the URL cannot be guessed from a
-- title alone.
create or replace function public.tournament_defaults()
returns trigger language plpgsql as $$
declare
  base text;
begin
  if new.slug is null or new.slug = '' then
    base := trim(both '-' from regexp_replace(lower(new.title), '[^a-z0-9]+', '-', 'g'));
    base := left(nullif(base, ''), 56);
    new.slug := coalesce(base || '-', '') || substr(encode(extensions.gen_random_bytes(4), 'hex'), 1, 6);
  end if;
  return new;
end $$;

drop trigger if exists tournaments_defaults on public.tournaments;
create trigger tournaments_defaults before insert on public.tournaments
  for each row execute function public.tournament_defaults();

-- Every tournament gets its secrets row, so an invite link always exists.
create or replace function public.create_tournament_secrets()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  insert into tournament_secrets (tournament_id) values (new.id) on conflict do nothing;
  return new;
end $$;

drop trigger if exists tournaments_secrets on public.tournaments;
create trigger tournaments_secrets after insert on public.tournaments
  for each row execute function public.create_tournament_secrets();

-- The lifecycle only moves forward, with two deliberate exceptions: an
-- organiser can take a published event back to draft before it starts, and
-- can archive at any point. A finished tournament reopening for registration
-- would let results be played over.
create or replace function public.guard_tournament_status()
returns trigger language plpgsql as $$
begin
  if new.status = old.status then
    return new;
  end if;
  if new.status = 'archived'
     or (old.status = 'draft'        and new.status = 'registration')
     or (old.status = 'registration' and new.status in ('draft', 'live'))
     or (old.status = 'live'         and new.status = 'finished') then
    return new;
  end if;
  raise exception 'a tournament cannot go from % to %', old.status, new.status
    using errcode = 'check_violation';
end $$;

drop trigger if exists tournaments_status_guard on public.tournaments;
create trigger tournaments_status_guard before update of status on public.tournaments
  for each row execute function public.guard_tournament_status();

-- =============================================================================
-- Joining
-- =============================================================================
-- The ONLY way into a tournament. There is no insert policy on participants,
-- so this function is the whole gate: it decides who you are (auth.uid(), never
-- a request body), whether you may enter, and whether you are approved. The old
-- API took user_id and status from the client, so anyone could join as anyone
-- and send "Approved" to skip the organiser.
create or replace function public.join_tournament(
  p_slug   text,
  p_code   text default null,
  p_invite text default null
)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
declare
  me      uuid := auth.uid();
  t       tournaments;
  s       tournament_secrets;
  via     text := 'open';
  invited boolean := false;
  taken   int;
  row     participants;
begin
  if me is null then
    raise exception 'sign in to join' using errcode = '28000';
  end if;

  select * into t from tournaments where slug = p_slug;
  if not found then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  if t.status <> 'registration' then
    raise exception 'this tournament is not taking entries' using errcode = 'check_violation';
  end if;

  select * into s from tournament_secrets where tournament_id = t.id;
  invited := p_invite is not null and p_invite = s.invite_token;

  -- Already in? Return the row rather than failing: opening the invite link
  -- twice should not look like an error.
  select * into row from participants where tournament_id = t.id and user_id = me;
  if found then
    if row.status = 'withdrawn' then
      -- Re-entering after withdrawing goes back through the gate below.
      null;
    else
      return row;
    end if;
  end if;

  if invited then
    via := 'invite';
  elsif t.requires_code then
    if p_code is null or upper(trim(p_code)) is distinct from s.entry_code then
      raise exception 'that entry code is not right' using errcode = '28000';
    end if;
    via := 'code';
  end if;

  if t.max_participants is not null then
    select count(*) into taken from participants
     where tournament_id = t.id and status = 'approved';
    if taken >= t.max_participants then
      raise exception 'this tournament is full' using errcode = 'check_violation';
    end if;
  end if;

  insert into participants (tournament_id, user_id, status, rating_at_entry, joined_via, decided_at)
  values (
    t.id,
    me,
    -- The cast is not decoration. A CASE of string literals resolves to text,
    -- and Postgres will not assign text to an enum column - without it this
    -- insert fails for every caller, which is to say nobody could join anything.
    (case when invited or t.auto_approve then 'approved' else 'pending' end)::participant_status,
    (select case when t.game = 'chess' then chess_rating else checkers_rating end
       from profiles where id = me),
    via,
    case when invited or t.auto_approve then now() end
  )
  on conflict (tournament_id, user_id) do update
    set status          = excluded.status,
        rating_at_entry = excluded.rating_at_entry,
        joined_via      = excluded.joined_via,
        decided_at      = excluded.decided_at,
        decided_by      = null
  returning * into row;

  return row;
end $$;

-- Leaving is yours to do, and only before the event starts: withdrawing from a
-- live event would void games already paired.
create or replace function public.withdraw_from_tournament(p_slug text)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
declare
  row participants;
begin
  update participants p
     set status = 'withdrawn'
    from tournaments t
   where t.slug = p_slug
     and p.tournament_id = t.id
     and p.user_id = auth.uid()
     and t.status in ('draft', 'registration')
  returning p.* into row;

  if not found then
    raise exception 'nothing to withdraw from' using errcode = 'no_data_found';
  end if;
  return row;
end $$;

-- An organiser approving or rejecting an entry. A function rather than a plain
-- UPDATE so capacity is checked at the moment of approval - the same cap
-- join_tournament() enforces, which a direct status update would step around.
create or replace function public.decide_participant(p_participant uuid, p_status public.participant_status)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
declare
  row   participants;
  t     tournaments;
  taken int;
begin
  if p_status not in ('approved', 'rejected') then
    raise exception 'an entry can only be approved or rejected' using errcode = 'check_violation';
  end if;

  select * into row from participants where id = p_participant;
  if not found or not private.is_tournament_staff(row.tournament_id) then
    -- The same answer for "no such entry" and "not yours", so this cannot be
    -- used to probe for entries in tournaments you do not run.
    raise exception 'no such entry' using errcode = 'no_data_found';
  end if;

  select * into t from tournaments where id = row.tournament_id;
  if p_status = 'approved' and row.status <> 'approved' and t.max_participants is not null then
    select count(*) into taken from participants
     where tournament_id = t.id and status = 'approved';
    if taken >= t.max_participants then
      raise exception 'this tournament is full' using errcode = 'check_violation';
    end if;
  end if;

  update participants
     set status = p_status, decided_by = auth.uid(), decided_at = now()
   where id = p_participant
  returning * into row;
  return row;
end $$;

-- Publishing, starting, finishing, archiving. status is not client-writable,
-- so this is the only way it moves, and the lifecycle guard trigger runs on
-- every call. Managers only; the "no such tournament" answer is the same for
-- missing and not-yours, so it cannot be used to discover drafts.
create or replace function public.set_tournament_status(p_tournament uuid, p_status public.tournament_status)
returns public.tournaments
language plpgsql security definer set search_path = public, extensions as $$
declare
  row tournaments;
begin
  if not private.is_tournament_manager(p_tournament) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  update tournaments set status = p_status where id = p_tournament returning * into row;
  return row;
end $$;

-- A tournament by slug: the read path for unlisted events, and the one the
-- public page uses for all of them. Published events to anyone who has the
-- link; drafts to their staff.
-- setof, so "not found" reaches PostgREST as [] rather than a row of nulls.
-- Dropped first because CREATE OR REPLACE cannot change a return type, and an
-- earlier apply may have created the single-row version.
drop function if exists public.get_tournament(text);
create or replace function public.get_tournament(p_slug text)
returns setof public.tournaments
language sql stable security definer set search_path = public, extensions as $$
  select t.* from tournaments t
   where t.slug = p_slug
     and (t.status <> 'draft' or private.is_tournament_staff(t.id) or private.is_tournament_participant(t.id));
$$;

-- The approved roster by slug, with names. Same visibility rule as
-- get_tournament(), plus the organiser's participants_visible switch, which
-- staff and the participants themselves see past.
create or replace function public.get_roster(p_slug text)
returns table (
  participant_id  uuid,
  user_id         uuid,
  display_name    text,
  username        text,
  avatar_url      text,
  country         text,
  rating_at_entry int,
  seed            int,
  joined_at       timestamptz
)
language sql stable security definer set search_path = public, extensions as $$
  select p.id, p.user_id, pr.display_name, pr.username, pr.avatar_url, pr.country,
         p.rating_at_entry, p.seed, p.created_at
    from tournaments t
    join participants p on p.tournament_id = t.id and p.status = 'approved'
    join profiles pr on pr.id = p.user_id
   where t.slug = p_slug
     and (
       (t.status <> 'draft' and t.participants_visible)
       or private.is_tournament_staff(t.id)
       or private.is_tournament_participant(t.id)
     )
   order by p.seed nulls last, p.rating_at_entry desc nulls last, p.created_at;
$$;

-- The caller's own profile. A function because PostgREST cannot filter on
-- auth.uid(); SECURITY INVOKER, so RLS still applies inside it.
create or replace function public.me()
returns public.profiles
language sql stable security invoker set search_path = public, extensions as $$
  select * from profiles where id = auth.uid();
$$;

-- Everything the caller runs or plays in, with the part they play. INVOKER:
-- it can only return what the read policies already let them see.
create or replace function public.my_tournaments()
returns table (tournament public.tournaments, my_role text)
language sql stable security invoker set search_path = public, extensions as $$
  select t, 'owner' from tournaments t where t.owner_id = auth.uid()
  union all
  select t, a.role::text from tournaments t
    join tournament_admins a on a.tournament_id = t.id and a.user_id = auth.uid()
  union all
  select t, 'participant' from tournaments t
    join participants p on p.tournament_id = t.id and p.user_id = auth.uid()
   where p.status in ('pending', 'approved');
$$;

-- A new invite link, invalidating the old one: the remedy when a link has been
-- passed further than intended.
create or replace function public.rotate_invite(p_tournament uuid)
returns text
language plpgsql security definer set search_path = public, extensions as $$
declare
  token text;
begin
  if not private.is_tournament_manager(p_tournament) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  update tournament_secrets
     set invite_token = encode(extensions.gen_random_bytes(16), 'hex'), rotated_at = now()
   where tournament_id = p_tournament
  returning invite_token into token;
  return token;
end $$;

-- =============================================================================
-- Row level security
-- =============================================================================
alter table public.profiles           enable row level security;
alter table public.tournaments        enable row level security;
alter table public.tournament_secrets enable row level security;
alter table public.tournament_admins  enable row level security;
alter table public.participants       enable row level security;

-- Profiles: anyone can see who is playing; you edit only yourself.
drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to anon, authenticated using (true);
drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());

-- Tournaments: listed events once published; everything you run or are in.
-- Drafts are visible to their staff only.
drop policy if exists tournaments_read on public.tournaments;
-- owner_id is checked on the row itself, ahead of the helpers. The helpers are
-- STABLE, so they read a snapshot from before the statement began - on
-- INSERT ... RETURNING, which is how supabase-py inserts by default, they could
-- not see the row the owner had just created, and the insert would fail its
-- own read-back.
create policy tournaments_read on public.tournaments for select to anon, authenticated using (
  owner_id = auth.uid()
  or (status <> 'draft' and is_listed)
  or private.is_tournament_staff(id)
  or private.is_tournament_participant(id)
);
-- Unlisted events are deliberately absent from this policy. "Unlisted" has to
-- mean reachable-by-link, like an unlisted video - and a policy that let anyone
-- select unlisted rows would make `select * from tournaments` enumerate every
-- one of them. They are read through get_tournament(slug) instead, which
-- requires knowing the slug, and slugs carry a random tail.
drop policy if exists tournaments_read_by_link on public.tournaments;
drop policy if exists tournaments_insert on public.tournaments;
create policy tournaments_insert on public.tournaments for insert to authenticated
  with check (owner_id = auth.uid());
drop policy if exists tournaments_update on public.tournaments;
create policy tournaments_update on public.tournaments for update to authenticated
  using (private.is_tournament_manager(id)) with check (private.is_tournament_manager(id));
drop policy if exists tournaments_delete on public.tournaments;
create policy tournaments_delete on public.tournaments for delete to authenticated
  using (owner_id = auth.uid() and status = 'draft');

-- Secrets: organisers only, in both directions.
drop policy if exists secrets_read on public.tournament_secrets;
create policy secrets_read on public.tournament_secrets for select to authenticated
  using (private.is_tournament_manager(tournament_id));
drop policy if exists secrets_update on public.tournament_secrets;
create policy secrets_update on public.tournament_secrets for update to authenticated
  using (private.is_tournament_manager(tournament_id)) with check (private.is_tournament_manager(tournament_id));

-- Staff: visible to staff; appointed and removed by the owner alone. A co-admin
-- who could appoint co-admins could appoint a whole second team, and the owner
-- would find out from the roster.
drop policy if exists admins_read on public.tournament_admins;
create policy admins_read on public.tournament_admins for select to authenticated
  using (private.is_tournament_staff(tournament_id));
drop policy if exists admins_insert on public.tournament_admins;
create policy admins_insert on public.tournament_admins for insert to authenticated
  with check (private.is_tournament_owner(tournament_id) and user_id <> auth.uid() and added_by = auth.uid());
drop policy if exists admins_update on public.tournament_admins;
create policy admins_update on public.tournament_admins for update to authenticated
  using (private.is_tournament_owner(tournament_id)) with check (private.is_tournament_owner(tournament_id));
drop policy if exists admins_delete on public.tournament_admins;
create policy admins_delete on public.tournament_admins for delete to authenticated
  using (private.is_tournament_owner(tournament_id));

-- Participants: approved entrants are public when the organiser allows it;
-- staff see the whole roster; you always see your own row. NO insert policy -
-- join_tournament() is the only way in.
drop policy if exists participants_read on public.participants;
create policy participants_read on public.participants for select to anon, authenticated using (
  user_id = auth.uid()
  or private.is_tournament_staff(tournament_id)
  or (status = 'approved' and private.roster_is_public(tournament_id))
);
drop policy if exists participants_delete on public.participants;
create policy participants_delete on public.participants for delete to authenticated
  using (private.is_tournament_manager(tournament_id));

-- =============================================================================
-- Grants
-- =============================================================================
-- RLS decides which ROWS; grants decide which COLUMNS. Supabase grants ALL on
-- public tables to anon and authenticated by default, so these start from
-- nothing and add back only what each role should have.
revoke all on public.profiles, public.tournaments, public.tournament_secrets,
              public.tournament_admins, public.participants
  from anon, authenticated;

grant select on public.profiles, public.tournaments, public.participants to anon, authenticated;
grant select on public.tournament_secrets, public.tournament_admins to authenticated;

-- Your profile, minus the ratings: those are earned in games, not typed in.
grant update (username, display_name, avatar_url, country) on public.profiles to authenticated;

-- A tournament, minus owner_id and status. Ownership never moves; status moves
-- only through publish/start/finish, which the API calls as functions so the
-- lifecycle guard always runs with a reason attached.
grant insert (slug, title, description, game, variant, format, clock_base_s, clock_increment_s,
              starts_at, rounds_count, arena_minutes, tiebreaks, max_participants, is_listed,
              participants_visible, games_watchable, requires_code, auto_approve)
  on public.tournaments to authenticated;
grant update (title, description, clock_base_s, clock_increment_s, starts_at, rounds_count,
              arena_minutes, tiebreaks, max_participants, is_listed, participants_visible,
              games_watchable, requires_code, auto_approve)
  on public.tournaments to authenticated;
grant delete on public.tournaments to authenticated;

grant update (entry_code) on public.tournament_secrets to authenticated;

grant insert (tournament_id, user_id, role) on public.tournament_admins to authenticated;
grant update (role) on public.tournament_admins to authenticated;
grant delete on public.tournament_admins to authenticated;

grant delete on public.participants to authenticated;

-- Functions: callable by signed-in users only, and each checks its caller.
revoke all on function public.join_tournament(text, text, text) from public, anon;
revoke all on function public.withdraw_from_tournament(text) from public, anon;
revoke all on function public.decide_participant(uuid, public.participant_status) from public, anon;
revoke all on function public.rotate_invite(uuid) from public, anon;
grant execute on function public.join_tournament(text, text, text) to authenticated;
grant execute on function public.withdraw_from_tournament(text) to authenticated;
grant execute on function public.decide_participant(uuid, public.participant_status) to authenticated;
grant execute on function public.rotate_invite(uuid) to authenticated;
revoke all on function public.set_tournament_status(uuid, public.tournament_status) from public, anon;
grant execute on function public.set_tournament_status(uuid, public.tournament_status) to authenticated;

-- Readable without signing in: the public tournament page has to work for a
-- visitor following a link.
grant execute on function public.get_tournament(text) to anon, authenticated;
grant execute on function public.get_roster(text) to anon, authenticated;

-- Postgres grants EXECUTE to PUBLIC on every new function, and Supabase adds
-- anon on top - so each of these is revoked before it is granted, or an
-- anonymous visitor could call it.
revoke all on function public.me() from public, anon;
revoke all on function public.my_tournaments() from public, anon;
grant execute on function public.me() to authenticated;
grant execute on function public.my_tournaments() to authenticated;
