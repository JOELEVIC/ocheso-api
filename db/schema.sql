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

-- Helpers, checks and internal tables live in `private` (see "Role checks"
-- below for why). Created up here because the organisation checks need it
-- before the first table that uses them.
create schema if not exists private;

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

-- What an organisation pays for. Set by hand (there is no billing in v1) and
-- never writable by a client: see the column grants on organizations.
do $$ begin
  create type public.org_plan as enum ('community', 'club', 'federation');
exception when duplicate_object then null; end $$;

-- -----------------------------------------------------------------------------
-- Profiles
-- -----------------------------------------------------------------------------
-- No email column. Profiles are publicly readable (they are how you see who you
-- are playing), and the old model copied email into both profiles and
-- participants - which would have published every player's address beside
-- their name on every public roster.
--
-- Two kinds. An `account` is an Ocheso sign-in: its id IS its auth.users id.
-- A `member` is a platform's own user, entered by that platform's server
-- (db/platforms.sql): it has no auth.users row at all, belongs to one
-- organisation (org_players), and its ratings are that organisation's by
-- construction - nobody outside it ever plays it.
--
-- That is why there is no foreign key to auth.users any more: a member could
-- not satisfy one. profile_integrity() below holds the rule a key used to
-- hold - an account needs its auth row, and losing that row deletes it.
create table if not exists public.profiles (
  id              uuid primary key,
  username        text unique check (username ~ '^[a-z0-9_]{3,24}$'),
  display_name    text check (char_length(display_name) between 1 and 60),
  avatar_url      text,
  country         text check (country ~ '^[A-Z]{2}$'),
  chess_rating    int not null default 1500 check (chess_rating between 100 and 3500),
  checkers_rating int not null default 1500 check (checkers_rating between 100 and 3500),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

alter table public.profiles add column if not exists kind text not null default 'account';
alter table public.profiles drop constraint if exists profiles_kind_check;
-- A member has no username, so nothing that looks people up by name -
-- add_participant(), /v1/profiles/{username}, staff by name - can reach one.
alter table public.profiles add constraint profiles_kind_check check (
  kind in ('account', 'member') and (kind = 'account' or username is null)
);

-- The rule the foreign key used to hold, plus the one it could not: an
-- account needs its auth.users row; a member must not share an id with one
-- (or signing up could inherit a platform user's games); and neither id nor
-- kind ever changes - turning a member into an account would hand a platform
-- user's history to whoever owns that auth id.
create or replace function private.profile_integrity()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if tg_op = 'UPDATE' then
    if new.id is distinct from old.id or new.kind is distinct from old.kind then
      raise exception 'a profile''s id and kind never change' using errcode = 'check_violation';
    end if;
    return new;
  end if;
  if new.kind = 'account' and not exists (select 1 from auth.users where id = new.id) then
    raise exception 'an account profile needs an account' using errcode = 'foreign_key_violation';
  end if;
  if new.kind = 'member' and exists (select 1 from auth.users where id = new.id) then
    raise exception 'a member profile cannot share an account''s id' using errcode = 'check_violation';
  end if;
  return new;
end $$;
revoke all on function private.profile_integrity() from public, anon, authenticated;

drop trigger if exists profiles_integrity on public.profiles;
create trigger profiles_integrity before insert or update of id, kind on public.profiles
  for each row execute function private.profile_integrity();

-- What `on delete cascade` did: an account deleted in Auth takes its profile,
-- and through it everything that cascades from profiles. Account profiles
-- only - a member's id is never an auth id.
create or replace function public.handle_deleted_user()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from profiles where id = old.id and kind = 'account';
  return old;
end $$;

drop trigger if exists on_auth_user_deleted on auth.users;
create trigger on_auth_user_deleted after delete on auth.users
  for each row execute function public.handle_deleted_user();

-- Databases made before member profiles carry profiles_id_fkey. It goes, but
-- only if nothing already breaks the rule the trigger above takes over: one
-- statement, all or nothing, and it refuses rather than drop a key over rows
-- that would be orphans the moment it is gone.
do $$
begin
  if exists (select 1 from pg_constraint
              where conname = 'profiles_id_fkey' and conrelid = 'public.profiles'::regclass) then
    if exists (select 1 from public.profiles p where not exists (select 1 from auth.users u where u.id = p.id)) then
      raise exception 'profiles has rows with no auth.users row; resolve them before applying this file';
    end if;
    alter table public.profiles drop constraint profiles_id_fkey;
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- Organisations
-- -----------------------------------------------------------------------------
-- A company or platform running tournaments inside its own site or app
-- (docs/OCHESO_PLATFORMS.md). Here, not in db/platforms.sql, because the role
-- checks below - which every tournament policy runs - ask who manages an
-- organisation's events, and SQL functions are checked against the tables
-- they name when they are created.

-- A brand is rendered into other people's pages, so it is checked as data
-- here and never accepted as CSS: known keys only, colours as #rrggbb, a font
-- from a fixed list, URLs that are https and cannot break out of a quoted
-- attribute or a url(). 4 KB at most.
create or replace function private.brand_url_ok(u jsonb)
returns boolean language sql immutable as $$
  select jsonb_typeof(u) = 'string'
     and char_length(u #>> '{}') <= 500
     and (u #>> '{}') ~ '^https://[^\s"''<>()\\]+$';
$$;

create or replace function private.brand_ok(b jsonb)
returns boolean language sql immutable as $$
  select b is not null and jsonb_typeof(b) = 'object' and octet_length(b::text) <= 4096
     and not exists (select 1 from jsonb_object_keys(b) k
                      where k not in ('v', 'name', 'logo_url', 'logo_dark_url', 'colors', 'font',
                                      'radius', 'theme', 'board', 'locale', 'badge'))
     and (not b ? 'v' or jsonb_typeof(b -> 'v') = 'number')
     and (not b ? 'name' or (jsonb_typeof(b -> 'name') = 'string' and char_length(b ->> 'name') between 1 and 80))
     and (not b ? 'logo_url' or private.brand_url_ok(b -> 'logo_url'))
     and (not b ? 'logo_dark_url' or private.brand_url_ok(b -> 'logo_dark_url'))
     and (not b ? 'colors' or (
           jsonb_typeof(b -> 'colors') = 'object'
           and (select count(*) from jsonb_object_keys(b -> 'colors')) <= 16
           and not exists (select 1 from jsonb_each(b -> 'colors') c
                            where c.key !~ '^[a-z][a-z0-9_]{0,23}$'
                               or jsonb_typeof(c.value) <> 'string'
                               or (c.value #>> '{}') !~ '^#[0-9a-fA-F]{6}$')))
     and (not b ? 'font' or (jsonb_typeof(b -> 'font') = 'string'
                             and b ->> 'font' in ('system', 'inter', 'poppins', 'manrope', 'roboto')))
     and (not b ? 'radius' or (jsonb_typeof(b -> 'radius') = 'number' and (b ->> 'radius')::numeric between 0 and 24))
     and (not b ? 'theme' or (jsonb_typeof(b -> 'theme') = 'string' and b ->> 'theme' in ('auto', 'light', 'dark')))
     and (not b ? 'board' or (jsonb_typeof(b -> 'board') = 'string'
                              and b ->> 'board' in ('slate', 'wood', 'green', 'brand', 'contrast')))
     and (not b ? 'locale' or (jsonb_typeof(b -> 'locale') = 'string' and b ->> 'locale' in ('en', 'fr', 'both')))
     and (not b ? 'badge' or jsonb_typeof(b -> 'badge') = 'boolean');
$$;

-- Who may frame the embeds, in CSP source syntax: https://host[:port] or
-- https://*.host (never a bare *.tld), and http:// only for local testing.
-- Empty means anywhere: most organisers never fill it in, and an embed that
-- refuses to load is worse than one that loads everywhere - sign-in still
-- checks the parent origin against this list when it is not empty.
create or replace function private.origins_ok(o text[])
returns boolean language sql immutable as $$
  select o is not null and coalesce(cardinality(o), 0) <= 50
     and not exists (select 1 from unnest(o) x
                      where x is null or char_length(x) > 200 or not (
                        x ~ '^https://[a-z0-9-]+(\.[a-z0-9-]+)*(:[0-9]{1,5})?$'
                        or x ~ '^https://\*\.[a-z0-9-]+(\.[a-z0-9-]+)+$'
                        or x ~ '^http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$'));
$$;

create table if not exists public.organizations (
  id              uuid primary key default gen_random_uuid(),
  -- The org's address: /o/{slug}, /studio/{slug}. Words the site routes on
  -- are refused so an org can never shadow a page.
  slug            text not null unique check (
                    slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' and char_length(slug) between 3 and 40
                    and slug not in ('www', 'api', 'embed', 'admin', 'o', 'app', 'studio', 'platforms', 'developers')),
  name            text not null check (char_length(btrim(name)) between 2 and 80),
  website         text check (char_length(website) <= 300 and website ~ '^https://[^\s"''<>()\\]+$'),
  brand           jsonb not null default '{}'::jsonb check (private.brand_ok(brand)),
  allowed_origins text[] not null default '{}' check (private.origins_ok(allowed_origins)),
  -- IANA name, checked by organizations_guard() (pg_timezone_names is not
  -- immutable, so it cannot sit in a CHECK).
  timezone        text not null default 'Africa/Douala',
  support_email   text check (char_length(support_email) between 6 and 254
                              and support_email ~ '^[^@\s<>",;]+@[^@\s<>",;]+\.[^@\s<>",;]+$'),
  plan            public.org_plan not null default 'community',
  status          text not null default 'active' check (status in ('active', 'suspended')),
  created_by      uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

-- Exactly one owner (the partial unique index), any number of admins and
-- staff. Accounts only (private.require_account). `restrict` on the user: an
-- owner deleting their account would leave an organisation nobody runs, so
-- they transfer or leave first.
create table if not exists public.org_members (
  org_id     uuid not null references public.organizations (id) on delete cascade,
  user_id    uuid not null references public.profiles (id) on delete restrict,
  role       text not null check (role in ('owner', 'admin', 'staff')),
  added_by   uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create unique index if not exists org_members_one_owner on public.org_members (org_id) where role = 'owner';
create index if not exists org_members_user_idx on public.org_members (user_id);

-- A member profile and who it is on the platform that owns it. The email is
-- what the platform asserted and nobody verified: it is never used to claim an
-- invite or to send mail, and only the organisation's owner and admins see it.
create table if not exists public.org_players (
  profile_id   uuid primary key references public.profiles (id) on delete cascade,
  org_id       uuid not null references public.organizations (id) on delete cascade,
  external_id  text not null check (char_length(external_id) between 1 and 128),
  email        text check (char_length(email) <= 254),
  blocked_at   timestamptz,
  created_at   timestamptz not null default now(),
  last_seen_at timestamptz,
  unique (org_id, external_id)
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
  constraint format_shape check (
    (format = 'arena') = (arena_minutes is not null)
    and (format <> 'swiss' or rounds_count is not null)
  )
);

-- Only a Swiss event has a round count the organiser chooses. A round robin's
-- follows from its field (n - 1), a knockout's from its bracket (log2 n), and
-- neither is known until entries close - so asking for one at creation made
-- organisers invent a number the pairing engine would have to ignore.
-- Replaces arena_has_duration on databases created before this change.
alter table public.tournaments drop constraint if exists arena_has_duration;
alter table public.tournaments drop constraint if exists format_shape;
alter table public.tournaments add constraint format_shape check (
  (format = 'arena') = (arena_minutes is not null)
  and (format <> 'swiss' or rounds_count is not null)
);

-- Run for an organisation (docs/OCHESO_PLATFORMS.md, C2). Insert-only, by
-- column grant: an event cannot be moved into someone else's organisation.
-- `restrict`: an organisation with events is not deleted out from under them.
alter table public.tournaments add column if not exists org_id uuid references public.organizations (id) on delete restrict;
-- Who can play: Ocheso accounts, the organisation's own platform users
-- (member profiles), or both. Platform users exist only inside an
-- organisation, so a personal tournament is always `accounts`.
alter table public.tournaments add column if not exists identity_mode text not null default 'accounts'
  check (identity_mode in ('accounts', 'platform', 'any'));
-- Only people the organiser invited (by email, by link, or entered by the
-- platform's server) get in; the entry code does not open it.
alter table public.tournaments add column if not exists invite_only boolean not null default false;
-- On the organisation's schedule, independently of the public directory.
alter table public.tournaments add column if not exists org_listed boolean not null default true;
-- Whether account-vs-account games move global ratings (private.rate).
alter table public.tournaments add column if not exists rated boolean not null default true;
-- Autopilot (db/platforms.sql): starts, pairs, breaks and finishes by itself.
alter table public.tournaments add column if not exists autopilot boolean not null default false;
alter table public.tournaments add column if not exists min_players int not null default 2 check (min_players between 2 and 4096);
-- Too few players at the start: postpone by postpone_min (at most
-- max_postpones times, then wait), wait, or cancel (archived with a note).
alter table public.tournaments add column if not exists short_field text not null default 'postpone'
  check (short_field in ('postpone', 'wait', 'cancel'));
alter table public.tournaments add column if not exists postpone_min int not null default 15 check (postpone_min between 1 and 1440);
alter table public.tournaments add column if not exists max_postpones int not null default 4 check (max_postpones between 0 and 50);
alter table public.tournaments add column if not exists round_break_s int not null default 60 check (round_break_s between 0 and 3600);
-- What autopilot last did or is waiting for, in words. Written by the system
-- only: never granted to a client.
alter table public.tournaments add column if not exists autopilot_note text check (char_length(autopilot_note) <= 500);
alter table public.tournaments add column if not exists language text not null default 'en' check (language in ('en', 'fr', 'both'));
-- Bumped with every live event about the tournament (db/platforms.sql), so an
-- embed refetches its bundle as ?rev=N and the CDN collapses the refetches.
alter table public.tournaments add column if not exists embed_rev bigint not null default 0;

alter table public.tournaments drop constraint if exists identity_needs_org;
alter table public.tournaments add constraint identity_needs_org check (org_id is not null or identity_mode = 'accounts');

create index if not exists tournaments_owner_idx on public.tournaments (owner_id);
create index if not exists tournaments_listed_idx on public.tournaments (starts_at) where is_listed and status in ('registration', 'live');
create index if not exists tournaments_org_idx on public.tournaments (org_id, starts_at) where org_id is not null;

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
  -- 'email': an emailed invite, claimed on signing in with that address.
  -- 'platform': a member profile, entered through its platform.
  joined_via      text not null default 'open' check (joined_via in ('open', 'code', 'invite', 'added', 'email', 'platform')),
  decided_by      uuid references public.profiles (id),
  decided_at      timestamptz,
  created_at      timestamptz not null default now(),
  unique (tournament_id, user_id)
);
-- Databases made before 'email' and 'platform' existed.
alter table public.participants drop constraint if exists participants_joined_via_check;
alter table public.participants add constraint participants_joined_via_check
  check (joined_via in ('open', 'code', 'invite', 'added', 'email', 'platform'));

create index if not exists participants_user_idx on public.participants (user_id);
create index if not exists participants_tournament_status_idx on public.participants (tournament_id, status);

-- -----------------------------------------------------------------------------
-- Invites by email
-- -----------------------------------------------------------------------------
-- An organiser adds people by address; each is entered automatically the first
-- time they sign in (or up) with that address confirmed (private.claim_invites,
-- db/platforms.sql). Here rather than there because joining (below) both
-- counts the seats pending invites hold and claims the caller's own.
--
-- Adding an address never looks at auth.users, so the organiser cannot learn
-- whether someone has an account. The token in the email is a consent signal
-- - "I'm in" - not a credential: it admits nobody signed in as someone else.
create table if not exists public.tournament_invites (
  id               uuid primary key default gen_random_uuid(),
  tournament_id    uuid not null references public.tournaments (id) on delete cascade,
  email            text not null check (email = lower(btrim(email)) and char_length(email) between 6 and 254
                                        and email ~ '^[^@\s<>",;]+@[^@\s<>",;]+\.[^@\s<>",;]+$'),
  name             text check (char_length(btrim(name)) between 1 and 60),
  note             text check (char_length(note) <= 500),
  token            text not null unique default encode(extensions.gen_random_bytes(16), 'hex') check (token ~ '^[0-9a-f]{32}$'),
  status           text not null default 'pending' check (status in ('pending', 'claimed', 'declined', 'revoked', 'lapsed')),
  -- null when a platform's server added it with a key.
  invited_by       uuid references public.profiles (id) on delete set null,
  claimed_by       uuid references public.profiles (id) on delete set null,
  claimed_at       timestamptz,
  -- When the claimed player was told ("Yoursite entered you in X").
  claim_seen_at    timestamptz,
  send             boolean not null default true,
  sent_at          timestamptz,
  send_error       text,
  resends          int not null default 0,
  -- Held by a mail batch while it sends, so two ticks never mail twice.
  mail_lease_until timestamptz,
  opened_at        timestamptz,
  created_at       timestamptz not null default now(),
  unique (tournament_id, email)
);
create index if not exists tournament_invites_pending_email_idx on public.tournament_invites (email) where status = 'pending';
create index if not exists tournament_invites_unsent_idx on public.tournament_invites (created_at)
  where status = 'pending' and send and sent_at is null;

-- =============================================================================
-- Role checks
-- =============================================================================
-- In a `private` schema, not `public`. RLS policies evaluate as the caller, so
-- the caller needs EXECUTE on these - which, in `public`, would also publish
-- each one as a PostgREST RPC endpoint anyone could call. Supabase exposes only
-- `public` over the API, so here they are usable by policies and unreachable
-- from outside.
grant usage on schema private to anon, authenticated;

-- SECURITY DEFINER, so a policy on tournaments can ask about tournament_admins
-- without that table's own policies being evaluated recursively. Each answers
-- one question about auth.uid() and nothing else, which is what makes it safe
-- to let them step around RLS.

-- The caller's role in an organisation, or null.
create or replace function private.org_role(p_org uuid)
returns text language sql stable security definer set search_path = public, extensions as $$
  select role from org_members where org_id = p_org and user_id = auth.uid();
$$;

-- Owner or admin: keys, brand, team, webhooks, and every one of its events.
create or replace function private.is_org_admin(p_org uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from org_members where org_id = p_org and user_id = auth.uid() and role in ('owner', 'admin'));
$$;

-- An organisation's owner and admins stand in the owner's place on every one
-- of its events: appointing staff included. Its staff run the events they
-- create (they are owner_id there) and help on the rest (is_tournament_staff).
create or replace function private.is_tournament_owner(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournaments tt
                  where tt.id = t
                    and (tt.owner_id = auth.uid()
                         or (tt.org_id is not null
                             and exists (select 1 from org_members m
                                          where m.org_id = tt.org_id and m.user_id = auth.uid()
                                            and m.role in ('owner', 'admin')))));
$$;

-- Owner or co-admin: may change settings, see secrets, manage the roster.
create or replace function private.is_tournament_manager(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select private.is_tournament_owner(t)
      or exists (select 1 from tournament_admins
                  where tournament_id = t and user_id = auth.uid() and role = 'co_admin');
$$;

-- Any staff, moderators included: may see the full roster and decide entries.
-- For an organisation's event, anyone in the organisation.
create or replace function private.is_tournament_staff(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournaments tt
                  where tt.id = t
                    and (tt.owner_id = auth.uid()
                         or (tt.org_id is not null
                             and exists (select 1 from org_members m
                                          where m.org_id = tt.org_id and m.user_id = auth.uid()))))
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

-- Whether the caller may see a member profile. Accounts are public; a
-- platform's users are not, because the platform never published them: they
-- show to the organisation's own people, and wherever they appear on a roster
-- the caller can already see (public, or theirs to run or play in). Names in
-- unlisted events and embeds go through get_people() instead.
create or replace function private.member_visible(p uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from org_players op
                   join org_members m on m.org_id = op.org_id and m.user_id = auth.uid()
                  where op.profile_id = p)
      or exists (select 1 from participants pa
                  where pa.user_id = p and pa.status = 'approved'
                    and (private.roster_is_public(pa.tournament_id)
                         or private.is_tournament_staff(pa.tournament_id)
                         or private.is_tournament_participant(pa.tournament_id)));
$$;

-- Places taken: approved entries plus pending email invites, which hold a
-- seat until they are claimed or lapse. Joining, adding, approving and
-- inviting all count with this, so an organiser who invited 30 people to a
-- 32-board event has two open places, not 32.
create or replace function private.seats_taken(t uuid)
returns int language sql stable security definer set search_path = public, extensions as $$
  select ((select count(*) from participants where tournament_id = t and status = 'approved')
        + (select count(*) from tournament_invites where tournament_id = t and status = 'pending'))::int;
$$;
revoke all on function private.seats_taken(uuid) from public, anon, authenticated;

-- Rate limits: a fixed window per bucket, counted in one upsert. Raises
-- OC429, which the API answers as 429. Here rather than in db/platforms.sql
-- because joining throttles brand-new accounts (below).
create table if not exists private.hits (
  bucket       text not null,
  window_start timestamptz not null,
  n            int not null default 0,
  primary key (bucket, window_start)
);
revoke all on private.hits from public, anon, authenticated;

create or replace function private.throttle(p_bucket text, p_max int, p_window_s int, p_n int default 1)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  ws timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_s) * p_window_s);
  c  int;
begin
  insert into private.hits as h (bucket, window_start, n) values (p_bucket, ws, p_n)
  on conflict (bucket, window_start) do update set n = h.n + excluded.n
  returning n into c;
  if c > p_max then
    raise exception 'too many requests; try again in a little while' using errcode = 'OC429';
  end if;
end $$;
revoke all on function private.throttle(text, int, int, int) from public, anon, authenticated;

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

  -- The name shown: the one given at sign-up, or player_xxxxx - never the
  -- email's local part. Organisers now add people by address, and a profile
  -- named "amina.k" beside an invite list would tell them which addresses
  -- already had accounts.
  insert into profiles (id, username, display_name, avatar_url)
  values (
    new.id,
    base || '_' || substr(encode(extensions.gen_random_bytes(3), 'hex'), 1, 5),
    coalesce(nullif(left(btrim(coalesce(new.raw_user_meta_data ->> 'full_name',
                                        new.raw_user_meta_data ->> 'name', '')), 60), ''),
             'player_' || substr(encode(extensions.gen_random_bytes(3), 'hex'), 1, 5)),
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
  coalesce(nullif(left(btrim(coalesce(u.raw_user_meta_data ->> 'full_name',
                                      u.raw_user_meta_data ->> 'name', '')), 60), ''),
           'player_' || substr(encode(extensions.gen_random_bytes(3), 'hex'), 1, 5)),
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

-- Who can play and whether it counts are what people entered on. Once anyone
-- has, or the event has started, neither moves: switching to platform users
-- would strand the accounts already in, and rating a field after the fact
-- would rate games nobody agreed to have rated.
create or replace function public.guard_tournament_identity()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if (new.identity_mode is distinct from old.identity_mode or new.rated is distinct from old.rated)
     and (old.status not in ('draft', 'registration')
          or exists (select 1 from participants where tournament_id = old.id and status in ('pending', 'approved'))) then
    raise exception 'who can play and whether it is rated are fixed once players have entered'
      using errcode = 'check_violation';
  end if;
  return new;
end $$;

drop trigger if exists tournaments_identity_guard on public.tournaments;
create trigger tournaments_identity_guard before update of identity_mode, rated on public.tournaments
  for each row execute function public.guard_tournament_identity();

-- Organisations and tournament staff are people with sign-ins. A member
-- profile has no auth.uid() to act with, so making one an admin or a
-- moderator would create a role nobody can hold.
create or replace function private.require_account()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from profiles where id = new.user_id and kind = 'account') then
    raise exception 'only Ocheso accounts can be staff' using errcode = 'check_violation';
  end if;
  return new;
end $$;
revoke all on function private.require_account() from public, anon, authenticated;

drop trigger if exists tournament_admins_account on public.tournament_admins;
create trigger tournament_admins_account before insert or update of user_id on public.tournament_admins
  for each row execute function private.require_account();
drop trigger if exists org_members_account on public.org_members;
create trigger org_members_account before insert or update of user_id on public.org_members
  for each row execute function private.require_account();

-- An IANA zone, which a CHECK cannot ask about (pg_timezone_names is not
-- immutable). Plan and status are not checked here: no client can write them.
create or replace function private.organizations_guard()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from pg_timezone_names where name = new.timezone) then
    raise exception 'unknown time zone %', new.timezone using errcode = 'check_violation';
  end if;
  return new;
end $$;
revoke all on function private.organizations_guard() from public, anon, authenticated;

drop trigger if exists organizations_guard on public.organizations;
create trigger organizations_guard before insert or update of timezone on public.organizations
  for each row execute function private.organizations_guard();
drop trigger if exists organizations_touch on public.organizations;
create trigger organizations_touch before update on public.organizations
  for each row execute function public.touch_updated_at();

-- =============================================================================
-- Joining
-- =============================================================================
-- The ONLY way into a tournament. There is no insert policy on participants,
-- so this function is the whole gate: it decides who you are (never a request
-- body), whether you may enter, and whether you are approved. The old API took
-- user_id and status from the client, so anyone could join as anyone and send
-- "Approved" to skip the organiser.
--
-- Actor-explicit, so the rule exists once for every way of arriving: the
-- signed-in caller (join_tournament, below: actor = auth.uid()), and a player
-- in an embed whose session the API proved (db/platforms.sql, embed_call:
-- actor = the session's profile, with the session checked against the
-- tournament first). Callers never choose the actor; only these two do.
create or replace function private.do_join(
  p_slug    text,
  p_code    text,
  p_invite  text,
  p_actor   uuid,
  p_session uuid
)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
declare
  t        tournaments;
  s        tournament_secrets;
  person   profiles;
  via      text := 'open';
  invited  boolean := false;
  claim    tournament_invites;
  my_email text;
  row      participants;
begin
  if p_actor is null then
    raise exception 'sign in to join' using errcode = '28000';
  end if;

  select * into t from tournaments where slug = p_slug;
  if not found then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  if p_session is not null then
    perform private.session_may_touch(p_session, t.id);
  end if;
  if t.status <> 'registration' then
    raise exception 'this tournament is not taking entries' using errcode = 'check_violation';
  end if;

  -- Who can play. A member belongs to one organisation and plays only its
  -- events; to anyone else such an event does not exist.
  select * into person from profiles where id = p_actor;
  if person.kind = 'member' then
    if t.identity_mode = 'accounts'
       or not exists (select 1 from org_players where profile_id = p_actor and org_id = t.org_id) then
      raise exception 'no such tournament' using errcode = 'no_data_found';
    end if;
    if exists (select 1 from org_players where profile_id = p_actor and blocked_at is not null) then
      raise exception 'you cannot enter this organiser''s events' using errcode = '28000';
    end if;
  elsif t.identity_mode = 'platform' then
    raise exception 'this tournament is for players signed in on the organiser''s own site' using errcode = '28000';
  end if;

  select * into s from tournament_secrets where tournament_id = t.id;
  invited := p_invite is not null and p_invite = s.invite_token;

  -- An email invite to the caller's confirmed address is the organiser
  -- having already said yes: it admits like the invite link, past the code
  -- and the queue, and into the seat it has been holding. Only the caller's
  -- own - a forwarded email admits nobody else.
  if person.kind = 'account' then
    select u.email into my_email from auth.users u where u.id = p_actor and u.email_confirmed_at is not null;
    if my_email is not null then
      select * into claim from tournament_invites
       where tournament_id = t.id and email = lower(my_email) and status = 'pending'
       for update;
    end if;
  end if;

  -- Already in? Return the row rather than failing: opening the invite link
  -- twice should not look like an error. An invite still turns a queued or
  -- refused entry into an approved one.
  select * into row from participants where tournament_id = t.id and user_id = p_actor;
  if found and row.status <> 'withdrawn' and (claim.id is null or row.status = 'approved') then
    if claim.id is not null then
      update tournament_invites set status = 'claimed', claimed_by = p_actor, claimed_at = now()
       where id = claim.id;
    end if;
    return row;
  end if;

  if claim.id is not null then
    via := 'email';
  elsif invited then
    via := 'invite';
  else
    if t.invite_only then
      raise exception 'this tournament is by invitation only' using errcode = '28000';
    end if;
    if t.requires_code then
      if p_code is null or upper(trim(p_code)) is distinct from s.entry_code then
        raise exception 'that entry code is not right' using errcode = '28000';
      end if;
      via := 'code';
    end if;
  end if;
  if person.kind = 'member' and via in ('open', 'code') then
    via := 'platform';
  end if;

  -- A claimed invite brings its own seat; everyone else needs a free one.
  if t.max_participants is not null and claim.id is null
     and private.seats_taken(t.id) >= t.max_participants then
    raise exception 'this tournament is full' using errcode = 'check_violation';
  end if;

  -- Accounts made in the last day, per tournament per hour: the cheap way to
  -- fill an open event with throwaway sign-ups.
  if person.kind = 'account'
     and exists (select 1 from auth.users where id = p_actor and created_at > now() - interval '1 day') then
    perform private.throttle('join-new:' || t.id, 200, 3600);
  end if;

  insert into participants (tournament_id, user_id, status, rating_at_entry, joined_via, decided_at)
  values (
    t.id,
    p_actor,
    -- The cast is not decoration. A CASE of string literals resolves to text,
    -- and Postgres will not assign text to an enum column - without it this
    -- insert fails for every caller, which is to say nobody could join anything.
    (case when claim.id is not null or invited or t.auto_approve then 'approved' else 'pending' end)::participant_status,
    case when t.game = 'chess' then person.chess_rating else person.checkers_rating end,
    via,
    case when claim.id is not null or invited or t.auto_approve then now() end
  )
  on conflict (tournament_id, user_id) do update
    set status          = excluded.status,
        rating_at_entry = excluded.rating_at_entry,
        joined_via      = excluded.joined_via,
        decided_at      = excluded.decided_at,
        decided_by      = null
  returning * into row;

  if claim.id is not null then
    update tournament_invites set status = 'claimed', claimed_by = p_actor, claimed_at = now()
     where id = claim.id;
  end if;
  return row;
end $$;
revoke all on function private.do_join(text, text, text, uuid, uuid) from public, anon, authenticated;

create or replace function public.join_tournament(
  p_slug   text,
  p_code   text default null,
  p_invite text default null
)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
begin
  return private.do_join(p_slug, p_code, p_invite, auth.uid(), null);
end $$;

-- Leaving is yours to do, and only before the event starts: withdrawing from a
-- live event would void games already paired.
create or replace function private.do_withdraw(p_slug text, p_actor uuid, p_session uuid)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
declare
  row participants;
  tid uuid;
begin
  if p_session is not null then
    select id into tid from tournaments where slug = p_slug;
    if tid is null then
      raise exception 'no such tournament' using errcode = 'no_data_found';
    end if;
    perform private.session_may_touch(p_session, tid);
  end if;

  update participants p
     set status = 'withdrawn'
    from tournaments t
   where t.slug = p_slug
     and p.tournament_id = t.id
     and p.user_id = p_actor
     and t.status in ('draft', 'registration')
  returning p.* into row;

  if not found then
    -- Say why: an event already under way is the usual reason, and "nothing
    -- to withdraw from" would read as if the entry had vanished.
    if exists (select 1 from tournaments t join participants p on p.tournament_id = t.id
                where t.slug = p_slug and p.user_id = p_actor
                  and t.status not in ('draft', 'registration')) then
      raise exception 'the tournament has started; ask the organiser to withdraw you'
        using errcode = 'check_violation';
    end if;
    raise exception 'nothing to withdraw from' using errcode = 'no_data_found';
  end if;
  return row;
end $$;
revoke all on function private.do_withdraw(text, uuid, uuid) from public, anon, authenticated;

create or replace function public.withdraw_from_tournament(p_slug text)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
begin
  return private.do_withdraw(p_slug, auth.uid(), null);
end $$;

-- An organiser entering someone by username: approved at once, capacity
-- checked, recorded as 'added' so the entry list says how they got in.
-- Owners and co-admins only, before the start. Members have no username, so
-- this never reaches one.
create or replace function public.add_participant(p_tournament uuid, p_username text)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
declare
  t      tournaments;
  person profiles;
  row    participants;
begin
  select * into t from tournaments where id = p_tournament;
  if not found or not private.is_tournament_manager(t.id) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  if t.status not in ('draft', 'registration') then
    raise exception 'entries are closed' using errcode = 'check_violation';
  end if;
  if t.identity_mode = 'platform' then
    raise exception 'this tournament is for players signed in on your own site' using errcode = 'check_violation';
  end if;
  select * into person from profiles where username = lower(trim(both '@' from trim(p_username)));
  if not found then
    raise exception 'nobody is called @%', lower(trim(both '@' from trim(p_username))) using errcode = 'no_data_found';
  end if;
  if t.max_participants is not null
     and not exists (select 1 from participants where tournament_id = t.id and user_id = person.id and status = 'approved')
     and private.seats_taken(t.id) >= t.max_participants then
    raise exception 'this tournament is full' using errcode = 'check_violation';
  end if;
  insert into participants (tournament_id, user_id, status, rating_at_entry, joined_via, decided_by, decided_at)
  values (t.id, person.id, 'approved',
          case when t.game = 'chess' then person.chess_rating else person.checkers_rating end,
          'added', auth.uid(), now())
  on conflict (tournament_id, user_id) do update
    set status = 'approved', joined_via = 'added', decided_by = auth.uid(), decided_at = now(),
        rating_at_entry = excluded.rating_at_entry
  returning * into row;
  return row;
end $$;

-- An organiser approving or rejecting an entry. A function rather than a plain
-- UPDATE so capacity is checked at the moment of approval - the same count
-- join_tournament() uses, which a direct status update would step around.
create or replace function public.decide_participant(p_participant uuid, p_status public.participant_status)
returns public.participants
language plpgsql security definer set search_path = public, extensions as $$
declare
  row   participants;
  t     tournaments;
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
  if p_status = 'approved' and row.status <> 'approved' and t.max_participants is not null
     and private.seats_taken(t.id) >= t.max_participants then
    raise exception 'this tournament is full' using errcode = 'check_violation';
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
alter table public.organizations      enable row level security;
alter table public.org_members        enable row level security;
alter table public.org_players        enable row level security;
alter table public.tournament_invites enable row level security;

-- Profiles: anyone can see who is playing; you edit only yourself. A
-- platform's own users are the exception - see private.member_visible().
drop policy if exists profiles_read on public.profiles;
create policy profiles_read on public.profiles for select to anon, authenticated
  using (kind = 'account' or private.member_visible(id));
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
-- Into an organisation only by its own people (any role: staff create events).
create policy tournaments_insert on public.tournaments for insert to authenticated
  with check (owner_id = auth.uid() and (org_id is null or private.org_role(org_id) is not null));
drop policy if exists tournaments_update on public.tournaments;
create policy tournaments_update on public.tournaments for update to authenticated
  using (private.is_tournament_manager(id)) with check (private.is_tournament_manager(id));
drop policy if exists tournaments_delete on public.tournaments;
-- The owner's call, which for an organisation's draft its owner and admins share.
create policy tournaments_delete on public.tournaments for delete to authenticated
  using (private.is_tournament_owner(id) and status = 'draft');

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

-- Organisations: seen by their own people, edited by owner and admins,
-- deleted by the owner. Anyone else reads the public face through
-- get_org_public() (db/platforms.sql), which leaves out everything internal.
-- Created only by create_organization(), which makes the owner row with it.
drop policy if exists organizations_read on public.organizations;
create policy organizations_read on public.organizations for select to authenticated
  using (private.org_role(id) is not null);
drop policy if exists organizations_update on public.organizations;
create policy organizations_update on public.organizations for update to authenticated
  using (private.is_org_admin(id)) with check (private.is_org_admin(id));
drop policy if exists organizations_delete on public.organizations;
create policy organizations_delete on public.organizations for delete to authenticated
  using (private.org_role(id) = 'owner');

-- The team, visible to the team. Every change is a function
-- (db/platforms.sql) so "exactly one owner" and who may promote whom are
-- checked in one place.
drop policy if exists org_members_read on public.org_members;
create policy org_members_read on public.org_members for select to authenticated
  using (private.org_role(org_id) is not null);

-- Platform players and the unverified email their platform sent: owner and
-- admins only. Written only by the platform's server, through org_call().
drop policy if exists org_players_read on public.org_players;
create policy org_players_read on public.org_players for select to authenticated
  using (private.is_org_admin(org_id));

-- Invites: the event's staff see who was invited and what happened. The
-- token is not among the granted columns: it belongs to the invitee.
drop policy if exists tournament_invites_read on public.tournament_invites;
create policy tournament_invites_read on public.tournament_invites for select to authenticated
  using (private.is_tournament_staff(tournament_id));

-- =============================================================================
-- Grants
-- =============================================================================
-- RLS decides which ROWS; grants decide which COLUMNS. Supabase grants ALL on
-- public tables to anon and authenticated by default, so these start from
-- nothing and add back only what each role should have.
revoke all on public.profiles, public.tournaments, public.tournament_secrets,
              public.tournament_admins, public.participants, public.organizations,
              public.org_members, public.org_players, public.tournament_invites
  from anon, authenticated;

grant select on public.profiles, public.tournaments, public.participants to anon, authenticated;
grant select on public.tournament_secrets, public.tournament_admins to authenticated;

-- Your profile, minus the ratings: those are earned in games, not typed in.
grant update (username, display_name, avatar_url, country) on public.profiles to authenticated;

-- A tournament, minus owner_id and status. Ownership never moves; status moves
-- only through publish/start/finish, which the API calls as functions so the
-- lifecycle guard always runs with a reason attached.
-- org_id is insert-only; autopilot_note and embed_rev are the system's.
grant insert (slug, title, description, game, variant, format, clock_base_s, clock_increment_s,
              starts_at, rounds_count, arena_minutes, tiebreaks, max_participants, is_listed,
              participants_visible, games_watchable, requires_code, auto_approve,
              org_id, identity_mode, invite_only, org_listed, rated, autopilot, min_players,
              short_field, postpone_min, max_postpones, round_break_s, language)
  on public.tournaments to authenticated;
grant update (title, description, clock_base_s, clock_increment_s, starts_at, rounds_count,
              arena_minutes, tiebreaks, max_participants, is_listed, participants_visible,
              games_watchable, requires_code, auto_approve,
              identity_mode, invite_only, org_listed, rated, autopilot, min_players,
              short_field, postpone_min, max_postpones, round_break_s, language)
  on public.tournaments to authenticated;
grant delete on public.tournaments to authenticated;

grant update (entry_code) on public.tournament_secrets to authenticated;

grant insert (tournament_id, user_id, role) on public.tournament_admins to authenticated;
grant update (role) on public.tournament_admins to authenticated;
grant delete on public.tournament_admins to authenticated;

grant delete on public.participants to authenticated;

-- Plan and status are never client-writable: an organisation does not
-- upgrade itself or lift its own suspension.
grant select on public.organizations, public.org_members, public.org_players to authenticated;
grant update (name, website, brand, allowed_origins, support_email, timezone) on public.organizations to authenticated;
grant delete on public.organizations to authenticated;

grant select (id, tournament_id, email, name, note, status, invited_by, claimed_by, claimed_at,
              send, sent_at, send_error, resends, opened_at, created_at)
  on public.tournament_invites to authenticated;

-- Functions: callable by signed-in users only, and each checks its caller.
revoke all on function public.join_tournament(text, text, text) from public, anon;
revoke all on function public.withdraw_from_tournament(text) from public, anon;
revoke all on function public.decide_participant(uuid, public.participant_status) from public, anon;
revoke all on function public.add_participant(uuid, text) from public, anon;
revoke all on function public.rotate_invite(uuid) from public, anon;
grant execute on function public.join_tournament(text, text, text) to authenticated;
grant execute on function public.withdraw_from_tournament(text) to authenticated;
grant execute on function public.decide_participant(uuid, public.participant_status) to authenticated;
grant execute on function public.add_participant(uuid, text) to authenticated;
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

-- Trigger functions are not RPCs.
revoke all on function public.handle_deleted_user() from public, anon, authenticated;
revoke all on function public.guard_tournament_identity() from public, anon, authenticated;
