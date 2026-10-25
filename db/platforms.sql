-- =============================================================================
-- Ocheso — platforms: organisations running tournaments inside their own sites
-- =============================================================================
-- Applied after db/schema.sql, db/play.sql and db/agents.sql - db/apply.sh
-- runs all four in order - by hand, idempotent like them. The contract is
-- docs/OCHESO_PLATFORMS.md (section C); the letters below refer to it.
--
-- WHAT IS NEW HERE. A company or platform (an organisation) creates Ocheso
-- tournaments and runs them inside its own website or app: invites by email,
-- its own users as players, embeds with live updates, autopilot, webhooks.
-- Tables and checks that existing functions depend on were added where those
-- functions live (organisations, member profiles, email invites, seats and
-- the throttle in schema.sql; the actor-explicit play rules in play.sql);
-- everything that is new and only new is here.
--
-- FOUR KINDS OF CALLER, AND WHAT STOPS EACH.
--   * Signed-in people (Studio, the site): row level security and functions
--     that check auth.uid(), as everywhere else.
--   * A platform's server, holding an org secret key (`ochs_...`): the API
--     hashes the key and signs the request; org_call() checks the signature,
--     then the key, its scope and the organisation.
--   * A player in an embed, holding an embed session (`oche_...`): the API
--     hashes the session and signs the request; embed_call() checks the
--     signature, then the session, then that the session may touch that
--     tournament (session_may_touch). The player is the session's profile -
--     never anything the request names.
--   * The autopilot: pg_cron pokes the API, the API signs; system_call()
--     checks the signature and, for anything that changes a tournament, the
--     lease that tick took on it.
-- The signature is private.machine_request (db/agents.sql): HMAC under the
-- referee's key, which the API holds as REFEREE_SECRET and nothing else does.
-- Each dispatcher accepts only its own kinds, so a request signed for one can
-- never be replayed into another. The API still holds no service-role key.
--
-- TOKENS (B). Org keys, player tokens and embed sessions are random and kept
-- only as SHA-256: the raw value exists once, in the reply that made it.
-- Webhook secrets are kept as they are, because the pump signs with them.
-- Invite tokens are kept as they are too: they are a consent signal in an
-- email ("I'm in"), not a credential, and resending must send the same link.
-- =============================================================================

-- pg_net makes the autopilot's and the webhooks' outgoing requests. Created
-- here when the server has it (Supabase does); a local test database has the
-- stand-in from db/test/supabase_shim.sql instead.
do $$
begin
  if exists (select 1 from pg_available_extensions where name = 'pg_net') then
    create extension if not exists pg_net;
  end if;
end $$;

-- =============================================================================
-- Infrastructure
-- =============================================================================

-- What each plan allows (A7). A literal, so it is immutable and there is no
-- table for anyone to edit; the badge is computed from the plan, never stored.
create or replace function private.plan_limit(p_plan public.org_plan, p_what text)
returns int language sql immutable as $$
  select ('{"community":  {"players": 64,   "members": 3,   "keys": 2,  "webhooks": 0,  "invites_day": 500,   "player_tokens_min": 60},
            "club":       {"players": 4096, "members": 20,  "keys": 10, "webhooks": 5,  "invites_day": 5000,  "player_tokens_min": 600},
            "federation": {"players": 4096, "members": 100, "keys": 50, "webhooks": 20, "invites_day": 50000, "player_tokens_min": 3000}}'::jsonb
          -> (p_plan::text) ->> p_what)::int;
$$;

-- One more key from the one secret (B), so there is no new signing variable to
-- deploy and leak: hex(hmac_sha256(REFEREE_SECRET, label)). The API computes
-- the same in Python; db/test/test_platforms.py holds the two to each other.
--   ocheso:v1:tick  signs the autopilot's tick (the key is the hex string)
--   ocheso:v1:ip    keys the daily IP hash the throttles count by
create or replace function private.derived_key(p_label text)
returns text language sql stable security definer set search_path = public, extensions as $$
  select encode(extensions.hmac(p_label, secret, 'sha256'), 'hex') from private.referee;
$$;
revoke all on function private.derived_key(text) from public, anon, authenticated;

-- A visitor's IP as the throttles see it: keyed, and with today's (UTC) date
-- in it, so a bucket name cannot be turned back into an address or followed
-- from one day to the next. The API sends this hash, never the address.
create or replace function private.ip_hash(p_ip text)
returns text language sql stable security definer set search_path = public, extensions as $$
  select encode(extensions.hmac(p_ip || to_char(now() at time zone 'utc', 'YYYY-MM-DD'),
                                private.derived_key('ocheso:v1:ip'), 'sha256'), 'hex');
$$;
revoke all on function private.ip_hash(text) from public, anon, authenticated;

-- Things that went wrong somewhere nobody was waiting for an answer: a claim
-- that failed inside a sign-in, an audit finding. Never shown to clients.
create table if not exists private.ops_log (
  id      bigserial primary key,
  at      timestamptz not null default now(),
  source  text not null,
  message text not null,
  detail  jsonb not null default '{}'::jsonb
);
create index if not exists ops_log_at_idx on private.ops_log (at);

-- The switches the founder flips after a deploy (H3). One row. Both features
-- start off, so applying this file changes nothing until someone means it to.
create table if not exists private.platform_settings (
  id                boolean primary key default true check (id),
  api_tick_url      text check (api_tick_url ~ '^https://[^\s]+$' or api_tick_url ~ '^http://(localhost|127\.0\.0\.1)(:[0-9]+)?/[^\s]*$'),
  autopilot_enabled boolean not null default false,
  webhooks_enabled  boolean not null default false,
  updated_at        timestamptz not null default now()
);
insert into private.platform_settings default values on conflict do nothing;
-- Whether the API can send mail (RESEND_API_KEY and MAIL_FROM set), as its
-- last tick said (sys-work), and when it said so. null: not told yet. Mail
-- can be off by design (H4 is a step of its own), and the database cannot
-- see the API's environment: without this an unsent invite would keep
-- autopilot_due() true, and a tick that skips mail would be kicked every 10
-- seconds for as long as mail stays off.
-- Plain http only for a tick URL on this machine: localhost, or the host as a
-- local Supabase stack's database container sees it (Docker's
-- host.docker.internal). Re-stated here so re-applying updates older rows.
alter table private.platform_settings drop constraint if exists platform_settings_api_tick_url_check;
alter table private.platform_settings add constraint platform_settings_api_tick_url_check
  check (api_tick_url ~ '^https://[^\s]+$' or api_tick_url ~ '^http://(localhost|127\.0\.0\.1|host\.docker\.internal)(:[0-9]+)?/[^\s]*$');
alter table private.platform_settings add column if not exists mail_on boolean;
alter table private.platform_settings add column if not exists mail_checked_at timestamptz;

create or replace function private.hooks_on()
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select coalesce((select webhooks_enabled from private.platform_settings), false);
$$;

-- =============================================================================
-- Tables
-- =============================================================================

-- Staff invited by email (C1). Unlike tournament invites they are not claimed
-- at sign-in: the person accepts from the email (accept_invite), because a
-- team membership can carry an organisation's ownership with it.
create table if not exists public.org_invites (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references public.organizations (id) on delete cascade,
  email       text not null check (email = lower(btrim(email)) and char_length(email) between 6 and 254
                                   and email ~ '^[^@\s<>",;]+@[^@\s<>",;]+\.[^@\s<>",;]+$'),
  role        text not null default 'staff' check (role in ('admin', 'staff')),
  token       text not null unique default encode(extensions.gen_random_bytes(16), 'hex') check (token ~ '^[0-9a-f]{32}$'),
  status      text not null default 'pending' check (status in ('pending', 'accepted', 'declined', 'revoked')),
  invited_by  uuid references public.profiles (id) on delete set null,
  accepted_by uuid references public.profiles (id) on delete set null,
  accepted_at timestamptz,
  created_at  timestamptz not null default now()
);
create unique index if not exists org_invites_pending_idx on public.org_invites (org_id, email) where status = 'pending';
create index if not exists org_invites_email_idx on public.org_invites (email) where status = 'pending';

-- Server-to-server keys (C1), the mirror of agent_keys: only the hash is
-- kept, the prefix says which is which, scopes say what each may do.
create table if not exists public.org_keys (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references public.organizations (id) on delete cascade,
  name         text not null check (char_length(btrim(name)) between 1 and 60),
  prefix       text not null,
  hash         text not null unique check (hash ~ '^[0-9a-f]{64}$'),
  scopes       text[] not null default array['players', 'tournaments', 'invites', 'read']
                 check (cardinality(scopes) >= 1 and scopes <@ array['players', 'tournaments', 'invites', 'read']),
  created_by   uuid references public.profiles (id) on delete set null,
  created_at   timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);
create index if not exists org_keys_org_idx on public.org_keys (org_id);

-- Where the embeds have been seen (C10): one row per origin and view, written
-- by the frame's once-a-day ping, so Studio can say "Seen on yoursite.com".
-- The ping is unauthenticated (sendBeacon from a frame), so every column here
-- is a claim, not a fact: `allowed` is origin_allowed() at the last sighting,
-- for Studio's green/amber pill and nothing else. Invitation links use a row
-- only when its origin is on a list the organiser wrote (sys_mail_batch).
create table if not exists public.org_installs (
  org_id        uuid not null references public.organizations (id) on delete cascade,
  origin        text not null,
  view          text not null,
  allowed       boolean not null,
  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  hits          int not null default 1,
  last_path     text,
  primary key (org_id, origin, view)
);

-- Weekly series (C3): a template, a weekday and a local time. series_next()
-- makes the next instance whenever there is none waiting, so an embed of the
-- series always has a live or next event to show. weekday is Postgres's dow:
-- 0 is Sunday.
create table if not exists public.tournament_series (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.organizations (id) on delete cascade,
  slug       text not null check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' and char_length(slug) between 3 and 60),
  title      text not null check (char_length(btrim(title)) between 3 and 120),
  template   jsonb not null default '{}'::jsonb check (jsonb_typeof(template) = 'object' and octet_length(template::text) <= 8192),
  weekday    int not null check (weekday between 0 and 6),
  local_time time not null,
  timezone   text not null,
  active     boolean not null default true,
  skip_dates date[] not null default '{}',
  -- Stopped for good (paused is active = false, and can resume).
  stopped_at timestamptz,
  created_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, slug)
);

-- Why the series could not make its next instance, and when to try again:
-- written by series_next_safe, so a template the plan no longer allows shows
-- in Studio and is retried every five minutes, not every tick.
alter table public.tournament_series add column if not exists last_error text;
alter table public.tournament_series add column if not exists retry_at timestamptz;

alter table public.tournaments add column if not exists series_id uuid references public.tournament_series (id) on delete set null;
create index if not exists tournaments_series_idx on public.tournaments (series_id, status) where series_id is not null;
-- The autopilot's candidates, and every live game it checks clocks on.
create index if not exists tournaments_autopilot_idx on public.tournaments (status) where autopilot and status in ('registration', 'live');
create index if not exists games_live_idx on public.games (tournament_id) where status = 'live';

-- Webhook endpoints (C9). The URL is checked so a delivery can only ever be
-- an https request to a public name on 443 - never into our own network,
-- Supabase, or ocheso.com. pg_net resolves the name itself and cannot be
-- told which addresses to refuse, so names are all this can judge: no IP
-- literals, and no name that spells one out - the wildcard-DNS services
-- (169.254.169.254.nip.io, 10-0-0-5.sslip.io, anything.localtest.me) and any
-- host with an address written into it, dots or dashes. A name of one's own
-- pointed at a private address still passes; webhook_result keeps what such a
-- delivery can teach to "unreachable" or an HTTP status.
create or replace function private.webhook_url_ok(u text)
returns boolean language sql immutable as $$
  select u is not null and char_length(u) <= 500
     and u ~ '^https://[a-z0-9.-]+(:443)?(/[^\s"''<>\\]*)?$'
     and h !~ '^[0-9.]+$'
     and h !~ '\.\.'
     and h ~ '[a-z0-9-]\.[a-z]{2,}$'
     and h !~ '(^|\.)(localhost|local|internal|intranet|lan|corp|home|localdomain)$'
     and h !~ '(^|\.)supabase\.'
     and h !~ '(^|\.)ocheso\.com$'
     and h !~ '(^|\.)(nip\.io|sslip\.io|xip\.io|nip\.direct|traefik\.me|localtest\.me|lvh\.me|vcap\.me|lacolhost\.com|localhost\.direct|1u\.ms|rbndr\.us|rebind\.it|backname\.io|ip6\.name)$'
     and h !~ '(^|[.-])[0-9]{1,3}[.-][0-9]{1,3}[.-][0-9]{1,3}[.-][0-9]{1,3}([.-]|$)'
    from (select substring(u from '^https://([a-z0-9.-]+)') as h) x;
$$;

create or replace function private.webhook_events()
returns text[] language sql immutable as $$
  select array['tournament.created', 'tournament.updated', 'tournament.published', 'tournament.started',
               'tournament.postponed', 'tournament.finished', 'tournament.archived',
               'participant.joined', 'participant.approved', 'participant.rejected', 'participant.withdrawn',
               'participant.removed', 'invite.claimed', 'invite.declined', 'invite.lapsed',
               'round.published', 'round.started', 'round.finished', 'game.started', 'game.finished',
               'autopilot.stalled', 'install.first_seen', 'webhook.test'];
$$;

create table if not exists public.org_webhooks (
  id                   uuid primary key default gen_random_uuid(),
  org_id               uuid not null references public.organizations (id) on delete cascade,
  url                  text not null check (private.webhook_url_ok(url)),
  -- Empty means every event.
  events               text[] not null default '{}' check (events <@ private.webhook_events()),
  active               boolean not null default true,
  description          text check (char_length(description) <= 200),
  consecutive_failures int not null default 0,
  first_failure_at     timestamptz,
  disabled_at          timestamptz,
  disabled_reason      text,
  created_by           uuid references public.profiles (id) on delete set null,
  created_at           timestamptz not null default now(),
  updated_at           timestamptz not null default now()
);
create index if not exists org_webhooks_org_idx on public.org_webhooks (org_id);

-- The signing secret, and the one before it for a day after a rotation: the
-- pump signs with both meanwhile, so a receiver can switch without a gap.
create table if not exists private.webhook_secrets (
  webhook_id uuid primary key references public.org_webhooks (id) on delete cascade,
  current    text not null,
  previous   text,
  rotated_at timestamptz
);

-- One delivery of one event to one endpoint. The id is the webhook-id the
-- receiver dedupes on, so it stays the same across retries. Response bodies
-- are never stored: a receiver's error page is theirs.
create table if not exists private.webhook_outbox (
  id               uuid primary key default gen_random_uuid(),
  webhook_id       uuid not null references public.org_webhooks (id) on delete cascade,
  org_id           uuid not null references public.organizations (id) on delete cascade,
  event            text not null,
  payload          jsonb not null,
  status           text not null default 'pending' check (status in ('pending', 'sending', 'delivered', 'failed')),
  attempts         int not null default 0,
  next_attempt_at  timestamptz not null default now(),
  request_id       bigint,
  response_status  int,
  last_error       text,
  last_attempt_at  timestamptz,
  delivered_at     timestamptz,
  created_at       timestamptz not null default now()
);
create index if not exists webhook_outbox_due_idx on private.webhook_outbox (next_attempt_at) where status = 'pending';
create index if not exists webhook_outbox_sending_idx on private.webhook_outbox (request_id) where status = 'sending';
create index if not exists webhook_outbox_webhook_idx on private.webhook_outbox (webhook_id, created_at desc);

-- Player tokens (B): what a platform's server hands its page, exchanged by
-- the frame for an embed session. Ten minutes, reusable meanwhile - one fetch
-- serves every widget on the page.
create table if not exists private.player_tokens (
  hash          text primary key check (hash ~ '^[0-9a-f]{64}$'),
  org_id        uuid not null references public.organizations (id) on delete cascade,
  profile_id    uuid not null references public.profiles (id) on delete cascade,
  tournament_id uuid references public.tournaments (id) on delete cascade,
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null
);

-- Embed sessions (B, A4): every embed action, member or account, is made with
-- one. Scoped to an organisation (and to one tournament when the token or the
-- personal event says so); members 12 h, accounts 7 days and revocable.
create table if not exists private.embed_sessions (
  id            uuid primary key default gen_random_uuid(),
  hash          text not null unique check (hash ~ '^[0-9a-f]{64}$'),
  kind          text not null check (kind in ('member', 'account')),
  org_id        uuid references public.organizations (id) on delete cascade,
  profile_id    uuid not null references public.profiles (id) on delete cascade,
  tournament_id uuid references public.tournaments (id) on delete cascade,
  parent_origin text,
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  last_used_at  timestamptz,
  revoked_at    timestamptz
);
create index if not exists embed_sessions_profile_idx on private.embed_sessions (profile_id) where revoked_at is null;

-- Google sign-in for a frame that cannot do OAuth itself (E4): the frame
-- keeps S and registers sha256(S); the popup, signed in first-party, binds
-- its account to that hash; the frame redeems S for a session. Knowing the
-- hash (it is in the popup's URL) is not enough to redeem.
create table if not exists private.embed_handoffs (
  hash          text primary key check (hash ~ '^[0-9a-f]{64}$'),
  org_id        uuid references public.organizations (id) on delete cascade,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  created_at    timestamptz not null default now(),
  bind_by       timestamptz not null,
  profile_id    uuid references public.profiles (id) on delete cascade,
  bound_at      timestamptz,
  redeemed_at   timestamptz
);

-- Broadcast topics (C7): 128 random bits per tournament and per game, handed
-- out only to those who may watch. Clients cannot send on them (no insert
-- policy), so a topic is a read capability, nothing more.
create table if not exists private.live_topics (
  kind  text not null check (kind in ('t', 'g')),
  ref   uuid not null,
  topic text not null unique default encode(extensions.gen_random_bytes(16), 'hex') check (topic ~ '^[0-9a-f]{32}$'),
  primary key (kind, ref)
);

-- Mail that is not an invite (invites are sent straight from
-- tournament_invites): staff invites, "your event was postponed", "your
-- webhook was switched off". `to_user` is resolved to an address only when
-- the batch is sent, so no address is copied here that need not be.
create table if not exists private.mail_outbox (
  id            bigserial primary key,
  kind          text not null,
  to_email      text,
  to_user       uuid references public.profiles (id) on delete cascade,
  org_id        uuid references public.organizations (id) on delete cascade,
  tournament_id uuid references public.tournaments (id) on delete cascade,
  data          jsonb not null default '{}'::jsonb,
  created_at    timestamptz not null default now(),
  lease_until   timestamptz,
  attempts      int not null default 0,
  sent_at       timestamptz,
  send_error    text,
  check (to_email is not null or to_user is not null)
);
create index if not exists mail_outbox_unsent_idx on private.mail_outbox (created_at) where sent_at is null;

-- Addresses that bounced or complained: never mailed again.
create table if not exists private.email_suppressions (
  email      text primary key,
  reason     text,
  created_at timestamptz not null default now()
);

-- Each autopilot poke, so pokes never stack while the API is still busy.
create table if not exists private.kicks (
  id         bigserial primary key,
  at         timestamptz not null default now(),
  request_id bigint
);
create index if not exists kicks_at_idx on private.kicks (at);

-- What the autopilot knows about a tournament (C8). The lease is how two
-- ticks never act on one tournament at once: only transaction-scoped locks
-- take it (PostgREST pools connections, so a session lock would outlive the
-- request that took it), and every later sys-* call names it.
create table if not exists private.autopilot_state (
  tournament_id  uuid primary key references public.tournaments (id) on delete cascade,
  lease_id       uuid,
  lease_until    timestamptz,
  postponed      int not null default 0,
  next_check_at  timestamptz,
  -- "+5 min break" from Studio: nothing happens before this.
  hold_until     timestamptz,
  last_action    text,
  last_action_at timestamptz,
  last_error     text,
  errors         int not null default 0
);

-- Idempotency-Key (D2), for the platform API's POSTs: the reply, kept a day,
-- under a hash of the key. Never for player tokens, whose reply is a secret.
create table if not exists private.org_idempotency (
  org_id     uuid not null references public.organizations (id) on delete cascade,
  kind       text not null,
  key_hash   text not null check (char_length(key_hash) between 16 and 128),
  response   jsonb not null,
  created_at timestamptz not null default now(),
  primary key (org_id, kind, key_hash)
);

revoke all on private.ops_log, private.platform_settings, private.webhook_secrets, private.webhook_outbox,
              private.player_tokens, private.embed_sessions, private.embed_handoffs, private.live_topics,
              private.mail_outbox, private.email_suppressions, private.kicks, private.autopilot_state,
              private.org_idempotency
  from public, anon, authenticated;

-- =============================================================================
-- Helpers
-- =============================================================================

-- Whether a page at `p_origin` may host this organisation's embeds with a
-- signed-in player: the same rules as CSP frame-ancestors, so `*.a.com`
-- matches `https://x.a.com` and not `https://a.com`. An empty list allows any.
create or replace function private.origin_allowed(p_origins text[], p_origin text)
returns boolean language sql immutable as $$
  select coalesce(cardinality(p_origins), 0) = 0
      or exists (select 1 from unnest(p_origins) a
                  where lower(a) = lower(p_origin)
                     or (a like 'https://*.%'
                         and lower(p_origin) ~ '^https://[a-z0-9-]+(\.[a-z0-9-]+)*$'
                         and char_length(p_origin) > char_length(a) - 1
                         and right(lower(p_origin), char_length(a) - 9) = lower(substr(a, 10))));
$$;

-- Whether an origin is on the organisation's OWN list: what it declared, as
-- opposed to origin_allowed's "an empty list allows any". Anything that acts
-- on where an embed was seen - an invitation's "I'm in" link - needs this
-- one, because a sighting is an unauthenticated ping that names any origin
-- it likes; only a list the organiser wrote turns it into something to trust.
create or replace function private.origin_listed(p_origins text[], p_origin text)
returns boolean language sql immutable as $$
  select coalesce(cardinality(p_origins), 0) > 0 and private.origin_allowed(p_origins, p_origin);
$$;

-- A path as the frame reports it (location.pathname), or null: no query, no
-- fragment, no `//` (which some servers redirect as a scheme-relative URL), no
-- dot segments or encoded slashes, nothing that could leave the origin when
-- it is glued after one. The ping is unauthenticated, so this is what keeps a
-- spoofed path from turning a partner's own page into a redirect elsewhere.
create or replace function private.plain_path(p text)
returns text language sql immutable as $$
  select case when char_length(p) <= 300 and p ~ '^/[A-Za-z0-9._~!$&*+,;=:@%/-]*$'
               and p !~ '//' and p !~ '(^|/)\.\.?(/|$)' and p !~* '%(2f|5c|2e)'
              then p end;
$$;

-- The badge under an embed (A7): always on for community, subtle for club,
-- and hideable - brand.badge = false - for federation.
create or replace function private.org_badge(o public.organizations)
returns text language sql immutable as $$
  select case o.plan
           when 'community' then 'full'
           when 'club' then 'subtle'
           else case when o.brand -> 'badge' = 'false'::jsonb then 'hidden' else 'subtle' end
         end;
$$;

-- An organisation as anyone may see it.
create or replace function private.org_public_json(o public.organizations)
returns jsonb language sql immutable as $$
  select jsonb_build_object('id', o.id, 'slug', o.slug, 'name', o.name, 'website', o.website, 'brand', o.brand,
                            'badge', private.org_badge(o), 'allowed_origins', to_jsonb(o.allowed_origins),
                            'timezone', o.timezone);
$$;

-- A person as a roster shows them. No email, no external id.
create or replace function private.person_json(p public.profiles)
returns jsonb language sql immutable as $$
  select case when p.id is null then null else
         jsonb_build_object('id', p.id, 'name', p.display_name, 'username', p.username,
                            'avatar_url', p.avatar_url, 'country', p.country, 'kind', p.kind) end;
$$;

-- "am•••@gmail.com": enough for its owner to recognise, not enough to copy.
create or replace function private.mask_email(e text)
returns text language sql immutable as $$
  select left(split_part(e, '@', 1), case when char_length(split_part(e, '@', 1)) > 3 then 2 else 1 end)
         || '•••@' || split_part(e, '@', 2);
$$;

create or replace function private.topic(p_kind text, p_ref uuid)
returns text language sql stable security definer set search_path = public, extensions as $$
  select 'live:' || kind || ':' || topic from private.live_topics where kind = p_kind and ref = p_ref;
$$;

-- A tournament as an embed or a hosted page shows it.
create or replace function private.tournament_public_json(t public.tournaments)
returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare
  n     int := (select count(*) from participants where tournament_id = t.id and status = 'approved');
  taken int := private.seats_taken(t.id);
  is_full boolean := t.max_participants is not null and taken >= t.max_participants;
begin
  return jsonb_build_object(
    'id', t.id, 'slug', t.slug, 'title', t.title, 'description', t.description,
    'game', t.game, 'variant', t.variant, 'format', t.format, 'status', t.status,
    'starts_at', t.starts_at, 'started_at', t.started_at,
    'clock', jsonb_build_object('base_s', t.clock_base_s, 'inc_s', t.clock_increment_s),
    'rounds_count', t.rounds_count, 'arena_minutes', t.arena_minutes, 'tiebreaks', to_jsonb(t.tiebreaks),
    'language', t.language, 'identity_mode', t.identity_mode, 'invite_only', t.invite_only,
    'requires_code', t.requires_code,
    'entry', jsonb_build_object('count', n, 'cap', t.max_participants, 'full', is_full,
                                'open', t.status = 'registration' and not is_full),
    'games_watchable', t.games_watchable, 'participants_visible', t.participants_visible,
    'is_listed', t.is_listed, 'org_listed', t.org_listed, 'rated', t.rated,
    'autopilot', t.autopilot, 'autopilot_note', t.autopilot_note, 'series_id', t.series_id,
    -- The organisation's slug, so a platform's create reply can link the
    -- branded page (/o/{org}/{slug}) and print snippets without a second read.
    'org_slug', (select o.slug from organizations o where o.id = t.org_id),
    'rev', t.embed_rev);
end $$;

create or replace function private.org_by_slug(p_slug text)
returns public.organizations language sql stable security definer set search_path = public, extensions as $$
  select * from organizations where slug = lower(p_slug) and status = 'active';
$$;

-- The caller's confirmed address, or null: the only address claims ever use.
create or replace function private.confirmed_email(p_user uuid)
returns text language sql stable security definer set search_path = public, extensions as $$
  select lower(email) from auth.users where id = p_user and email_confirmed_at is not null;
$$;

revoke all on function private.origin_allowed(text[], text) from public, anon, authenticated;
revoke all on function private.origin_listed(text[], text) from public, anon, authenticated;
revoke all on function private.plain_path(text) from public, anon, authenticated;
revoke all on function private.org_badge(public.organizations) from public, anon, authenticated;
revoke all on function private.org_public_json(public.organizations) from public, anon, authenticated;
revoke all on function private.person_json(public.profiles) from public, anon, authenticated;
revoke all on function private.mask_email(text) from public, anon, authenticated;
revoke all on function private.topic(text, uuid) from public, anon, authenticated;
revoke all on function private.tournament_public_json(public.tournaments) from public, anon, authenticated;
revoke all on function private.org_by_slug(text) from public, anon, authenticated;
revoke all on function private.confirmed_email(uuid) from public, anon, authenticated;
revoke all on function private.hooks_on() from public, anon, authenticated;
revoke all on function private.plan_limit(public.org_plan, text) from public, anon, authenticated;

-- =============================================================================
-- Live feed and webhook events
-- =============================================================================

-- Broadcast on a private topic (C7). Realtime delivers it to subscribers the
-- policy on realtime.messages admits - anyone holding the topic - and the
-- server time rides along so clocks can be corrected.
create or replace function private.live_send(p_kind text, p_ref uuid, p_event text, p_payload jsonb)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  tp text := private.topic(p_kind, p_ref);
begin
  if tp is null then
    return;
  end if;
  perform realtime.send(p_payload || jsonb_build_object('server_now', now()), p_event, tp, true);
end $$;

-- The tournament feed's revision. Embeds debounce `t:` events and refetch the
-- bundle as ?rev=N, which the CDN collapses into one request per revision.
create or replace function private.bump_rev(p_tournament uuid)
returns bigint language sql security definer set search_path = public, extensions as $$
  update tournaments set embed_rev = embed_rev + 1 where id = p_tournament returning embed_rev;
$$;

-- Queue an event for an organisation's endpoints (C9). A no-op while
-- webhooks are switched off, except a test aimed at one endpoint (p_only).
create or replace function private.emit_org(p_org uuid, p_event text, p_data jsonb, p_only uuid default null)
returns int language plpgsql security definer set search_path = public, extensions as $$
declare
  n int;
begin
  if p_org is null or (p_only is null and not private.hooks_on()) then
    return 0;
  end if;
  insert into private.webhook_outbox (webhook_id, org_id, event, payload)
  select w.id, w.org_id, p_event,
         jsonb_build_object('type', p_event,
                            'timestamp', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
                            'data', p_data)
    from public.org_webhooks w
   where w.org_id = p_org
     and (case when p_only is not null then w.id = p_only
               else w.active and w.disabled_at is null
                    and (cardinality(w.events) = 0 or p_event = any (w.events)) end);
  get diagnostics n = row_count;
  return n;
end $$;

-- ...for a tournament: personal tournaments have no endpoints to tell.
create or replace function private.emit(p_tournament uuid, p_event text, p_data jsonb)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  o uuid;
begin
  if not private.hooks_on() then
    return;
  end if;
  select org_id into o from tournaments where id = p_tournament;
  if o is not null then
    perform private.emit_org(o, p_event, p_data);
  end if;
end $$;

create or replace function private.tournament_hook(t public.tournaments)
returns jsonb language sql immutable as $$
  select jsonb_build_object('tournament', jsonb_build_object(
           'id', t.id, 'slug', t.slug, 'title', t.title, 'status', t.status, 'starts_at', t.starts_at,
           'format', t.format, 'game', t.game, 'autopilot_note', t.autopilot_note, 'series_id', t.series_id));
$$;

-- A participant as a webhook carries them: member players with the id their
-- platform knows them by (A3, C9).
create or replace function private.participant_hook(p public.participants)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object(
           'tournament', (select jsonb_build_object('id', t.id, 'slug', t.slug) from tournaments t where t.id = p.tournament_id),
           'participant', jsonb_build_object(
             'id', p.id, 'status', p.status, 'joined_via', p.joined_via, 'profile_id', p.user_id,
             'kind', pr.kind, 'name', pr.display_name,
             'external_id', (select external_id from org_players where profile_id = p.user_id)))
    from profiles pr where pr.id = p.user_id;
$$;

create or replace function private.game_hook(g public.games)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object(
           'tournament', (select jsonb_build_object('id', t.id, 'slug', t.slug) from tournaments t where t.id = g.tournament_id),
           'game', jsonb_build_object(
             'id', g.id, 'round', (select number from rounds where id = g.round_id), 'board', g.board,
             'status', g.status, 'result', g.result, 'termination', g.termination,
             'white', (select jsonb_build_object('profile_id', g.white_id, 'external_id', op.external_id)
                         from (select 1) one left join org_players op on op.profile_id = g.white_id),
             'black', case when g.black_id is null then null else
                      (select jsonb_build_object('profile_id', g.black_id, 'external_id', op.external_id)
                         from (select 1) one left join org_players op on op.profile_id = g.black_id) end));
$$;

-- A game on the tournament feed: no position, no clocks - those go to the
-- game's own topic - and the players only if the organiser shows who entered.
create or replace function private.feed_game(gj jsonb, p_rev bigint)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object('id', gj -> 'id', 'round', (select number from rounds where id = (gj ->> 'round_id')::uuid),
                            'board', gj -> 'board', 'status', gj -> 'status', 'result', gj -> 'result', 'rev', p_rev)
         || case when t.participants_visible
                 then jsonb_build_object('white_id', gj -> 'white_id', 'black_id', gj -> 'black_id')
                 else '{}'::jsonb end
    from tournaments t where t.id = (gj ->> 'tournament_id')::uuid;
$$;

-- A game's state on its own topic, everything a board needs to redraw.
create or replace function private.game_state(gj jsonb)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'id', gj -> 'id', 'ply', gj -> 'ply', 'position', gj -> 'position', 'turn', gj -> 'turn',
    'last_move', gj -> 'last_move',
    'san', (select san from moves where game_id = (gj ->> 'id')::uuid and ply = (gj ->> 'ply')::int),
    'white_ms', gj -> 'white_ms', 'black_ms', gj -> 'black_ms', 'turn_started_at', gj -> 'turn_started_at',
    'draw_offer', gj -> 'draw_offer', 'status', gj -> 'status', 'result', gj -> 'result',
    'termination', gj -> 'termination', 'legal', gj -> 'legal');
$$;

revoke all on function private.live_send(text, uuid, text, jsonb) from public, anon, authenticated;
revoke all on function private.bump_rev(uuid) from public, anon, authenticated;
revoke all on function private.emit_org(uuid, text, jsonb, uuid) from public, anon, authenticated;
revoke all on function private.emit(uuid, text, jsonb) from public, anon, authenticated;
revoke all on function private.tournament_hook(public.tournaments) from public, anon, authenticated;
revoke all on function private.participant_hook(public.participants) from public, anon, authenticated;
revoke all on function private.game_hook(public.games) from public, anon, authenticated;
revoke all on function private.feed_game(jsonb, bigint) from public, anon, authenticated;
revoke all on function private.game_state(jsonb) from public, anon, authenticated;

-- =============================================================================
-- Organisation tournaments: the plan's ceiling, an active organisation
-- =============================================================================
-- Players per event by plan (community: 64). An event with no cap gets the
-- plan's; asking for more than the plan allows is refused rather than
-- quietly cut, so nobody discovers the limit on the day.
create or replace function private.guard_org_tournament()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  o   organizations;
  cap int;
begin
  if new.org_id is null then
    return new;
  end if;
  select * into o from organizations where id = new.org_id;
  if tg_op = 'INSERT' and o.status <> 'active' then
    raise exception 'this organisation is suspended' using errcode = 'check_violation';
  end if;
  cap := private.plan_limit(o.plan, 'players');
  if new.max_participants is null and cap < 4096 then
    new.max_participants := cap;
  elsif new.max_participants > cap
        and (tg_op = 'INSERT' or new.max_participants is distinct from old.max_participants) then
    raise exception 'the % plan allows % players per event', o.plan, cap using errcode = 'check_violation';
  end if;
  return new;
end $$;
revoke all on function private.guard_org_tournament() from public, anon, authenticated;

drop trigger if exists tournaments_org_guard on public.tournaments;
create trigger tournaments_org_guard before insert or update of max_participants on public.tournaments
  for each row execute function private.guard_org_tournament();

-- =============================================================================
-- Public reads
-- =============================================================================

-- Names for an event, members included (C4): what an embed or an unlisted
-- event's page needs and profiles_read does not give a visitor. Same rule as
-- get_results(): anyone who can open the event, unless the organiser hides
-- who has entered.
create or replace function public.get_people(p_tournament uuid)
returns table (id uuid, display_name text, username text, avatar_url text, country text, kind text)
language sql stable security definer set search_path = public, extensions as $$
  select pr.id, pr.display_name, pr.username, pr.avatar_url, pr.country, pr.kind
    from profiles pr
    join tournaments t on t.id = p_tournament
   where pr.id in (select user_id from participants where tournament_id = p_tournament and status = 'approved'
                   union
                   select white_id from games where tournament_id = p_tournament
                   union
                   select black_id from games where tournament_id = p_tournament and black_id is not null)
     and ((t.status <> 'draft' and t.participants_visible)
          or private.is_tournament_staff(p_tournament)
          or private.is_tournament_participant(p_tournament));
$$;

-- The tournament's broadcast topic: whoever may open the event (get_tournament's rule).
create or replace function public.get_live_topic(p_slug text)
returns text language sql stable security definer set search_path = public, extensions as $$
  select private.topic('t', t.id) from tournaments t
   where t.slug = p_slug
     and (t.status <> 'draft' or private.is_tournament_staff(t.id) or private.is_tournament_participant(t.id));
$$;

-- A game's topic: its players, the event's staff and entrants, or anyone when
-- the organiser lets people watch and shows who entered.
create or replace function public.get_game_topic(p_game uuid)
returns text language sql stable security definer set search_path = public, extensions as $$
  select private.topic('g', g.id) from games g join tournaments t on t.id = g.tournament_id
   where g.id = p_game
     and (auth.uid() in (g.white_id, g.black_id)
          or private.is_tournament_staff(t.id)
          or private.is_tournament_participant(t.id)
          or (t.games_watchable and t.participants_visible and t.status <> 'draft'));
$$;

-- Who may frame an embed (D3 /v1/embed/policy): the organisation's allowed
-- origins, found from whichever of tournament, organisation or game the page
-- is for. [] means anywhere; null means there is no such thing.
create or replace function public.get_embed_policy(p_tournament text default null, p_org text default null, p_game uuid default null)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  with target as (
    select t.org_id, true as found from tournaments t where p_tournament is not null and t.slug = p_tournament
    union all
    select o.id, true from organizations o where p_org is not null and o.slug = lower(p_org)
    union all
    select t.org_id, true from games g join tournaments t on t.id = g.tournament_id where p_game is not null and g.id = p_game
  )
  select case when not exists (select 1 from target) then null else
         coalesce((select to_jsonb(o.allowed_origins) from target x join organizations o on o.id = x.org_id limit 1),
                  '[]'::jsonb) end;
$$;

-- =============================================================================
-- Email invites (C5)
-- =============================================================================

-- Add people by address. All or nothing on seats: pending invites hold
-- places, so "only N places left" is said now, not on the day. It never reads
-- auth.users, so the answer for an address with an account and one without
-- is the same, to the byte: the organiser learns nothing about who has one.
-- Rows: [{email, name?, note?}]. `row` in `invalid` counts from 1.
create or replace function private.do_add_invites(t public.tournaments, p_rows jsonb, p_send boolean, p_by uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  plan     public.org_plan := coalesce((select o.plan from organizations o where o.id = t.org_id), 'community');
  r        jsonb;
  i        int := 0;
  e        text;
  st       text;
  seen     text[] := '{}';
  emails   text[] := '{}';
  names    text[] := '{}';
  notes    text[] := '{}';
  invalid  jsonb := '[]'::jsonb;
  already  int := 0;
  fresh    int;
  taken    int;
  left_now int;
begin
  if t.status not in ('draft', 'registration') then
    raise exception 'entries are closed' using errcode = 'check_violation';
  end if;
  if t.identity_mode = 'platform' then
    raise exception 'this tournament is for players signed in on your own site; enter them from your server'
      using errcode = 'check_violation';
  end if;
  if jsonb_typeof(p_rows) is distinct from 'array' or jsonb_array_length(p_rows) not between 1 and 500 then
    raise exception 'add between 1 and 500 people at a time' using errcode = 'invalid_parameter_value';
  end if;

  for r in select * from jsonb_array_elements(p_rows) loop
    i := i + 1;
    e := lower(btrim(r ->> 'email'));
    if e is null or char_length(e) not between 6 and 254 or e !~ '^[^@\s<>",;]+@[^@\s<>",;]+\.[^@\s<>",;]+$' then
      invalid := invalid || jsonb_build_object('row', i, 'reason', 'not an email address');
      continue;
    end if;
    if e = any (seen) then
      invalid := invalid || jsonb_build_object('row', i, 'reason', 'listed twice');
      continue;
    end if;
    seen := seen || e;
    select status into st from tournament_invites where tournament_id = t.id and email = e;
    -- Revoked or lapsed invites can be sent again; anything else stands.
    if found and st not in ('revoked', 'lapsed') then
      already := already + 1;
      continue;
    end if;
    emails := emails || e;
    names := names || nullif(left(btrim(coalesce(r ->> 'name', '')), 60), '');
    notes := notes || nullif(left(btrim(coalesce(r ->> 'note', '')), 500), '');
  end loop;
  fresh := cardinality(emails);

  if fresh > 0 then
    if t.max_participants is not null then
      taken := private.seats_taken(t.id);
      if taken + fresh > t.max_participants then
        raise exception 'only % places left', greatest(t.max_participants - taken, 0) using errcode = 'check_violation';
      end if;
    end if;
    if (select count(*) from tournament_invites where tournament_id = t.id and status not in ('revoked', 'lapsed')) + fresh > 4096 then
      raise exception 'a tournament can have at most 4096 invites' using errcode = 'check_violation';
    end if;
    perform private.throttle('invites:' || coalesce(t.org_id, t.owner_id), private.plan_limit(plan, 'invites_day'), 86400, fresh);

    -- A revoked or lapsed invite added again is the same invite back, and
    -- its mail history comes with it: re-adding is resend_invite by another
    -- door, so it follows resend's rules (at most three more, an hour
    -- apart) and counts as one. Resetting the counters here would let
    -- revoke-and-add mail one address as often as anyone likes. An invite
    -- that was never mailed is mailed as a new one; one that may not be
    -- mailed yet comes back pending, holding its seat, without an email.
    insert into tournament_invites (tournament_id, email, name, note, invited_by, send)
    select t.id, x.e, x.n, x.note, p_by, coalesce(p_send, true)
      from unnest(emails, names, notes) as x(e, n, note)
    on conflict (tournament_id, email) do update
      set status = 'pending', name = excluded.name, note = excluded.note, invited_by = excluded.invited_by,
          send_error = null, claimed_by = null, claimed_at = null, claim_seen_at = null, mail_lease_until = null,
          created_at = now(),
          send = excluded.send
                 and (not (tournament_invites.sent_at is not null or tournament_invites.resends > 0)
                      or (tournament_invites.resends < 3
                          and (tournament_invites.sent_at is null or tournament_invites.sent_at <= now() - interval '1 hour'))),
          sent_at = case when excluded.send
                          and (tournament_invites.sent_at is not null or tournament_invites.resends > 0)
                          and tournament_invites.resends < 3
                          and (tournament_invites.sent_at is null or tournament_invites.sent_at <= now() - interval '1 hour')
                         then null else tournament_invites.sent_at end,
          resends = case when excluded.send
                          and (tournament_invites.sent_at is not null or tournament_invites.resends > 0)
                          and tournament_invites.resends < 3
                          and (tournament_invites.sent_at is null or tournament_invites.sent_at <= now() - interval '1 hour')
                         then tournament_invites.resends + 1 else tournament_invites.resends end
      where tournament_invites.status in ('revoked', 'lapsed');
  end if;

  left_now := case when t.max_participants is null then null
                   else greatest(t.max_participants - private.seats_taken(t.id), 0) end;
  return jsonb_build_object('added', fresh, 'already', already, 'invalid', invalid, 'places_left', left_now);
end $$;
revoke all on function private.do_add_invites(public.tournaments, jsonb, boolean, uuid) from public, anon, authenticated;

create or replace function public.add_invites(p_tournament uuid, p_rows jsonb, p_send boolean default true)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  t tournaments;
begin
  select * into t from tournaments where id = p_tournament;
  if not found or not private.is_tournament_manager(t.id) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  return private.do_add_invites(t, p_rows, p_send, auth.uid());
end $$;

-- An invite as its organiser sees it: never the token, which is the invitee's.
create or replace function private.invite_json(i public.tournament_invites)
returns jsonb language sql immutable as $$
  select to_jsonb(i) - 'token' - 'mail_lease_until';
$$;
revoke all on function private.invite_json(public.tournament_invites) from public, anon, authenticated;

create or replace function public.revoke_invite(p_invite uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  i tournament_invites;
begin
  select * into i from tournament_invites where id = p_invite for update;
  if not found or not private.is_tournament_manager(i.tournament_id) then
    raise exception 'no such invite' using errcode = 'no_data_found';
  end if;
  if i.status <> 'pending' then
    raise exception 'only a pending invite can be revoked' using errcode = 'check_violation';
  end if;
  update tournament_invites set status = 'revoked', mail_lease_until = null where id = i.id returning * into i;
  return private.invite_json(i);
end $$;

-- Mail it again: three times per address at most, an hour apart, so an
-- invite list cannot be turned into a way of flooding someone's inbox. The
-- counters live on the row and survive revoking and adding the address again
-- (do_add_invites), and sys_mail_batch caps what one sender mails one address
-- in a day across all its events, which no revocation clears.
create or replace function public.resend_invite(p_invite uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  i tournament_invites;
begin
  select * into i from tournament_invites where id = p_invite for update;
  if not found or not private.is_tournament_manager(i.tournament_id) then
    raise exception 'no such invite' using errcode = 'no_data_found';
  end if;
  if i.status <> 'pending' then
    raise exception 'only a pending invite can be sent again' using errcode = 'check_violation';
  end if;
  if exists (select 1 from private.email_suppressions where email = i.email) then
    raise exception 'mail to this address bounced; check it and add it again' using errcode = 'check_violation';
  end if;
  if i.resends >= 3 then
    raise exception 'this invite has been sent again three times already' using errcode = 'check_violation';
  end if;
  if i.sent_at is not null and i.sent_at > now() - interval '1 hour' then
    raise exception 'it was sent less than an hour ago; try again later' using errcode = 'check_violation';
  end if;
  update tournament_invites
     set send = true, sent_at = null, send_error = null, mail_lease_until = null, resends = resends + 1
   where id = i.id
  returning * into i;
  return private.invite_json(i);
end $$;

-- Enter a user in every event that invited this address (C5). Accounts only:
-- the address must be one Auth confirmed, which only it can know, so this
-- takes the user and the address from its callers - the sign-in trigger and
-- the functions below that read them from auth.users - never from a client.
-- Idempotent, and safe against itself: `skip locked`, and an entry that
-- already exists is approved rather than duplicated. Returns how many it
-- claimed.
--
-- Staff invites are NOT claimed here, though C1 first said they would be:
-- joining a team is not like entering an event. A member can be handed the
-- organisation (transfer_org_ownership), and a member's account cannot be
-- deleted until they leave (org_members restricts it), so a team someone was
-- put in just by signing in would be a way to saddle anyone whose address is
-- known with an organisation they never chose. They join from the email:
-- accept_invite, with the token only that inbox has.
create or replace function private.claim_invites(p_user uuid, p_email text, p_only uuid default null)
returns int language plpgsql security definer set search_path = public, extensions as $$
declare
  inv tournament_invites;
  t   tournaments;
  n   int := 0;
begin
  if p_user is null or p_email is null
     or not exists (select 1 from profiles where id = p_user and kind = 'account') then
    return 0;
  end if;
  for inv in
    select i.* from tournament_invites i
      join tournaments tt on tt.id = i.tournament_id
     where i.email = lower(p_email) and i.status = 'pending'
       and (p_only is null or i.tournament_id = p_only)
       and tt.status in ('draft', 'registration') and tt.identity_mode in ('accounts', 'any')
     for update of i skip locked
  loop
    select * into t from tournaments where id = inv.tournament_id;
    insert into participants (tournament_id, user_id, status, rating_at_entry, joined_via, decided_at)
    select t.id, p_user, 'approved',
           case when t.game = 'chess' then p.chess_rating else p.checkers_rating end, 'email', now()
      from profiles p where p.id = p_user
    on conflict (tournament_id, user_id) do update
      set status = 'approved', joined_via = 'email', decided_at = now(), decided_by = null,
          rating_at_entry = excluded.rating_at_entry
      where participants.status <> 'approved';
    update tournament_invites set status = 'claimed', claimed_by = p_user, claimed_at = now(), mail_lease_until = null
     where id = inv.id;
    n := n + 1;
  end loop;
  return n;
end $$;
revoke all on function private.claim_invites(uuid, text, uuid) from public, anon, authenticated;

-- "When they join or log in they just see it" (A2): on sign-up with a
-- confirmed address (Google), on confirming the code, and on every later
-- sign-in. Named to sort after on_auth_user_created, so the profile exists
-- by the time this runs. It must never stand between someone and signing in:
-- anything that goes wrong is written to private.ops_log and swallowed.
create or replace function public.handle_verified_user()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  if new.email is null or new.email_confirmed_at is null then
    return new;
  end if;
  if tg_op = 'UPDATE'
     and new.email is not distinct from old.email
     and new.email_confirmed_at is not distinct from old.email_confirmed_at
     and new.last_sign_in_at is not distinct from old.last_sign_in_at then
    return new;
  end if;
  begin
    -- The common case is nobody invited them: one index probe and out.
    if exists (select 1 from tournament_invites where email = lower(new.email) and status = 'pending') then
      perform private.claim_invites(new.id, new.email);
    end if;
  exception when others then
    begin
      insert into private.ops_log (source, message, detail)
      values ('on_auth_user_verified', sqlerrm, jsonb_build_object('user', new.id, 'sqlstate', sqlstate));
    exception when others then
      null;
    end;
  end;
  return new;
end $$;
revoke all on function public.handle_verified_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_verified on auth.users;
create trigger on_auth_user_verified after insert or update of email, email_confirmed_at, last_sign_in_at on auth.users
  for each row execute function public.handle_verified_user();

-- The same for the signed-in caller, run once per page load (GET /v1/me), and
-- the claims they have not yet been told about - whether this call made them
-- or the sign-in trigger did - for "Yoursite entered you in X".
create or replace function public.claim_my_invites()
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  me  uuid := auth.uid();
  e   text := private.confirmed_email(auth.uid());
  res jsonb;
begin
  if me is null then
    raise exception 'sign in to do this' using errcode = '28000';
  end if;
  if e is not null then
    perform private.claim_invites(me, e);
  end if;
  with told as (
    update tournament_invites i set claim_seen_at = now()
     where i.claimed_by = me and i.status = 'claimed' and i.claim_seen_at is null
    returning i.tournament_id
  )
  select coalesce(jsonb_agg(jsonb_build_object('slug', t.slug, 'title', t.title, 'starts_at', t.starts_at,
                                               'org', (select jsonb_build_object('slug', o.slug, 'name', o.name)
                                                         from organizations o where o.id = t.org_id))
                            order by t.starts_at), '[]'::jsonb)
    into res
    from told join tournaments t on t.id = told.tournament_id;
  return res;
end $$;

-- For a banner: invites waiting for the caller's address, and the last
-- fortnight's claims. The tokens are the caller's own.
create or replace function public.my_invites()
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', i.id, 'token', i.token, 'status', i.status, 'created_at', i.created_at, 'claimed_at', i.claimed_at,
           'tournament', jsonb_build_object('slug', t.slug, 'title', t.title, 'starts_at', t.starts_at, 'status', t.status),
           'org', (select jsonb_build_object('slug', o.slug, 'name', o.name) from organizations o where o.id = t.org_id))
         order by i.created_at desc), '[]'::jsonb)
    from tournament_invites i join tournaments t on t.id = i.tournament_id
   where auth.uid() is not null
     and ((i.status = 'pending' and i.email = private.confirmed_email(auth.uid()))
          or (i.status = 'claimed' and i.claimed_by = auth.uid() and i.claimed_at > now() - interval '14 days'));
$$;

-- "I'm in" from the email, by a signed-in user whose confirmed address is the
-- one invited. For staff invites this is the only way in: the person asks,
-- with the token from their own inbox (claim_invites says why).
create or replace function public.accept_invite(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  me uuid := auth.uid();
  e  text := private.confirmed_email(auth.uid());
  i  tournament_invites;
  oi org_invites;
  t  tournaments;
begin
  if me is null then
    raise exception 'sign in to do this' using errcode = '28000';
  end if;
  if e is null then
    raise exception 'confirm your email address first' using errcode = '28000';
  end if;
  select * into i from tournament_invites where token = p_token;
  if found then
    if i.email <> e then
      raise exception 'this invitation was sent to another address' using errcode = '28000';
    end if;
    select * into t from tournaments where id = i.tournament_id;
    if i.status = 'pending' then
      if t.status not in ('draft', 'registration') then
        raise exception 'entries are closed' using errcode = 'check_violation';
      end if;
      if t.identity_mode = 'platform' then
        raise exception 'this tournament is for players signed in on the organiser''s own site' using errcode = 'check_violation';
      end if;
      perform private.claim_invites(me, e, t.id);
      select * into i from tournament_invites where id = i.id;
    end if;
    if i.status <> 'claimed' then
      raise exception 'this invitation was %', i.status using errcode = 'check_violation';
    end if;
    update tournament_invites set claim_seen_at = coalesce(claim_seen_at, now()) where id = i.id;
    return jsonb_build_object('kind', 'tournament', 'status', 'claimed',
                              'tournament', jsonb_build_object('slug', t.slug, 'title', t.title, 'starts_at', t.starts_at));
  end if;

  select * into oi from org_invites where token = p_token for update;
  if not found then
    raise exception 'no such invitation' using errcode = 'no_data_found';
  end if;
  if oi.email <> e then
    raise exception 'this invitation was sent to another address' using errcode = '28000';
  end if;
  if oi.status = 'pending' then
    insert into org_members (org_id, user_id, role, added_by) values (oi.org_id, me, oi.role, oi.invited_by)
    on conflict (org_id, user_id) do nothing;
    update org_invites set status = 'accepted', accepted_by = me, accepted_at = now() where id = oi.id
    returning * into oi;
  end if;
  if oi.status <> 'accepted' then
    raise exception 'this invitation was %', oi.status using errcode = 'check_violation';
  end if;
  return jsonb_build_object('kind', 'org', 'status', 'accepted',
                            'org', (select jsonb_build_object('slug', o.slug, 'name', o.name) from organizations o where o.id = oi.org_id));
end $$;

create or replace function public.decline_invite(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  e  text := private.confirmed_email(auth.uid());
  i  tournament_invites;
  oi org_invites;
begin
  if auth.uid() is null then
    raise exception 'sign in to do this' using errcode = '28000';
  end if;
  select * into i from tournament_invites where token = p_token for update;
  if found then
    if e is null or i.email <> e then
      raise exception 'this invitation was sent to another address' using errcode = '28000';
    end if;
    if i.status = 'claimed' then
      raise exception 'you are already in; withdraw from the tournament page' using errcode = 'check_violation';
    end if;
    if i.status = 'pending' then
      update tournament_invites set status = 'declined', mail_lease_until = null where id = i.id;
    end if;
    return jsonb_build_object('kind', 'tournament', 'status', 'declined');
  end if;
  select * into oi from org_invites where token = p_token for update;
  if not found then
    raise exception 'no such invitation' using errcode = 'no_data_found';
  end if;
  if e is null or oi.email <> e then
    raise exception 'this invitation was sent to another address' using errcode = '28000';
  end if;
  if oi.status = 'pending' then
    update org_invites set status = 'declined' where id = oi.id;
  end if;
  return jsonb_build_object('kind', 'org', 'status', 'declined');
end $$;

-- What the invite page shows before anyone signs in: the event, who runs it,
-- and the address masked - enough to say "send my code to am•••@gmail.com",
-- not enough to learn the address from a forwarded link. The first look is
-- noted for the organiser ("Link opened"). null when there is no such token.
create or replace function public.get_invite_preview(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  i  tournament_invites;
  oi org_invites;
  t  tournaments;
  o  organizations;
begin
  select * into i from tournament_invites where token = p_token;
  if found then
    if i.opened_at is null then
      update tournament_invites set opened_at = now() where id = i.id;
    end if;
    select * into t from tournaments where id = i.tournament_id;
    select * into o from organizations where id = t.org_id;
    return jsonb_build_object(
      'kind', 'tournament', 'status', i.status, 'email_masked', private.mask_email(i.email), 'name', i.name,
      'tournament', jsonb_build_object('slug', t.slug, 'title', t.title, 'starts_at', t.starts_at, 'status', t.status,
                                       'game', t.game, 'format', t.format, 'language', t.language,
                                       'clock', jsonb_build_object('base_s', t.clock_base_s, 'inc_s', t.clock_increment_s)),
      'org', case when o.id is null then null else private.org_public_json(o) end);
  end if;
  select * into oi from org_invites where token = p_token;
  if found then
    select * into o from organizations where id = oi.org_id;
    return jsonb_build_object('kind', 'org', 'status', oi.status, 'role', oi.role,
                              'email_masked', private.mask_email(oi.email), 'org', private.org_public_json(o));
  end if;
  return null;
end $$;

-- =============================================================================
-- Organisations (C1)
-- =============================================================================

-- The organisation and its owner row, in one transaction: there is never an
-- organisation nobody owns. A taken slug is a unique violation (409), and the
-- API retries with a numeric suffix.
create or replace function public.create_organization(
  p_slug     text,
  p_name     text,
  p_website  text default null,
  p_brand    jsonb default '{}'::jsonb,
  p_origins  text[] default '{}',
  p_timezone text default 'Africa/Douala'
)
returns public.organizations
language plpgsql security definer set search_path = public, extensions as $$
declare
  me uuid := auth.uid();
  o  organizations;
begin
  if me is null or not exists (select 1 from profiles where id = me and kind = 'account') then
    raise exception 'sign in to do this' using errcode = '28000';
  end if;
  if (select count(*) from org_members where user_id = me and role = 'owner') >= 10 then
    raise exception 'you own 10 organisations, which is the most for now' using errcode = 'check_violation';
  end if;
  insert into organizations (slug, name, website, brand, allowed_origins, timezone, created_by)
  values (lower(btrim(p_slug)), btrim(p_name), nullif(btrim(p_website), ''), coalesce(p_brand, '{}'::jsonb),
          coalesce(p_origins, '{}'), coalesce(nullif(btrim(p_timezone), ''), 'Africa/Douala'), me)
  returning * into o;
  insert into org_members (org_id, user_id, role, added_by) values (o.id, me, 'owner', me);
  return o;
end $$;

-- Roles change by the owner's word only: an admin who could promote could
-- make a second owner in all but name. Ownership itself moves by transfer.
create or replace function public.set_org_member_role(p_org uuid, p_user uuid, p_role text)
returns public.org_members
language plpgsql security definer set search_path = public, extensions as $$
declare
  m org_members;
begin
  select * into m from org_members where org_id = p_org and user_id = p_user for update;
  if not found or private.org_role(p_org) is null then
    raise exception 'no such member' using errcode = 'no_data_found';
  end if;
  if private.org_role(p_org) <> 'owner' then
    raise exception 'only the owner changes roles' using errcode = 'insufficient_privilege';
  end if;
  if p_role not in ('admin', 'staff') then
    raise exception 'a member is an admin or staff; ownership moves by transfer' using errcode = 'invalid_parameter_value';
  end if;
  if m.role = 'owner' then
    raise exception 'the owner''s role changes only by transferring ownership' using errcode = 'check_violation';
  end if;
  update org_members set role = p_role where org_id = p_org and user_id = p_user returning * into m;
  return m;
end $$;

-- The owner removes anyone else; an admin removes staff.
create or replace function public.remove_org_member(p_org uuid, p_user uuid)
returns void
language plpgsql security definer set search_path = public, extensions as $$
declare
  mine   text := private.org_role(p_org);
  theirs text;
begin
  select role into theirs from org_members where org_id = p_org and user_id = p_user;
  if mine is null or theirs is null then
    raise exception 'no such member' using errcode = 'no_data_found';
  end if;
  if p_user = auth.uid() then
    raise exception 'use leave to leave' using errcode = 'check_violation';
  end if;
  if theirs = 'owner' or not (mine = 'owner' or (mine = 'admin' and theirs = 'staff')) then
    raise exception 'you cannot remove this member' using errcode = 'insufficient_privilege';
  end if;
  delete from org_members where org_id = p_org and user_id = p_user;
end $$;

create or replace function public.leave_org(p_org uuid)
returns void
language plpgsql security definer set search_path = public, extensions as $$
declare
  mine text := private.org_role(p_org);
begin
  if mine is null then
    raise exception 'no such organisation' using errcode = 'no_data_found';
  end if;
  if mine = 'owner' then
    raise exception 'transfer ownership before leaving' using errcode = 'check_violation';
  end if;
  delete from org_members where org_id = p_org and user_id = auth.uid();
end $$;

-- The owner hands over to another member and stays on as an admin. Old owner
-- first, so the one-owner index never sees two. Members are only ever people
-- who accepted (create_organization, accept_invite), and the new owner is held
-- to the same ten organisations create_organization allows, so nobody can be
-- made to own more than they could have started.
create or replace function public.transfer_org_ownership(p_org uuid, p_user uuid)
returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if private.org_role(p_org) is distinct from 'owner' then
    raise exception 'only the owner can transfer ownership' using errcode = 'insufficient_privilege';
  end if;
  if p_user = auth.uid() or not exists (select 1 from org_members where org_id = p_org and user_id = p_user) then
    raise exception 'ownership goes to another member of the organisation' using errcode = 'check_violation';
  end if;
  if (select count(*) from org_members where user_id = p_user and role = 'owner') >= 10 then
    raise exception 'they already own 10 organisations, which is the most for now' using errcode = 'check_violation';
  end if;
  update org_members set role = 'admin' where org_id = p_org and user_id = auth.uid();
  update org_members set role = 'owner' where org_id = p_org and user_id = p_user;
end $$;

-- Staff by email. Owners invite admins and staff, admins invite staff. The
-- reply is the same whether or not the address has an account; they become a
-- member when they accept from the email (accept_invite) - never just by
-- signing in (claim_invites says why).
create or replace function public.invite_org_member(p_org uuid, p_email text, p_role text default 'staff')
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  mine text := private.org_role(p_org);
  o    organizations;
  e    text := lower(btrim(p_email));
  inv  org_invites;
begin
  if mine is null or mine = 'staff' then
    raise exception 'no such organisation' using errcode = 'no_data_found';
  end if;
  if p_role not in ('admin', 'staff') then
    raise exception 'invite an admin or staff' using errcode = 'invalid_parameter_value';
  end if;
  if p_role = 'admin' and mine <> 'owner' then
    raise exception 'only the owner invites admins' using errcode = 'insufficient_privilege';
  end if;
  select * into o from organizations where id = p_org;
  select * into inv from org_invites where org_id = p_org and email = e and status = 'pending' for update;
  if not found then
    if (select count(*) from org_members where org_id = p_org)
       + (select count(*) from org_invites where org_id = p_org and status = 'pending')
       >= private.plan_limit(o.plan, 'members') then
      raise exception 'the % plan allows % people in the team', o.plan, private.plan_limit(o.plan, 'members')
        using errcode = 'check_violation';
    end if;
    perform private.throttle('org-invites:' || p_org, 100, 86400);
    insert into org_invites (org_id, email, role, invited_by) values (p_org, e, p_role, auth.uid())
    returning * into inv;
  else
    update org_invites set role = p_role where id = inv.id returning * into inv;
  end if;
  insert into private.mail_outbox (kind, to_email, org_id, data)
  values ('org-invite', e, p_org,
          jsonb_build_object('token', inv.token, 'role', inv.role, 'org', jsonb_build_object('slug', o.slug, 'name', o.name),
                             'invited_by', (select display_name from profiles where id = auth.uid())));
  return to_jsonb(inv) - 'token';
end $$;

-- Withdraw a staff invitation nobody has accepted. Now that joining takes a
-- yes, an invitation can wait forever - to a mistyped address, or someone who
-- never answers - holding one of the plan's team seats; this gives it back.
-- The same rule as inviting: owners withdraw any, admins staff invitations.
create or replace function public.revoke_org_invite(p_invite uuid)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare
  oi   org_invites;
  mine text;
begin
  select * into oi from org_invites where id = p_invite for update;
  if found then
    mine := private.org_role(oi.org_id);
  end if;
  if not found or mine is null or mine = 'staff' then
    raise exception 'no such invitation' using errcode = 'no_data_found';
  end if;
  if oi.role = 'admin' and mine <> 'owner' then
    raise exception 'only the owner withdraws an invitation to be an admin' using errcode = 'insufficient_privilege';
  end if;
  if oi.status <> 'pending' then
    raise exception 'only a pending invitation can be withdrawn' using errcode = 'check_violation';
  end if;
  update org_invites set status = 'revoked' where id = oi.id returning * into oi;
  return to_jsonb(oi) - 'token';
end $$;

-- The organisation's public face, for embeds and hosted pages. null when
-- there is none, or it is suspended.
create or replace function public.get_org_public(p_slug text)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select private.org_public_json(o) from organizations o where o.slug = lower(p_slug) and o.status = 'active';
$$;

-- What is on: events listed on the organisation's schedule that are live or
-- taking entries, and its active series with their current instance.
create or replace function public.get_org_schedule(p_slug text)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'org', private.org_public_json(o),
    'tournaments', coalesce((select jsonb_agg(private.tournament_public_json(t)
                                              || jsonb_build_object('series_slug', s.slug)
                                              order by (t.status = 'live') desc, t.starts_at)
                               from tournaments t left join tournament_series s on s.id = t.series_id
                              where t.org_id = o.id and t.org_listed and t.status in ('registration', 'live')), '[]'::jsonb),
    'series', coalesce((select jsonb_agg(jsonb_build_object(
                                 'slug', s.slug, 'title', s.title, 'weekday', s.weekday, 'local_time', s.local_time,
                                 'timezone', s.timezone,
                                 'current', (select jsonb_build_object('slug', t.slug, 'status', t.status, 'starts_at', t.starts_at)
                                               from tournaments t
                                              where t.series_id = s.id and t.status in ('registration', 'live')
                                              order by (t.status = 'live') desc, t.starts_at limit 1))
                               order by s.weekday, s.local_time)
                          from tournament_series s
                         where s.org_id = o.id and s.active and s.stopped_at is null), '[]'::jsonb))
    from organizations o where o.slug = lower(p_slug) and o.status = 'active';
$$;

-- Block or unblock one of the platform's own players (D1 .../players/{id}/block):
-- owners and admins. A block ends their sessions and tokens at once and takes
-- them out of events that have not started; results already played stay.
-- Accounts are not the organisation's to block - remove them from an event.
create or replace function public.block_org_player(p_org uuid, p_profile uuid, p_blocked boolean default true)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  op org_players;
begin
  if not private.is_org_admin(p_org) then
    raise exception 'no such organisation' using errcode = 'no_data_found';
  end if;
  select * into op from org_players where org_id = p_org and profile_id = p_profile for update;
  if not found then
    raise exception 'only your platform''s own players can be blocked; remove an account from an event instead'
      using errcode = 'no_data_found';
  end if;
  update org_players set blocked_at = case when p_blocked then coalesce(blocked_at, now()) end
   where profile_id = p_profile returning * into op;
  if p_blocked then
    delete from private.embed_sessions where profile_id = p_profile;
    delete from private.player_tokens where profile_id = p_profile;
    delete from arena_queue where user_id = p_profile;
    update participants p set status = 'withdrawn'
      from tournaments t
     where t.id = p.tournament_id and t.org_id = p_org and t.status in ('draft', 'registration')
       and p.user_id = p_profile and p.status in ('pending', 'approved');
  end if;
  return jsonb_build_object('profile_id', op.profile_id, 'external_id', op.external_id, 'blocked_at', op.blocked_at);
end $$;

-- What the plan allows and what is used (D1 /v1/orgs/{org}/usage), so the
-- limits are written once - in plan_limit() - and Studio only displays them.
create or replace function public.get_org_usage(p_org uuid)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'plan', o.plan, 'badge', private.org_badge(o),
    'limits', jsonb_build_object('players', private.plan_limit(o.plan, 'players'),
                                 'members', private.plan_limit(o.plan, 'members'),
                                 'keys', private.plan_limit(o.plan, 'keys'),
                                 'webhooks', private.plan_limit(o.plan, 'webhooks'),
                                 'invites_day', private.plan_limit(o.plan, 'invites_day'),
                                 'player_tokens_min', private.plan_limit(o.plan, 'player_tokens_min')),
    'used', jsonb_build_object(
      'members', (select count(*) from org_members where org_id = o.id)
                 + (select count(*) from org_invites where org_id = o.id and status = 'pending'),
      'keys', (select count(*) from org_keys where org_id = o.id and revoked_at is null),
      'webhooks', (select count(*) from org_webhooks where org_id = o.id),
      'invites_today', coalesce((select n from private.hits
                                  where bucket = 'invites:' || o.id
                                    and window_start = to_timestamp(floor(extract(epoch from now()) / 86400) * 86400)), 0),
      'players_30d', (select count(distinct p.user_id) from participants p join tournaments t on t.id = p.tournament_id
                       where t.org_id = o.id and p.status = 'approved' and t.starts_at > now() - interval '30 days'),
      'games_30d', (select count(*) from games g join tournaments t on t.id = g.tournament_id
                     where t.org_id = o.id and g.status = 'finished' and g.black_id is not null
                       and g.finished_at > now() - interval '30 days'),
      'live', (select count(*) from tournaments t where t.org_id = o.id and t.status = 'live'),
      'upcoming', (select count(*) from tournaments t where t.org_id = o.id and t.status = 'registration')))
  from organizations o where o.id = p_org and private.org_role(o.id) is not null;
$$;

-- =============================================================================
-- Org keys (C1, B)
-- =============================================================================
create or replace function public.create_org_key(p_org uuid, p_name text, p_scopes text[] default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  o   organizations;
  raw text := 'ochs_' || encode(extensions.gen_random_bytes(24), 'hex');
  k   org_keys;
begin
  if not private.is_org_admin(p_org) then
    raise exception 'no such organisation' using errcode = 'no_data_found';
  end if;
  select * into o from organizations where id = p_org;
  if (select count(*) from org_keys where org_id = p_org and revoked_at is null) >= private.plan_limit(o.plan, 'keys') then
    raise exception 'the % plan allows % live keys; revoke one first', o.plan, private.plan_limit(o.plan, 'keys')
      using errcode = 'check_violation';
  end if;
  insert into org_keys (org_id, name, prefix, hash, scopes, created_by)
  values (p_org, btrim(p_name), left(raw, 13), encode(extensions.digest(raw, 'sha256'), 'hex'),
          coalesce(p_scopes, array['players', 'tournaments', 'invites', 'read']), auth.uid())
  returning * into k;
  return jsonb_build_object('id', k.id, 'name', k.name, 'prefix', k.prefix, 'scopes', to_jsonb(k.scopes),
                            'created_at', k.created_at, 'key', raw);
end $$;

create or replace function public.revoke_org_key(p_key uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  update org_keys set revoked_at = coalesce(revoked_at, now())
   where id = p_key and private.is_org_admin(org_id);
  if not found then
    raise exception 'no such key' using errcode = 'no_data_found';
  end if;
end $$;

-- =============================================================================
-- Series (C3)
-- =============================================================================

-- A tournament for an organisation from a JSON object of tournament fields:
-- org_call's create and every series instance. Unknown keys are ignored, and
-- the columns no client may set (owner, status, the system's notes) are not
-- read from it. Organisation events default to unlisted in the public
-- directory and unrated (A9, F2), unless the fields say otherwise.
create or replace function private.insert_org_tournament(
  o        public.organizations,
  p_owner  uuid,
  f        jsonb,
  p_series uuid default null,
  p_status public.tournament_status default 'draft'
)
returns public.tournaments language plpgsql security definer set search_path = public, extensions as $$
declare
  r tournaments := jsonb_populate_record(null::public.tournaments, coalesce(f, '{}'::jsonb));
  t tournaments;
begin
  insert into tournaments (owner_id, org_id, series_id, status, slug, title, description, game, variant, format,
                           clock_base_s, clock_increment_s, starts_at, rounds_count, arena_minutes, tiebreaks,
                           max_participants, is_listed, participants_visible, games_watchable, requires_code,
                           auto_approve, identity_mode, invite_only, org_listed, rated, autopilot, min_players,
                           short_field, postpone_min, max_postpones, round_break_s, language)
  values (p_owner, o.id, p_series, p_status, nullif(r.slug, ''), r.title, r.description, r.game,
          coalesce(r.variant, case when r.game = 'chess' then 'standard' else 'international' end::public.game_variant),
          r.format, r.clock_base_s, coalesce(r.clock_increment_s, 0), r.starts_at, r.rounds_count, r.arena_minutes,
          coalesce(r.tiebreaks, array['buchholz', 'sonneborn_berger']), r.max_participants,
          coalesce(r.is_listed, false), coalesce(r.participants_visible, true), coalesce(r.games_watchable, true),
          coalesce(r.requires_code, false), coalesce(r.auto_approve, true), coalesce(r.identity_mode, 'accounts'),
          coalesce(r.invite_only, false), coalesce(r.org_listed, true), coalesce(r.rated, false),
          coalesce(r.autopilot, false), coalesce(r.min_players, 2), coalesce(r.short_field, 'postpone'),
          coalesce(r.postpone_min, 15), coalesce(r.max_postpones, 4), coalesce(r.round_break_s, 60),
          coalesce(r.language, 'en'))
  returning * into t;
  if f ? 'entry_code' and f ->> 'entry_code' is not null then
    update tournament_secrets set entry_code = upper(btrim(f ->> 'entry_code')) where tournament_id = t.id;
  end if;
  return t;
end $$;
revoke all on function private.insert_org_tournament(public.organizations, uuid, jsonb, uuid, public.tournament_status) from public, anon, authenticated;

-- The next instance, if the series has none waiting: entries open, autopilot
-- on, starting on the next of its weekday at its local time in its zone, past
-- any skipped dates and after the last instance. Created as the series'
-- maker's event while they are still in the organisation, else its owner's.
-- Called by the autopilot tick and when an instance starts. Returns null when
-- there was nothing to do.
create or replace function private.series_next(p_series uuid)
returns public.tournaments language plpgsql security definer set search_path = public, extensions as $$
declare
  s     tournament_series;
  o     organizations;
  prev_at timestamptz;
  d       date;
  next_at timestamptz;
  maker   uuid;
  t       tournaments;
begin
  select * into s from tournament_series where id = p_series for update;
  if not found or not s.active or s.stopped_at is not null then
    return null;
  end if;
  if exists (select 1 from tournaments where series_id = s.id and status in ('draft', 'registration')) then
    return null;
  end if;
  select * into o from organizations where id = s.org_id;
  if o.status <> 'active' then
    return null;
  end if;
  select max(starts_at) into prev_at from tournaments where series_id = s.id;
  for i in 0..62 loop
    d := (now() at time zone s.timezone)::date + i;
    continue when extract(dow from d) <> s.weekday or d = any (s.skip_dates);
    next_at := (d + s.local_time) at time zone s.timezone;
    exit when next_at > now() and (prev_at is null or next_at > prev_at);
  end loop;
  if next_at is null or next_at <= now() or (prev_at is not null and next_at <= prev_at) then
    return null;
  end if;
  select m.user_id into maker from org_members m
   where m.org_id = s.org_id and (m.user_id = s.created_by or m.role = 'owner')
   order by (m.user_id = s.created_by) desc limit 1;
  t := private.insert_org_tournament(
         o, maker,
         s.template || jsonb_build_object('title', coalesce(s.template ->> 'title', s.title),
                                          'starts_at', next_at, 'autopilot', true, 'slug', null),
         s.id, 'registration');
  return t;
end $$;
revoke all on function private.series_next(uuid) from public, anon, authenticated;

-- series_next for callers that must not fail because of it: an instance
-- starting (on_tournament_update) and the autopilot (sys-series). Making the
-- next instance is a courtesy to the embed; it must never stop this one from
-- going live. A template the plan no longer allows (a downgrade by hand, say)
-- would otherwise roll the start back and leave the autopilot retrying it
-- every tick in silence. The failure is written on the series (last_error,
-- retry_at: series_due skips it for five minutes) and in private.ops_log.
create or replace function private.series_next_safe(p_series uuid, p_source text)
returns public.tournaments language plpgsql security definer set search_path = public, extensions as $$
declare
  t tournaments;
begin
  begin
    t := private.series_next(p_series);
  exception when others then
    update tournament_series set last_error = left(sqlerrm, 300), retry_at = now() + interval '5 minutes'
     where id = p_series;
    insert into private.ops_log (source, message, detail)
    values (p_source, sqlerrm, jsonb_build_object('series', p_series, 'sqlstate', sqlstate));
    return null;
  end;
  update tournament_series set last_error = null, retry_at = null
   where id = p_series and (last_error is not null or retry_at is not null);
  return t;
end $$;
revoke all on function private.series_next_safe(uuid, text) from public, anon, authenticated;

-- Whether series_next could make an instance from this template: a trial
-- insert, undone. update_series runs it, so the organiser hears "the
-- community plan allows 64 players per event" when they save the template,
-- not on the day the next instance is due.
create or replace function private.series_template_check(s public.tournament_series)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  o     organizations;
  maker uuid;
begin
  select * into o from organizations where id = s.org_id;
  select m.user_id into maker from org_members m
   where m.org_id = s.org_id and (m.user_id = s.created_by or m.role = 'owner')
   order by (m.user_id = s.created_by) desc limit 1;
  begin
    perform private.insert_org_tournament(
              o, maker,
              s.template || jsonb_build_object('title', coalesce(s.template ->> 'title', s.title),
                                               'starts_at', now() + interval '7 days', 'autopilot', true, 'slug', null),
              s.id, 'registration');
    raise exception 'trial insert' using errcode = 'OCTRY';
  exception when sqlstate 'OCTRY' then
    null;  -- it would work; the trial row is gone with the savepoint
  end;
end $$;
revoke all on function private.series_template_check(public.tournament_series) from public, anon, authenticated;

create or replace function private.series_manageable(s public.tournament_series)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select private.is_org_admin(s.org_id) or (s.created_by = auth.uid() and private.org_role(s.org_id) is not null);
$$;
revoke all on function private.series_manageable(public.tournament_series) from public, anon, authenticated;

-- A weekly series and its first instance. Anyone in the organisation may
-- start one (staff create events); its maker and the admins run it.
create or replace function public.create_series(
  p_org        uuid,
  p_slug       text,
  p_title      text,
  p_template   jsonb,
  p_weekday    int,
  p_local_time time,
  p_timezone   text default null
)
returns public.tournament_series
language plpgsql security definer set search_path = public, extensions as $$
declare
  o organizations;
  s tournament_series;
begin
  if private.org_role(p_org) is null then
    raise exception 'no such organisation' using errcode = 'no_data_found';
  end if;
  select * into o from organizations where id = p_org;
  if not exists (select 1 from pg_timezone_names where name = coalesce(p_timezone, o.timezone)) then
    raise exception 'unknown time zone' using errcode = 'check_violation';
  end if;
  insert into tournament_series (org_id, slug, title, template, weekday, local_time, timezone, created_by)
  values (p_org, lower(btrim(p_slug)), btrim(p_title), coalesce(p_template, '{}'::jsonb), p_weekday, p_local_time,
          coalesce(p_timezone, o.timezone), auth.uid())
  returning * into s;
  perform private.series_next(s.id);
  return s;
end $$;

-- Changes to title, template, weekday, local_time, timezone. They shape the
-- next instance made; an instance already waiting keeps what it was made with.
create or replace function public.update_series(p_series uuid, p_changes jsonb)
returns public.tournament_series
language plpgsql security definer set search_path = public, extensions as $$
declare
  s tournament_series;
  c jsonb := coalesce(p_changes, '{}'::jsonb);
begin
  select * into s from tournament_series where id = p_series for update;
  if not found or not private.series_manageable(s) then
    raise exception 'no such series' using errcode = 'no_data_found';
  end if;
  if c ? 'timezone' and not exists (select 1 from pg_timezone_names where name = c ->> 'timezone') then
    raise exception 'unknown time zone' using errcode = 'check_violation';
  end if;
  update tournament_series set
    title      = case when c ? 'title' then btrim(c ->> 'title') else title end,
    template   = case when c ? 'template' then c -> 'template' else template end,
    weekday    = case when c ? 'weekday' then (c ->> 'weekday')::int else weekday end,
    local_time = case when c ? 'local_time' then (c ->> 'local_time')::time else local_time end,
    timezone   = case when c ? 'timezone' then c ->> 'timezone' else timezone end,
    updated_at = now()
  where id = s.id
  returning * into s;
  -- A template that could not make an instance is refused now (the trial
  -- raises, and this whole change rolls back). One that can clears an
  -- earlier failure, so the next tick tries again at once.
  if c ? 'template' or c ? 'title' then
    perform private.series_template_check(s);
    update tournament_series set last_error = null, retry_at = null where id = s.id returning * into s;
  end if;
  return s;
end $$;

-- Paused series make no new instances until resumed.
create or replace function public.pause_series(p_series uuid, p_paused boolean default true)
returns public.tournament_series
language plpgsql security definer set search_path = public, extensions as $$
declare
  s tournament_series;
begin
  select * into s from tournament_series where id = p_series for update;
  if not found or not private.series_manageable(s) then
    raise exception 'no such series' using errcode = 'no_data_found';
  end if;
  if s.stopped_at is not null then
    raise exception 'this series has stopped' using errcode = 'check_violation';
  end if;
  update tournament_series set active = not p_paused, updated_at = now(), last_error = null, retry_at = null
   where id = s.id returning * into s;
  -- Resuming makes the next instance now, and unlike the autopilot's call it
  -- may fail: the organiser pressing Resume is the one person who can act on
  -- "the community plan allows 64 players per event", and the series stays
  -- paused until the template allows it.
  if s.active then
    perform private.series_next(s.id);
  end if;
  return s;
end $$;

-- Skip (or un-skip) one date: a holiday. An instance already made for that
-- date is the organiser's to archive; this only steers the next one.
create or replace function public.skip_series_date(p_series uuid, p_date date, p_skip boolean default true)
returns public.tournament_series
language plpgsql security definer set search_path = public, extensions as $$
declare
  s tournament_series;
begin
  select * into s from tournament_series where id = p_series for update;
  if not found or not private.series_manageable(s) then
    raise exception 'no such series' using errcode = 'no_data_found';
  end if;
  update tournament_series
     set skip_dates = case when p_skip then array(select distinct x from unnest(skip_dates || p_date) x order by x)
                           else array_remove(skip_dates, p_date) end,
         updated_at = now()
   where id = s.id
  returning * into s;
  return s;
end $$;

-- Stopped for good. Instances already made stay, to be run or archived.
create or replace function public.stop_series(p_series uuid)
returns public.tournament_series
language plpgsql security definer set search_path = public, extensions as $$
declare
  s tournament_series;
begin
  select * into s from tournament_series where id = p_series for update;
  if not found or not private.series_manageable(s) then
    raise exception 'no such series' using errcode = 'no_data_found';
  end if;
  update tournament_series set active = false, stopped_at = coalesce(stopped_at, now()), updated_at = now()
   where id = s.id returning * into s;
  return s;
end $$;

-- The instance an embed of the series shows: the live one, else the next.
create or replace function public.get_series_current(p_org text, p_series_slug text)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object('slug', t.slug, 'status', t.status, 'starts_at', t.starts_at, 'title', t.title,
                            'series', jsonb_build_object('slug', s.slug, 'title', s.title))
    from organizations o
    join tournament_series s on s.org_id = o.id and s.slug = lower(p_series_slug)
    join tournaments t on t.series_id = s.id and t.status in ('registration', 'live')
   where o.slug = lower(p_org) and o.status = 'active'
   order by (t.status = 'live') desc, t.starts_at
   limit 1;
$$;

-- =============================================================================
-- Embed sessions (C6)
-- =============================================================================

-- A new session. The raw `oche_` value is in this reply and nowhere else.
create or replace function private.mint_session(p_kind text, p_org uuid, p_profile uuid, p_tournament uuid, p_origin text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  raw text := 'oche_' || encode(extensions.gen_random_bytes(32), 'hex');
  s   private.embed_sessions;
  p   profiles;
begin
  insert into private.embed_sessions (hash, kind, org_id, profile_id, tournament_id, parent_origin, expires_at)
  values (encode(extensions.digest(raw, 'sha256'), 'hex'), p_kind, p_org, p_profile, p_tournament, p_origin,
          now() + case when p_kind = 'member' then interval '12 hours' else interval '7 days' end)
  returning * into s;
  select * into p from profiles where id = p_profile;
  return jsonb_build_object('session', raw, 'session_id', s.id, 'expires_at', s.expires_at,
                            'player', jsonb_build_object('id', p.id, 'name', p.display_name, 'kind', s.kind));
end $$;
revoke all on function private.mint_session(text, uuid, uuid, uuid, text) from public, anon, authenticated;

-- A session by its hash, or a refusal. OC401: the API answers 401, which an
-- embed takes as "sign in again" (need-identity{expired}).
create or replace function private.session_by_hash(p_hash text)
returns private.embed_sessions language plpgsql security definer set search_path = public, extensions as $$
declare
  s private.embed_sessions;
begin
  select * into s from private.embed_sessions where hash = p_hash;
  if not found or s.revoked_at is not null or s.expires_at <= now() then
    raise exception 'your session has ended; sign in again' using errcode = 'OC401';
  end if;
  if s.org_id is not null and not exists (select 1 from organizations where id = s.org_id and status = 'active') then
    raise exception 'this organiser''s events are paused' using errcode = 'OC401';
  end if;
  if s.kind = 'member' then
    if not exists (select 1 from org_players where profile_id = s.profile_id) then
      raise exception 'your session has ended; sign in again' using errcode = 'OC401';
    end if;
    if exists (select 1 from org_players where profile_id = s.profile_id and blocked_at is not null) then
      raise exception 'you cannot enter this organiser''s events' using errcode = '28000';
    end if;
  end if;
  -- At most once a minute: an embed polling every few seconds would
  -- otherwise rewrite its row on every request.
  if s.last_used_at is null or s.last_used_at < now() - interval '1 minute' then
    update private.embed_sessions set last_used_at = now() where id = s.id;
  end if;
  return s;
end $$;
revoke all on function private.session_by_hash(text) from public, anon, authenticated;

-- Whether a session may act on a tournament (C6). Outside its organisation or
-- its tournament the event "does not exist" - the same answer as a wrong slug,
-- so a session cannot be used to discover another organisation's events.
-- Then identity: members only where platform users play, accounts only where
-- accounts do.
create or replace function private.session_may_touch(p_session uuid, p_tournament uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  s  private.embed_sessions;
  t  tournaments;
begin
  select * into s from private.embed_sessions where id = p_session;
  select * into t from tournaments where id = p_tournament;
  if s.id is null or t.id is null
     or t.org_id is distinct from s.org_id
     or (s.tournament_id is not null and s.tournament_id <> t.id) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  if s.kind = 'member' and t.identity_mode = 'accounts' then
    raise exception 'this tournament is for Ocheso accounts; sign in with your email' using errcode = '28000';
  end if;
  if s.kind = 'account' and t.identity_mode = 'platform' then
    raise exception 'this tournament is for players signed in on the organiser''s own site' using errcode = '28000';
  end if;
end $$;
revoke all on function private.session_may_touch(uuid, uuid) from public, anon, authenticated;

-- An account session, right after signing in inside the frame (A4): the
-- frame trades its Supabase token for this through the API and forgets the
-- token. Scoped to the organisation (or, for a personal event, to that
-- event). A pending invite to this event is accepted on the way. Twenty live
-- sessions per person: the oldest beyond that are revoked.
create or replace function public.create_account_embed_session(p_slug text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  me uuid := auth.uid();
  t  tournaments;
  e  text;
begin
  if me is null or not exists (select 1 from profiles where id = me and kind = 'account') then
    raise exception 'sign in to do this' using errcode = '28000';
  end if;
  select * into t from tournaments
   where slug = p_slug and (status <> 'draft' or private.is_tournament_staff(id));
  if not found or (t.org_id is not null and not exists (select 1 from organizations where id = t.org_id and status = 'active')) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  if t.identity_mode = 'platform' then
    raise exception 'this tournament is for players signed in on the organiser''s own site' using errcode = '28000';
  end if;
  e := private.confirmed_email(me);
  if e is not null then
    perform private.claim_invites(me, e, t.id);
  end if;
  update private.embed_sessions set revoked_at = now()
   where id in (select id from private.embed_sessions
                 where profile_id = me and kind = 'account' and revoked_at is null and expires_at > now()
                 order by created_at desc offset 19);
  return private.mint_session('account', t.org_id, me, case when t.org_id is null then t.id end, null);
end $$;

-- The Google popup, signed in first-party, binds its account to the frame's
-- hash (E4). Confirmed address, unbound row, before its deadline.
create or replace function public.embed_handoff_bind(p_hash text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  me uuid := auth.uid();
  h  private.embed_handoffs;
  t  tournaments;
begin
  if me is null or not exists (select 1 from profiles where id = me and kind = 'account') then
    raise exception 'sign in to do this' using errcode = '28000';
  end if;
  if private.confirmed_email(me) is null then
    raise exception 'confirm your email address first' using errcode = '28000';
  end if;
  select * into h from private.embed_handoffs where hash = p_hash for update;
  if not found or h.profile_id is not null or h.redeemed_at is not null or h.bind_by <= now() then
    raise exception 'this sign-in has expired; start again from the tournament' using errcode = 'no_data_found';
  end if;
  select * into t from tournaments where id = h.tournament_id;
  if t.identity_mode = 'platform' then
    raise exception 'this tournament is for players signed in on the organiser''s own site' using errcode = '28000';
  end if;
  update private.embed_handoffs set profile_id = me, bound_at = now() where hash = h.hash;
  return jsonb_build_object('status', 'bound',
                            'tournament', jsonb_build_object('slug', t.slug, 'title', t.title),
                            'org', (select jsonb_build_object('slug', o.slug, 'name', o.name) from organizations o where o.id = t.org_id));
end $$;

-- "Where am I signed in" (D1 /v1/me/embed-sessions): live account sessions.
create or replace function public.list_my_embed_sessions()
returns table (id uuid, org_slug text, org_name text, tournament_slug text, created_at timestamptz,
               expires_at timestamptz, last_used_at timestamptz)
language sql stable security definer set search_path = public, extensions as $$
  select s.id, o.slug, o.name, t.slug, s.created_at, s.expires_at, s.last_used_at
    from private.embed_sessions s
    left join organizations o on o.id = s.org_id
    left join tournaments t on t.id = s.tournament_id
   where s.profile_id = auth.uid() and s.kind = 'account' and s.revoked_at is null and s.expires_at > now()
   order by s.created_at desc;
$$;

create or replace function public.revoke_my_embed_session(p_session uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  update private.embed_sessions set revoked_at = coalesce(revoked_at, now())
   where id = p_session and profile_id = auth.uid() and kind = 'account';
  if not found then
    raise exception 'no such session' using errcode = 'no_data_found';
  end if;
end $$;

-- =============================================================================
-- embed_call (C6): everything an embed does, signed by the API
-- =============================================================================

-- Rate limits by kind (C10). The API may count in a separate call first
-- ({"phase": "hit"}, then the real call with {"counted": true}), so a request
-- that then fails still counts - what a brute-force-sensitive step needs.
create or replace function private.embed_throttle(k text, body jsonb)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  ip text := nullif(body ->> 'ip', '');
begin
  if k = 'emb-session-member' and ip is not null then
    perform private.throttle('emb-session:' || ip, 30, 3600);
  elsif k = 'emb-handoff-start' and ip is not null then
    perform private.throttle('emb-handoff:' || ip, 20, 600);
  elsif k = 'emb-handoff-redeem' and coalesce(body ->> 's', '') ~ '^[0-9a-f]{64}$' then
    perform private.throttle('emb-redeem:' || encode(extensions.digest(decode(body ->> 's', 'hex'), 'sha256'), 'hex'), 100, 180);
  elsif body ? 'session' and body ->> 'session' is not null then
    perform private.throttle('emb-act:' || (body ->> 'session'), 600, 60);
    -- An entry code is the one guessable secret an embed action takes, so a
    -- join that names one also counts in a bucket of its own: 20 per session
    -- per 10 minutes, plenty for a person mistyping. The API makes joins
    -- through the two-step count (routers/embed.py counted()), because a
    -- wrong code rolls its own transaction back - and its hit with it.
    if k = 'emb-join' and nullif(btrim(coalesce(body ->> 'code', '')), '') is not null then
      perform private.throttle('emb-code:' || (body ->> 'session'), 20, 600);
    end if;
  end if;
end $$;
revoke all on function private.embed_throttle(text, jsonb) from public, anon, authenticated;

-- emb-session-member {token: sha256 of the ochp_ token, parent_origin?, ip?}
create or replace function private.emb_session_member(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  pt     private.player_tokens;
  o      organizations;
  origin text := nullif(body ->> 'parent_origin', '');
begin
  select * into pt from private.player_tokens where hash = body ->> 'token';
  if not found or pt.expires_at <= now() then
    raise exception 'that sign-in has expired; ask the site to sign you in again' using errcode = 'OC401';
  end if;
  select * into o from organizations where id = pt.org_id;
  if o.status <> 'active' then
    raise exception 'this organiser''s events are paused' using errcode = 'OC401';
  end if;
  if exists (select 1 from org_players where profile_id = pt.profile_id and blocked_at is not null) then
    raise exception 'you cannot enter this organiser''s events' using errcode = '28000';
  end if;
  if origin is not null and not private.origin_allowed(o.allowed_origins, origin) then
    raise exception '% cannot sign players in to % tournaments', origin, o.name using errcode = '28000';
  end if;
  return private.mint_session('member', pt.org_id, pt.profile_id, pt.tournament_id, origin);
end $$;

-- emb-handoff-start {h, slug, ip?}: the frame registers sha256(S).
create or replace function private.emb_handoff_start(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  t tournaments;
  h private.embed_handoffs;
begin
  if coalesce(body ->> 'h', '') !~ '^[0-9a-f]{64}$' then
    raise exception 'that is not a sign-in request' using errcode = 'invalid_parameter_value';
  end if;
  select * into t from tournaments where slug = body ->> 'slug' and status <> 'draft';
  if not found then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  insert into private.embed_handoffs (hash, org_id, tournament_id, bind_by)
  values (body ->> 'h', t.org_id, t.id, now() + interval '10 minutes')
  on conflict (hash) do nothing
  returning * into h;
  if h.hash is null then
    raise exception 'that sign-in was already started' using errcode = 'unique_violation';
  end if;
  return jsonb_build_object('status', 'pending', 'bind_by', h.bind_by);
end $$;

-- emb-handoff-peek {h}: what the popup asks the person to confirm.
create or replace function private.emb_handoff_peek(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  h private.embed_handoffs;
  t tournaments;
begin
  select * into h from private.embed_handoffs where hash = body ->> 'h';
  if not found then
    raise exception 'no such sign-in' using errcode = 'no_data_found';
  end if;
  select * into t from tournaments where id = h.tournament_id;
  return jsonb_build_object(
    'status', case when h.redeemed_at is not null then 'used'
                   when h.profile_id is not null then 'bound'
                   when h.bind_by <= now() then 'expired'
                   else 'pending' end,
    'tournament', jsonb_build_object('slug', t.slug, 'title', t.title),
    'org', (select jsonb_build_object('slug', o.slug, 'name', o.name) from organizations o where o.id = t.org_id));
end $$;

-- emb-handoff-redeem {s}: S itself, as 64 hex (32 random bytes); h is
-- sha256 of those bytes. Answers a status until the popup has bound, then the
-- session exactly once.
create or replace function private.emb_handoff_redeem(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  h  private.embed_handoffs;
  e  text;
begin
  if coalesce(body ->> 's', '') !~ '^[0-9a-f]{64}$' then
    return jsonb_build_object('status', 'expired');
  end if;
  select * into h from private.embed_handoffs
   where hash = encode(extensions.digest(decode(body ->> 's', 'hex'), 'sha256'), 'hex')
   for update;
  if not found then
    return jsonb_build_object('status', 'expired');
  end if;
  if h.redeemed_at is not null then
    return jsonb_build_object('status', 'used');
  end if;
  if h.profile_id is null then
    return jsonb_build_object('status', case when h.bind_by <= now() then 'expired' else 'pending' end);
  end if;
  if h.bound_at < now() - interval '10 minutes' then
    return jsonb_build_object('status', 'expired');
  end if;
  update private.embed_handoffs set redeemed_at = now() where hash = h.hash;
  e := private.confirmed_email(h.profile_id);
  if e is not null then
    perform private.claim_invites(h.profile_id, e, h.tournament_id);
  end if;
  return jsonb_build_object('status', 'ok')
         || private.mint_session('account', h.org_id, h.profile_id,
                                 case when h.org_id is null then h.tournament_id end, null);
end $$;

-- emb-ping {t | o, origin, view, path?, ip?}: the frame saying where it is
-- (C10, E8). One write per row per five minutes, and the first sighting of an
-- origin is an event. Anyone can send one, naming any origin, so the 200-origin
-- cap is kept twice: origins on the organisation's own list, and the rest. A
-- flood of made-up origins fills only the second, and the partner's real site
-- - once it is on the list - is still recorded. A path that is not a plain
-- path (plain_path) is not stored.
create or replace function private.emb_ping(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  o      organizations;
  v_origin text := lower(body ->> 'origin');
  v_view   text := coalesce(body ->> 'view', 'tournament');
  v_path   text := private.plain_path(body ->> 'path');
  v_listed boolean;
  found_i  org_installs;
  is_first boolean;
begin
  if body ? 'o' then
    o := private.org_by_slug(body ->> 'o');
  else
    select org.* into o from tournaments t join organizations org on org.id = t.org_id
     where t.slug = body ->> 't' and org.status = 'active';
  end if;
  if o.id is null then
    return jsonb_build_object('status', 'ignored');
  end if;
  if v_origin is null or char_length(v_origin) > 200 or v_origin !~ '^https?://[a-z0-9.-]+(:[0-9]{1,5})?$'
     or v_view !~ '^[a-z][a-z-]{1,23}$' then
    raise exception 'that is not an origin' using errcode = 'invalid_parameter_value';
  end if;
  if nullif(body ->> 'ip', '') is not null then
    perform private.throttle('emb-ping:' || o.id || ':' || (body ->> 'ip'), 60, 3600);
  end if;
  v_listed := private.origin_listed(o.allowed_origins, v_origin);

  select * into found_i from org_installs where org_id = o.id and org_installs.origin = v_origin
                                         and org_installs.view = v_view for update;
  if found then
    if found_i.last_seen_at > now() - interval '5 minutes' then
      return jsonb_build_object('status', 'ok', 'first_seen', false);
    end if;
    update org_installs
       set last_seen_at = now(), hits = hits + 1, allowed = private.origin_allowed(o.allowed_origins, v_origin),
           last_path = coalesce(v_path, last_path)
     where org_id = o.id and org_installs.origin = v_origin and org_installs.view = v_view;
    return jsonb_build_object('status', 'ok', 'first_seen', false);
  end if;

  is_first := not exists (select 1 from org_installs where org_id = o.id and org_installs.origin = v_origin);
  if is_first and (select count(distinct i.origin) from org_installs i
                    where i.org_id = o.id and private.origin_listed(o.allowed_origins, i.origin) = v_listed) >= 200 then
    return jsonb_build_object('status', 'ignored');
  end if;
  insert into org_installs (org_id, origin, view, allowed, last_path)
  values (o.id, v_origin, v_view, private.origin_allowed(o.allowed_origins, v_origin), v_path)
  on conflict do nothing;
  if is_first then
    perform private.emit_org(o.id, 'install.first_seen',
                             jsonb_build_object('origin', v_origin, 'view', v_view, 'path', v_path,
                                                'allowed', private.origin_allowed(o.allowed_origins, v_origin)));
  end if;
  return jsonb_build_object('status', 'ok', 'first_seen', is_first);
end $$;

-- emb-bundle {slug, preview?}: everything a tournament embed renders (D3),
-- names included, server-rendered and cacheable. Drafts only for a preview,
-- which the API grants after checking a manager's token.
create or replace function private.emb_bundle(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  t         tournaments;
  o         organizations;
  watchable boolean;
begin
  select * into t from tournaments where slug = body ->> 'slug';
  if not found or (t.status = 'draft' and not coalesce((body ->> 'preview')::boolean, false)) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  select * into o from organizations where id = t.org_id;
  if o.id is not null and o.status <> 'active' then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  watchable := t.games_watchable and t.participants_visible;
  return jsonb_build_object(
    'v', 1,
    'tournament', private.tournament_public_json(t),
    'org', case when o.id is null then null else private.org_public_json(o) end,
    'roster', case when not t.participants_visible then '[]'::jsonb else coalesce((
      select jsonb_agg(jsonb_build_object('participant_id', p.id, 'user_id', p.user_id, 'name', pr.display_name,
                                          'username', pr.username, 'avatar_url', pr.avatar_url, 'country', pr.country,
                                          'kind', pr.kind, 'rating_at_entry', p.rating_at_entry, 'seed', p.seed,
                                          'joined_at', p.created_at)
                       order by p.seed nulls last, p.rating_at_entry desc nulls last, p.created_at)
        from participants p join profiles pr on pr.id = p.user_id
       where p.tournament_id = t.id and p.status = 'approved'), '[]'::jsonb) end,
    'people', case when not t.participants_visible then '[]'::jsonb else coalesce((
      select jsonb_agg(private.person_json(pr))
        from profiles pr
       where pr.id in (select white_id from games where tournament_id = t.id
                       union select black_id from games where tournament_id = t.id)), '[]'::jsonb) end,
    'results', case when not t.participants_visible then '[]'::jsonb else coalesce((
      select jsonb_agg(jsonb_build_object('game_id', g.id, 'round_number', r.number, 'round_status', r.status,
                                          'board', g.board, 'white_id', g.white_id, 'black_id', g.black_id,
                                          'status', g.status, 'result', g.result, 'termination', g.termination,
                                          'tiebreak_of', g.tiebreak_of, 'finished_at', g.finished_at)
                       order by r.number nulls last, g.board nulls last, g.created_at)
        from games g left join rounds r on r.id = g.round_id
       where g.tournament_id = t.id), '[]'::jsonb) end,
    'rounds', coalesce((
      select jsonb_agg(jsonb_build_object('number', r.number, 'status', r.status, 'created_at', r.created_at,
                                          'started_at', r.started_at, 'finished_at', r.finished_at)
                       order by r.number)
        from rounds r where r.tournament_id = t.id), '[]'::jsonb),
    'live', case when not watchable then '[]'::jsonb else coalesce((
      select jsonb_agg(jsonb_build_object('id', g.id, 'round', (select number from rounds where id = g.round_id),
                                          'board', g.board, 'white_id', g.white_id, 'black_id', g.black_id,
                                          'position', g.position, 'turn', g.turn, 'ply', g.ply,
                                          'last_move', g.last_move, 'white_ms', g.white_ms, 'black_ms', g.black_ms,
                                          'turn_started_at', g.turn_started_at, 'topic', private.topic('g', g.id))
                       order by g.board nulls last, g.created_at)
        from games g where g.tournament_id = t.id and g.status = 'live'), '[]'::jsonb) end,
    'topic', private.topic('t', t.id),
    'rev', t.embed_rev,
    'server_now', now());
end $$;

-- emb-game {game, session?}: a game with its moves, names and topic (D3),
-- for anyone when the organiser lets people watch, and for its own players
-- through their session even when not.
create or replace function private.emb_game(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  g      games;
  t      tournaments;
  s      private.embed_sessions;
  mine   text;
begin
  select * into g from games where id = (body ->> 'game')::uuid;
  if not found then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  select * into t from tournaments where id = g.tournament_id;
  if body ->> 'session' is not null then
    s := private.session_by_hash(body ->> 'session');
    perform private.session_may_touch(s.id, t.id);
    mine := private.side_of(g, s.profile_id);
  end if;
  if mine is null and not (t.games_watchable and t.participants_visible and t.status <> 'draft') then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  return jsonb_build_object(
    'game', to_jsonb(g),
    'tournament', jsonb_build_object('id', t.id, 'slug', t.slug, 'title', t.title, 'game', t.game, 'variant', t.variant,
                                     'format', t.format, 'status', t.status, 'games_watchable', t.games_watchable,
                                     'org_id', t.org_id),
    'round', (select number from rounds where id = g.round_id),
    'white', (select private.person_json(p) from profiles p where p.id = g.white_id),
    'black', (select private.person_json(p) from profiles p where p.id = g.black_id),
    'moves', coalesce((select jsonb_agg(jsonb_build_object('ply', m.ply, 'move', m.move, 'san', m.san,
                                                           'clock_ms', m.clock_ms, 'created_at', m.created_at)
                                        order by m.ply)
                         from moves m where m.game_id = g.id), '[]'::jsonb),
    'my_color', mine,
    'topic', private.topic('g', g.id),
    'server_now', now());
end $$;

-- emb-me {session, slug}: the player's own state in an event (D3).
create or replace function private.emb_me(s private.embed_sessions, body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  t     tournaments;
  p     profiles;
  entry participants;
  cur   games;
  nxt   jsonb;
  pend  rounds;
begin
  select * into t from tournaments where slug = body ->> 'slug';
  if not found then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  perform private.session_may_touch(s.id, t.id);
  select * into p from profiles where id = s.profile_id;
  select * into entry from participants where tournament_id = t.id and user_id = s.profile_id;
  select * into cur from games
   where tournament_id = t.id and status <> 'finished' and s.profile_id in (white_id, black_id)
   order by created_at desc limit 1;
  if t.status = 'registration' then
    nxt := jsonb_build_object('round', case when t.format = 'arena' then null else 1 end, 'at', t.starts_at);
  elsif t.status = 'live' and t.format <> 'arena' then
    select * into pend from rounds where tournament_id = t.id and status = 'pending' order by number desc limit 1;
    if pend.id is not null then
      nxt := jsonb_build_object('round', pend.number, 'at', pend.created_at + make_interval(secs => t.round_break_s));
    end if;
  end if;
  return jsonb_build_object(
    'player', jsonb_build_object('id', p.id, 'name', p.display_name, 'kind', p.kind),
    'tournament', jsonb_build_object('id', t.id, 'slug', t.slug, 'status', t.status),
    'entry', case when entry.id is null then null
                  else jsonb_build_object('status', entry.status, 'joined_via', entry.joined_via) end,
    'invite_pending', s.kind = 'account' and exists (
                        select 1 from tournament_invites
                         where tournament_id = t.id and status = 'pending' and email = private.confirmed_email(s.profile_id)),
    'current_game', case when cur.id is null then null
                         else jsonb_build_object('id', cur.id, 'status', cur.status,
                                                 'color', private.side_of(cur, s.profile_id),
                                                 'topic', private.topic('g', cur.id)) end,
    'next', nxt,
    'topic', private.topic('t', t.id));
end $$;

-- emb-arena-join {session, slug}: queue, and hand the API what it needs to
-- pick an opponent (queue, ratings, results). Already paired is an answer.
create or replace function private.emb_arena_join(s private.embed_sessions, body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  t   tournaments;
  cur games;
begin
  select * into t from tournaments where slug = body ->> 'slug';
  if not found then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  perform private.session_may_touch(s.id, t.id);
  select * into cur from games
   where tournament_id = t.id and status <> 'finished' and s.profile_id in (white_id, black_id) limit 1;
  if cur.id is not null then
    return jsonb_build_object('status', 'paired', 'game', to_jsonb(cur), 'topic', private.topic('g', cur.id));
  end if;
  perform private.do_arena_join(t.id, s.profile_id, s.id);
  -- The game and variant ride along: the API sets up the opening position of
  -- the pairing it signs from them, and would otherwise read the event again.
  return jsonb_build_object(
    'status', 'queued',
    'tournament', jsonb_build_object('id', t.id, 'slug', t.slug, 'game', t.game, 'variant', t.variant, 'format', t.format),
    'me', s.profile_id,
    'queue', coalesce((select jsonb_agg(jsonb_build_object('user_id', q.user_id, 'since', q.since) order by q.since)
                         from arena_queue q where q.tournament_id = t.id), '[]'::jsonb),
    'seeds', coalesce((select jsonb_agg(jsonb_build_object('user_id', p.user_id, 'rating', p.rating_at_entry))
                         from participants p where p.tournament_id = t.id and p.status = 'approved'), '[]'::jsonb),
    'results', coalesce((select jsonb_agg(jsonb_build_object('game_id', g.id, 'white_id', g.white_id, 'black_id', g.black_id,
                                                             'status', g.status, 'result', g.result))
                           from games g where g.tournament_id = t.id), '[]'::jsonb));
end $$;

revoke all on function private.emb_session_member(jsonb) from public, anon, authenticated;
revoke all on function private.emb_handoff_start(jsonb) from public, anon, authenticated;
revoke all on function private.emb_handoff_peek(jsonb) from public, anon, authenticated;
revoke all on function private.emb_handoff_redeem(jsonb) from public, anon, authenticated;
revoke all on function private.emb_ping(jsonb) from public, anon, authenticated;
revoke all on function private.emb_bundle(jsonb) from public, anon, authenticated;
revoke all on function private.emb_game(jsonb) from public, anon, authenticated;
revoke all on function private.emb_me(private.embed_sessions, jsonb) from public, anon, authenticated;
revoke all on function private.emb_arena_join(private.embed_sessions, jsonb) from public, anon, authenticated;

-- The dispatcher. The kind is read from the payload only to find the
-- function; the signature over the whole payload is checked first, and kinds
-- outside this list are refused, so nothing signed for org_call, system_call,
-- the referee or the agents can be replayed here.
create or replace function public.embed_call(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, p_payload::jsonb ->> 'kind');
  k    text := body ->> 'kind';
  s    private.embed_sessions;
  t    tournaments;
  res  jsonb;
begin
  if k is null or not k = any (array[
       'emb-session-member', 'emb-handoff-start', 'emb-handoff-peek', 'emb-handoff-redeem',
       'emb-me', 'emb-game', 'emb-join', 'emb-withdraw', 'emb-move', 'emb-flag', 'emb-resign', 'emb-draw',
       'emb-decline', 'emb-arena-join', 'emb-arena-leave', 'emb-arena-pairings', 'emb-logout',
       'emb-ping', 'emb-bundle']) then
    raise exception 'that request is for something else' using errcode = '28000';
  end if;
  if not coalesce((body ->> 'counted')::boolean, false) then
    perform private.embed_throttle(k, body);
  end if;
  if body ->> 'phase' = 'hit' then
    return jsonb_build_object('counted', true);
  end if;

  -- No session needed.
  case k
    when 'emb-session-member' then return private.emb_session_member(body);
    when 'emb-handoff-start'  then return private.emb_handoff_start(body);
    when 'emb-handoff-peek'   then return private.emb_handoff_peek(body);
    when 'emb-handoff-redeem' then return private.emb_handoff_redeem(body);
    when 'emb-ping'           then return private.emb_ping(body);
    when 'emb-bundle'         then return private.emb_bundle(body);
    when 'emb-game'           then return private.emb_game(body);
    else null;
  end case;

  -- Everything else is done by the session's player, and only by them.
  s := private.session_by_hash(body ->> 'session');
  case k
    when 'emb-me' then
      return private.emb_me(s, body);
    when 'emb-join' then
      return to_jsonb(private.do_join(body ->> 'slug', body ->> 'code', body ->> 'invite', s.profile_id, s.id));
    when 'emb-withdraw' then
      return to_jsonb(private.do_withdraw(body ->> 'slug', s.profile_id, s.id));
    when 'emb-move' then
      return to_jsonb(private.do_move(body, s.profile_id, s.id));
    when 'emb-flag' then
      return to_jsonb(private.do_flag(body, s.profile_id, false, s.id));
    when 'emb-resign' then
      return to_jsonb(private.do_resign((body ->> 'game')::uuid, s.profile_id, s.id));
    when 'emb-draw' then
      return to_jsonb(private.do_offer_draw((body ->> 'game')::uuid, s.profile_id, s.id));
    when 'emb-decline' then
      return to_jsonb(private.do_decline_draw((body ->> 'game')::uuid, s.profile_id, s.id));
    when 'emb-arena-join' then
      return private.emb_arena_join(s, body);
    when 'emb-arena-leave' then
      select * into t from tournaments where slug = body ->> 'slug';
      if not found then
        raise exception 'no such tournament' using errcode = 'no_data_found';
      end if;
      perform private.do_arena_leave(t.id, s.profile_id, s.id);
      return jsonb_build_object('status', 'left');
    when 'emb-arena-pairings' then
      select coalesce(jsonb_agg(to_jsonb(g)), '[]'::jsonb) into res
        from private.do_publish(jsonb_build_object('tournament', body -> 'tournament', 'round', null,
                                                   'start', true, 'games', body -> 'games'),
                                s.profile_id, false, s.id) g;
      return res;
    when 'emb-logout' then
      update private.embed_sessions set revoked_at = coalesce(revoked_at, now()) where id = s.id;
      return jsonb_build_object('status', 'ok');
  end case;
end $$;

-- =============================================================================
-- org_call (C6): a platform's server, with an org secret key
-- =============================================================================

-- The key behind a request: live, its organisation active, its scope
-- covering what is asked. Used at most once a minute is written down.
create or replace function private.org_key_by_hash(p_hash text, p_scope text)
returns public.org_keys language plpgsql security definer set search_path = public, extensions as $$
declare
  k org_keys;
begin
  select * into k from org_keys where hash = p_hash;
  if not found then
    raise exception 'that key is not valid' using errcode = 'OC401';
  end if;
  if k.revoked_at is not null then
    raise exception 'that key was revoked' using errcode = 'OC401';
  end if;
  if not exists (select 1 from organizations where id = k.org_id and status = 'active') then
    raise exception 'this organisation is suspended' using errcode = 'OC401';
  end if;
  if not p_scope = any (k.scopes) then
    raise exception 'this key cannot do that (it lacks the % scope)', p_scope using errcode = 'insufficient_privilege';
  end if;
  if k.last_used_at is null or k.last_used_at < now() - interval '1 minute' then
    update org_keys set last_used_at = now() where id = k.id;
  end if;
  return k;
end $$;
revoke all on function private.org_key_by_hash(text, text) from public, anon, authenticated;

-- A platform user as a member profile: made the first time, refreshed after.
-- Serialised per (organisation, external id) by a transaction lock, so two
-- widgets asking at once cannot make two profiles. Blocked players stop here.
-- f: {external_id, name, email?, avatar_url?, country?, rating?}
create or replace function private.upsert_member(o public.organizations, f jsonb)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare
  ext    text := btrim(f ->> 'external_id');
  nm     text := nullif(left(btrim(coalesce(f ->> 'name', '')), 60), '');
  avatar text := case when coalesce(f ->> 'avatar_url', '') ~ '^https://[^\s"''<>()\\]+$'
                       and char_length(f ->> 'avatar_url') <= 500 then f ->> 'avatar_url' end;
  ctry   text := case when coalesce(f ->> 'country', '') ~ '^[A-Z]{2}$' then f ->> 'country' end;
  v_email text := case when char_length(f ->> 'email') <= 254 then lower(btrim(f ->> 'email')) end;
  rating int  := case when coalesce(f ->> 'rating', '') ~ '^\d{3,4}$' and (f ->> 'rating')::int between 100 and 3500
                      then (f ->> 'rating')::int end;
  op     org_players;
  pid    uuid;
begin
  if ext is null or char_length(ext) not between 1 and 128 then
    raise exception 'external_id must be 1 to 128 characters' using errcode = 'invalid_parameter_value';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(o.id::text || ':' || ext, 0));
  select * into op from org_players where org_id = o.id and external_id = ext for update;
  if found then
    if op.blocked_at is not null then
      raise exception 'this player is blocked' using errcode = '28000';
    end if;
    update profiles
       set display_name = coalesce(nm, display_name),
           avatar_url = case when f ? 'avatar_url' then avatar else avatar_url end,
           country = case when f ? 'country' then ctry else country end
     where id = op.profile_id;
    update org_players set email = case when f ? 'email' then v_email else org_players.email end, last_seen_at = now()
     where profile_id = op.profile_id;
    return op.profile_id;
  end if;
  if nm is null then
    raise exception 'a new player needs a name (1 to 60 characters)' using errcode = 'invalid_parameter_value';
  end if;
  insert into profiles (id, kind, username, display_name, avatar_url, country, chess_rating, checkers_rating)
  values (gen_random_uuid(), 'member', null, nm, avatar, ctry, coalesce(rating, 1500), coalesce(rating, 1500))
  returning id into pid;
  insert into org_players (profile_id, org_id, external_id, email, last_seen_at)
  values (pid, o.id, ext, v_email, now());
  return pid;
end $$;
revoke all on function private.upsert_member(public.organizations, jsonb) from public, anon, authenticated;

-- Enter a member, as their platform's server says: approved, no code, no
-- queue, invite-only or not - the platform is the organiser here. Seats and
-- who-can-play still apply.
create or replace function private.enter_member(t public.tournaments, p_profile uuid)
returns public.participants language plpgsql security definer set search_path = public, extensions as $$
declare
  p   profiles;
  row participants;
begin
  if t.identity_mode = 'accounts' then
    raise exception 'this tournament takes Ocheso accounts only' using errcode = 'check_violation';
  end if;
  if t.status not in ('draft', 'registration') then
    raise exception 'entries are closed' using errcode = 'check_violation';
  end if;
  select * into row from participants where tournament_id = t.id and user_id = p_profile;
  if found and row.status = 'approved' then
    return row;
  end if;
  if t.max_participants is not null and private.seats_taken(t.id) >= t.max_participants then
    raise exception 'this tournament is full' using errcode = 'check_violation';
  end if;
  select * into p from profiles where id = p_profile;
  insert into participants (tournament_id, user_id, status, rating_at_entry, joined_via, decided_at)
  values (t.id, p_profile, 'approved', case when t.game = 'chess' then p.chess_rating else p.checkers_rating end,
          'platform', now())
  on conflict (tournament_id, user_id) do update
    set status = 'approved', joined_via = 'platform', decided_at = now(), decided_by = null,
        rating_at_entry = excluded.rating_at_entry
  returning * into row;
  return row;
end $$;
revoke all on function private.enter_member(public.tournaments, uuid) from public, anon, authenticated;

create or replace function private.org_tournament(o public.organizations, p_slug text, p_lock boolean default false)
returns public.tournaments language plpgsql security definer set search_path = public, extensions as $$
declare
  t tournaments;
begin
  if p_lock then
    select * into t from tournaments where slug = p_slug and org_id = o.id for update;
  else
    select * into t from tournaments where slug = p_slug and org_id = o.id;
  end if;
  if not found then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  return t;
end $$;
revoke all on function private.org_tournament(public.organizations, text, boolean) from public, anon, authenticated;

-- A roster with the ids the platform knows its players by.
create or replace function private.org_roster(p_tournament uuid)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'participant_id', p.id, 'profile_id', p.user_id, 'kind', pr.kind, 'external_id', op.external_id,
           'name', pr.display_name, 'username', pr.username, 'status', p.status, 'joined_via', p.joined_via,
           'rating_at_entry', p.rating_at_entry, 'seed', p.seed, 'joined_at', p.created_at)
         order by p.seed nulls last, p.rating_at_entry desc nulls last, p.created_at), '[]'::jsonb)
    from participants p join profiles pr on pr.id = p.user_id
    left join org_players op on op.profile_id = p.user_id
   where p.tournament_id = p_tournament and p.status in ('pending', 'approved');
$$;
revoke all on function private.org_roster(uuid) from public, anon, authenticated;

create or replace function private.org_results(p_tournament uuid)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'game_id', g.id, 'round_number', r.number, 'round_status', r.status, 'board', g.board,
           'white_id', g.white_id, 'black_id', g.black_id,
           'white_external_id', (select external_id from org_players where profile_id = g.white_id),
           'black_external_id', (select external_id from org_players where profile_id = g.black_id),
           'status', g.status, 'result', g.result, 'termination', g.termination,
           'tiebreak_of', g.tiebreak_of, 'finished_at', g.finished_at)
         order by r.number nulls last, g.board nulls last, g.created_at), '[]'::jsonb)
    from games g left join rounds r on r.id = g.round_id
   where g.tournament_id = p_tournament;
$$;
revoke all on function private.org_results(uuid) from public, anon, authenticated;

-- The fields a platform may change on its events: the same columns a manager
-- may, by the same names. Anything else in `c` is ignored.
create or replace function private.org_update_tournament(t public.tournaments, c jsonb)
returns public.tournaments language plpgsql security definer set search_path = public, extensions as $$
declare
  r   tournaments := jsonb_populate_record(t, c);
  res tournaments;
begin
  update tournaments set
    title = r.title, description = r.description, clock_base_s = r.clock_base_s,
    clock_increment_s = r.clock_increment_s, starts_at = r.starts_at, rounds_count = r.rounds_count,
    arena_minutes = r.arena_minutes, tiebreaks = r.tiebreaks, max_participants = r.max_participants,
    is_listed = r.is_listed, participants_visible = r.participants_visible, games_watchable = r.games_watchable,
    requires_code = r.requires_code, auto_approve = r.auto_approve, identity_mode = r.identity_mode,
    invite_only = r.invite_only, org_listed = r.org_listed, rated = r.rated, autopilot = r.autopilot,
    min_players = r.min_players, short_field = r.short_field, postpone_min = r.postpone_min,
    max_postpones = r.max_postpones, round_break_s = r.round_break_s, language = r.language
  where id = t.id
  returning * into res;
  if c ? 'entry_code' then
    update tournament_secrets set entry_code = nullif(upper(btrim(c ->> 'entry_code')), '') where tournament_id = t.id;
  end if;
  return res;
end $$;
revoke all on function private.org_update_tournament(public.tournaments, jsonb) from public, anon, authenticated;

-- The dispatcher. `key` is the SHA-256 of the ochs_ key; the API never sends
-- the key itself. `idem`, when present, is a hash of the Idempotency-Key: a
-- repeat within a day gets the first reply back instead of a second effect.
create or replace function public.org_call(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body   jsonb := private.machine_request(p_payload, p_sig, p_payload::jsonb ->> 'kind');
  k      text := body ->> 'kind';
  scope  text;
  okey   org_keys;
  o      organizations;
  t      tournaments;
  pid    uuid;
  raw    text;
  item   jsonb;
  i      int := 0;
  added  jsonb := '[]'::jsonb;
  errs   jsonb := '[]'::jsonb;
  res    jsonb;
  idem   text := nullif(body ->> 'idem', '');
  op     org_players;
begin
  scope := case k
             when 'org-player'            then 'players'
             when 'org-enter'             then 'players'
             when 'org-remove'            then 'players'
             when 'org-player-erase'      then 'players'
             when 'org-tournament-create' then 'tournaments'
             when 'org-tournament-update' then 'tournaments'
             when 'org-tournament-status' then 'tournaments'
             when 'org-invites'           then 'invites'
             when 'org-read'              then 'read'
           end;
  if scope is null then
    raise exception 'that request is for something else' using errcode = '28000';
  end if;
  okey := private.org_key_by_hash(body ->> 'key', scope);
  select * into o from organizations where id = okey.org_id;

  if idem is not null and k not in ('org-player', 'org-read') then
    select response into res from private.org_idempotency
     where org_id = o.id and kind = k and key_hash = idem and created_at > now() - interval '24 hours';
    if found then
      return res;
    end if;
  end if;

  case k
    -- {external_id, name, email?, avatar_url?, country?, rating?, tournament? (slug), enter?}
    when 'org-player' then
      perform private.throttle('org-ptok:' || o.id, private.plan_limit(o.plan, 'player_tokens_min'), 60);
      pid := private.upsert_member(o, body);
      if body ->> 'tournament' is not null then
        t := private.org_tournament(o, body ->> 'tournament');
      end if;
      raw := 'ochp_' || encode(extensions.gen_random_bytes(24), 'hex');
      insert into private.player_tokens (hash, org_id, profile_id, tournament_id, expires_at)
      values (encode(extensions.digest(raw, 'sha256'), 'hex'), o.id, pid, t.id, now() + interval '10 minutes');
      res := jsonb_build_object('token', raw, 'expires_at', now() + interval '10 minutes',
                                'player', (select jsonb_build_object('id', p.id, 'name', p.display_name)
                                             from profiles p where p.id = pid),
                                'entry', null);
      if coalesce((body ->> 'enter')::boolean, false) and t.id is not null then
        res := res || jsonb_build_object('entry', to_jsonb(private.enter_member(t, pid)));
      end if;
      return res;

    -- {tournament: {...fields}, publish?}
    when 'org-tournament-create' then
      t := private.insert_org_tournament(
             o, (select user_id from org_members where org_id = o.id and role = 'owner'),
             body -> 'tournament', null,
             case when coalesce((body ->> 'publish')::boolean, false) then 'registration' else 'draft' end::public.tournament_status);
      res := private.tournament_public_json(t);

    -- {slug, changes: {...}}
    when 'org-tournament-update' then
      t := private.org_tournament(o, body ->> 'slug', true);
      t := private.org_update_tournament(t, coalesce(body -> 'changes', '{}'::jsonb));
      res := private.tournament_public_json(t);

    -- {slug, status}: publish (registration), draft, start (live), finish, archive.
    when 'org-tournament-status' then
      t := private.org_tournament(o, body ->> 'slug', true);
      update tournaments set status = (body ->> 'status')::public.tournament_status where id = t.id returning * into t;
      res := private.tournament_public_json(t);

    -- {slug, players: [{external_id, name, ...}]}: all or nothing on seats.
    when 'org-enter' then
      t := private.org_tournament(o, body ->> 'slug', true);
      if jsonb_typeof(body -> 'players') is distinct from 'array' or jsonb_array_length(body -> 'players') not between 1 and 500 then
        raise exception 'enter between 1 and 500 players at a time' using errcode = 'invalid_parameter_value';
      end if;
      for item in select * from jsonb_array_elements(body -> 'players') loop
        i := i + 1;
        if coalesce(btrim(item ->> 'external_id'), '') = '' then
          errs := errs || jsonb_build_object('row', i, 'reason', 'external_id is missing');
          continue;
        end if;
        if exists (select 1 from org_players where org_id = o.id and external_id = btrim(item ->> 'external_id')
                                               and blocked_at is not null) then
          errs := errs || jsonb_build_object('row', i, 'external_id', item ->> 'external_id', 'reason', 'blocked');
          continue;
        end if;
        if coalesce(btrim(item ->> 'name'), '') = ''
           and not exists (select 1 from org_players where org_id = o.id and external_id = btrim(item ->> 'external_id')) then
          errs := errs || jsonb_build_object('row', i, 'external_id', item ->> 'external_id', 'reason', 'a new player needs a name');
          continue;
        end if;
        pid := private.upsert_member(o, item);
        added := added || jsonb_build_object('external_id', item ->> 'external_id', 'profile_id', pid,
                                             'status', (private.enter_member(t, pid)).status);
      end loop;
      res := jsonb_build_object('added', added, 'errors', errs);

    -- {slug, rows: [{email, name?, note?}], send?}
    when 'org-invites' then
      t := private.org_tournament(o, body ->> 'slug', true);
      res := private.do_add_invites(t, body -> 'rows', coalesce((body ->> 'send')::boolean, true), null);

    -- {slug, external_id}: out of the event (the row goes, as when a manager removes someone).
    -- Every lookup by external_id trims it as upsert_member stored it, so
    -- "alice " finds alice - for erasure above all, which must never quietly
    -- miss the person it was asked to forget.
    when 'org-remove' then
      t := private.org_tournament(o, body ->> 'slug', true);
      delete from participants p using org_players pl
       where p.tournament_id = t.id and pl.profile_id = p.user_id and pl.org_id = o.id
         and pl.external_id = btrim(body ->> 'external_id');
      res := jsonb_build_object('removed', found);

    -- {what: tournaments | tournament | roster | rounds | standings, slug?}
    when 'org-read' then
      if body ->> 'what' = 'tournaments' then
        return jsonb_build_object('tournaments', coalesce((
          select jsonb_agg(private.tournament_public_json(x) order by x.starts_at desc)
            from tournaments x where x.org_id = o.id and x.status <> 'archived'), '[]'::jsonb));
      end if;
      t := private.org_tournament(o, body ->> 'slug');
      res := jsonb_build_object('tournament', private.tournament_public_json(t));
      if body ->> 'what' in ('roster', 'standings') then
        res := res || jsonb_build_object('roster', private.org_roster(t.id));
      end if;
      if body ->> 'what' in ('rounds', 'standings') then
        res := res || jsonb_build_object(
          'results', private.org_results(t.id),
          'rounds', coalesce((select jsonb_agg(jsonb_build_object('number', r.number, 'status', r.status,
                                                                  'started_at', r.started_at, 'finished_at', r.finished_at)
                                               order by r.number)
                                from rounds r where r.tournament_id = t.id), '[]'::jsonb));
      end if;
      return res;

    -- {external_id}: the right to be forgotten (C4). The profile stays so
    -- results stay whole, as "Deleted player" with nothing that identifies
    -- them; the link to the platform's id goes, and so do their sessions.
    when 'org-player-erase' then
      select * into op from org_players where org_id = o.id and external_id = btrim(body ->> 'external_id') for update;
      if not found then
        res := jsonb_build_object('erased', false);
      else
        update profiles set display_name = 'Deleted player', avatar_url = null, country = null where id = op.profile_id;
        delete from private.embed_sessions where profile_id = op.profile_id;
        delete from private.player_tokens where profile_id = op.profile_id;
        delete from arena_queue where user_id = op.profile_id;
        delete from org_players where profile_id = op.profile_id;
        res := jsonb_build_object('erased', true, 'profile_id', op.profile_id);
      end if;
  end case;

  if idem is not null then
    insert into private.org_idempotency (org_id, kind, key_hash, response) values (o.id, k, idem, res)
    on conflict (org_id, kind, key_hash) do update set response = excluded.response, created_at = now();
  end if;
  return res;
end $$;

-- =============================================================================
-- Autopilot (C8) and system_call
-- =============================================================================

-- Tournaments with something for the autopilot to do, and what. Autopilot
-- events only, and only when no tick holds them and nobody asked it to wait.
--   start       entries open and the start time has passed
--   pair        round-based, live, and no round still open (round 1 included)
--   start-round a round published without starting, its break over
--   close       an arena whose window has shut, with every game finished
--   arena-pair  an open arena with two or more waiting
create or replace function private.autopilot_candidates()
returns table (tournament_id uuid, reasons text[])
language sql stable security definer set search_path = public, extensions as $$
  select c.id, c.reasons from (
    select t.id, array_remove(array[
             case when t.status = 'registration' and t.starts_at <= now() then 'start' end,
             case when t.status = 'live' and t.format <> 'arena'
                       and not exists (select 1 from rounds r where r.tournament_id = t.id and r.status <> 'finished')
                  then 'pair' end,
             case when t.status = 'live' and t.format <> 'arena'
                       and exists (select 1 from rounds r where r.tournament_id = t.id and r.status = 'pending'
                                     and r.created_at + make_interval(secs => t.round_break_s) <= now())
                  then 'start-round' end,
             case when t.status = 'live' and t.format = 'arena'
                       and now() >= t.started_at + make_interval(mins => t.arena_minutes)
                       and not exists (select 1 from games g where g.tournament_id = t.id and g.status <> 'finished')
                  then 'close' end,
             case when t.status = 'live' and t.format = 'arena'
                       and now() < t.started_at + make_interval(mins => t.arena_minutes)
                       and (select count(*) from arena_queue q where q.tournament_id = t.id) >= 2
                  then 'arena-pair' end
           ]::text[], null) as reasons
      from tournaments t
      left join private.autopilot_state st on st.tournament_id = t.id
     where t.autopilot and t.status in ('registration', 'live')
       and (st.lease_until is null or st.lease_until <= now())
       and (st.next_check_at is null or st.next_check_at <= now())
       and (st.hold_until is null or st.hold_until <= now())
       and (t.org_id is null or exists (select 1 from organizations o where o.id = t.org_id and o.status = 'active'))
  ) c
  where cardinality(c.reasons) > 0;
$$;

-- Games whose side to move has run out of time, in any tournament (C8: flag
-- sweeps apply to every tournament, not only autopilot ones - a behaviour
-- change for organisers who used to wait for a claim).
create or replace function private.expired_games(p_limit int default 50)
returns setof public.games language sql stable security definer set search_path = public, extensions as $$
  select g.* from games g
   where g.status = 'live' and g.turn_started_at is not null and private.time_left(g) <= 0
   order by g.turn_started_at
   limit p_limit;
$$;

-- Series with no instance waiting - except one whose last try failed, until
-- its retry_at (series_next_safe): a bad template is retried every five
-- minutes, not on every tick, and does not keep the autopilot kicking.
create or replace function private.series_due()
returns setof uuid language sql stable security definer set search_path = public, extensions as $$
  select s.id from tournament_series s join organizations o on o.id = s.org_id and o.status = 'active'
   where s.active and s.stopped_at is null
     and (s.retry_at is null or s.retry_at <= now())
     and not exists (select 1 from tournaments t where t.series_id = s.id and t.status in ('draft', 'registration'));
$$;

create or replace function private.mail_due()
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournament_invites
                  where status = 'pending' and send and sent_at is null
                    and (mail_lease_until is null or mail_lease_until <= now()))
      or exists (select 1 from private.mail_outbox
                  where sent_at is null and attempts < 3 and (lease_until is null or lease_until <= now()));
$$;

-- Whether waiting mail is worth a tick by itself: yes when the API last said
-- it can send (or has not said), and otherwise once every ten minutes, so an
-- API that has since been given its Resend settings gets to say so.
create or replace function private.mail_kick_ok()
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select coalesce((select mail_on is not false or mail_checked_at is null or mail_checked_at <= now() - interval '10 minutes'
                     from private.platform_settings), true);
$$;

-- Whether a tick would find anything at all to do. Cheap: each part is an
-- indexed probe, and pg_cron asks every 10 seconds.
create or replace function private.autopilot_due()
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from private.autopilot_candidates())
      or exists (select 1 from private.expired_games(1))
      or (private.mail_due() and private.mail_kick_ok())
      or exists (select 1 from private.series_due());
$$;

-- What the API needs to decide a tournament's next step without asking
-- again: the event, its autopilot state, the approved field in seeding
-- order, every result, the rounds, the arena queue.
create or replace function private.autopilot_snapshot(p_tournament uuid, p_lease uuid, p_reasons text[])
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'lease', p_lease,
    'reasons', to_jsonb(p_reasons),
    'tournament', to_jsonb(t) - 'embed_rev',
    'state', (select to_jsonb(st) - 'lease_id' - 'lease_until' from private.autopilot_state st where st.tournament_id = t.id),
    'seeds', coalesce((select jsonb_agg(jsonb_build_object('user_id', p.user_id, 'rating', p.rating_at_entry,
                                                           'seed', p.seed, 'joined_at', p.created_at)
                                        order by p.seed nulls last, p.rating_at_entry desc nulls last, p.created_at)
                         from participants p where p.tournament_id = t.id and p.status = 'approved'), '[]'::jsonb),
    'results', private.org_results(t.id),
    'rounds', coalesce((select jsonb_agg(jsonb_build_object('id', r.id, 'number', r.number, 'status', r.status,
                                                            'created_at', r.created_at, 'started_at', r.started_at,
                                                            'finished_at', r.finished_at) order by r.number)
                          from rounds r where r.tournament_id = t.id), '[]'::jsonb),
    'queue', coalesce((select jsonb_agg(jsonb_build_object('user_id', q.user_id, 'since', q.since) order by q.since)
                         from arena_queue q where q.tournament_id = t.id), '[]'::jsonb),
    'approved', (select count(*) from participants p where p.tournament_id = t.id and p.status = 'approved'),
    'pending_invites', (select count(*) from tournament_invites i where i.tournament_id = t.id and i.status = 'pending'))
  from tournaments t where t.id = p_tournament;
$$;

-- The lease a sys-* call names must still be this tick's. A human who acted
-- in between leaves it valid; the action itself then fails on the state it
-- finds, and the API takes that 409 as "nothing to do".
create or replace function private.lease_check(p_tournament uuid, p_lease uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  perform 1 from private.autopilot_state
   where tournament_id = p_tournament and lease_id = p_lease and lease_until > now()
   for update;
  if not found then
    raise exception 'the autopilot''s lease on this tournament has lapsed' using errcode = '40001';
  end if;
end $$;

-- sys-work {limit?, mail_on?}: lease up to 10 due tournaments (a
-- transaction-scoped row lock settles races: a second tick's upsert waits,
-- then finds the lease taken) and return their snapshots, the expired clocks,
-- the series that need an instance and whether mail is waiting. mail_on is
-- the API saying whether it can send mail (mail_kick_ok); written only when
-- it changes or every few minutes, not on every tick.
create or replace function private.sys_work(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  c     record;
  lid   uuid;
  n     int := least(greatest(coalesce((body ->> 'limit')::int, 10), 1), 10);
  snaps jsonb := '[]'::jsonb;
begin
  if jsonb_typeof(body -> 'mail_on') = 'boolean' then
    update private.platform_settings
       set mail_on = (body ->> 'mail_on')::boolean, mail_checked_at = now()
     where mail_on is distinct from (body ->> 'mail_on')::boolean
        or mail_checked_at is null or mail_checked_at <= now() - interval '5 minutes';
  end if;
  for c in select * from private.autopilot_candidates() limit 50 loop
    exit when jsonb_array_length(snaps) >= n;
    lid := null;
    insert into private.autopilot_state as st (tournament_id, lease_id, lease_until)
    values (c.tournament_id, gen_random_uuid(), now() + interval '60 seconds')
    on conflict (tournament_id) do update
      set lease_id = excluded.lease_id, lease_until = excluded.lease_until
      where st.lease_until is null or st.lease_until <= now()
    returning st.lease_id into lid;
    if lid is not null then
      snaps := snaps || private.autopilot_snapshot(c.tournament_id, lid, c.reasons);
    end if;
  end loop;
  return jsonb_build_object(
    'tournaments', snaps,
    'flags', coalesce((select jsonb_agg(jsonb_build_object(
                         'game', g.id, 'tournament', g.tournament_id, 'ply', g.ply, 'turn', g.turn,
                         'game_type', t.game, 'variant', t.variant,
                         'moves', coalesce((select jsonb_agg(m.move order by m.ply) from moves m where m.game_id = g.id), '[]'::jsonb)))
                         from private.expired_games(50) g join tournaments t on t.id = g.tournament_id), '[]'::jsonb),
    'series', coalesce((select jsonb_agg(x) from private.series_due() x), '[]'::jsonb),
    'mail', private.mail_due(),
    'server_now', now());
end $$;

-- sys-status {lease, tournament, status, note?}: start (with enough players),
-- finish, or cancel (archived, with the note saying why).
create or replace function private.sys_status(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  t  tournaments;
  to_status public.tournament_status := (body ->> 'status')::public.tournament_status;
begin
  perform private.lease_check((body ->> 'tournament')::uuid, (body ->> 'lease')::uuid);
  select * into t from tournaments where id = (body ->> 'tournament')::uuid for update;
  if not t.autopilot then
    raise exception 'autopilot is off for this tournament' using errcode = 'check_violation';
  end if;
  if not ((t.status = 'registration' and to_status in ('live', 'archived'))
          or (t.status = 'live' and to_status = 'finished')) then
    raise exception 'the autopilot cannot take a tournament from % to %', t.status, to_status using errcode = 'check_violation';
  end if;
  if to_status = 'live'
     and (select count(*) from participants where tournament_id = t.id and status = 'approved') < t.min_players then
    raise exception 'not enough players to start' using errcode = 'check_violation';
  end if;
  update tournaments set status = to_status, autopilot_note = coalesce(body ->> 'note', autopilot_note)
   where id = t.id returning * into t;
  update private.autopilot_state set last_action = 'status:' || to_status, last_action_at = now()
   where tournament_id = t.id;
  return private.tournament_public_json(t);
end $$;

-- sys-postpone {lease, tournament, minutes?, note?}: too few players at the
-- start. The organiser is mailed, and the platform told.
create or replace function private.sys_postpone(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  t    tournaments;
  st   private.autopilot_state;
  mins int;
begin
  perform private.lease_check((body ->> 'tournament')::uuid, (body ->> 'lease')::uuid);
  select * into t from tournaments where id = (body ->> 'tournament')::uuid for update;
  select * into st from private.autopilot_state where tournament_id = t.id;
  if not t.autopilot or t.status <> 'registration' then
    raise exception 'only a tournament waiting to start can be postponed' using errcode = 'check_violation';
  end if;
  if st.postponed >= t.max_postpones then
    raise exception 'this tournament has been postponed as often as it allows' using errcode = 'check_violation';
  end if;
  mins := least(greatest(coalesce((body ->> 'minutes')::int, t.postpone_min), 1), 1440);
  update tournaments
     set starts_at = greatest(starts_at, now()) + make_interval(mins => mins),
         autopilot_note = coalesce(body ->> 'note', autopilot_note)
   where id = t.id returning * into t;
  update private.autopilot_state set postponed = postponed + 1, last_action = 'postpone', last_action_at = now()
   where tournament_id = t.id;
  perform private.emit(t.id, 'tournament.postponed',
                       private.tournament_hook(t) || jsonb_build_object('postponed', st.postponed + 1, 'minutes', mins));
  insert into private.mail_outbox (kind, to_user, org_id, tournament_id, data)
  values ('postponed', t.owner_id, t.org_id, t.id,
          jsonb_build_object('slug', t.slug, 'title', t.title, 'starts_at', t.starts_at, 'note', t.autopilot_note,
                             'approved', (select count(*) from participants where tournament_id = t.id and status = 'approved'),
                             'min_players', t.min_players));
  return private.tournament_public_json(t);
end $$;

-- sys-release {lease, tournament, action?, error?, retry_in? (s), note?, stalled?}:
-- the tick is done with it. `stalled` tells the platform someone has to look -
-- once per stall: a stuck event is retried every five minutes, and each retry
-- releases with `stalled` again, so the event is sent only when the error is
-- new (the last release had none, or a different one).
create or replace function private.sys_release(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  tid  uuid := (body ->> 'tournament')::uuid;
  err  text := nullif(left(body ->> 'error', 500), '');
  prev text;
  t    tournaments;
begin
  select last_error into prev from private.autopilot_state
   where tournament_id = tid and lease_id = (body ->> 'lease')::uuid;
  update private.autopilot_state
     set lease_id = null, lease_until = null,
         last_action = coalesce(body ->> 'action', last_action),
         last_action_at = case when body ->> 'action' is not null then now() else last_action_at end,
         last_error = err,
         errors = case when err is not null then errors + 1 else 0 end,
         next_check_at = case when body ->> 'retry_in' is not null
                              then now() + make_interval(secs => least(greatest((body ->> 'retry_in')::int, 1), 86400))
                         end
   where tournament_id = tid and lease_id = (body ->> 'lease')::uuid;
  if not found then
    raise exception 'the autopilot''s lease on this tournament has lapsed' using errcode = '40001';
  end if;
  if body ? 'note' then
    update tournaments set autopilot_note = nullif(left(body ->> 'note', 500), '') where id = tid;
  end if;
  if coalesce((body ->> 'stalled')::boolean, false) and err is distinct from prev then
    select * into t from tournaments where id = tid;
    perform private.emit(tid, 'autopilot.stalled', private.tournament_hook(t) || jsonb_build_object('error', err));
  end if;
  return jsonb_build_object('released', true);
end $$;

-- The daily count of invitations one sender - an organisation, or a person
-- for their own events - has had delivered to one address (private.hits,
-- under a name that does not spell the address out).
create or replace function private.invite_mail_bucket(p_sender uuid, p_email text)
returns text language sql immutable as $$
  select 'invite-mail:' || p_sender || ':' || md5(lower(p_email));
$$;
revoke all on function private.invite_mail_bucket(uuid, text) from public, anon, authenticated;

-- sys-mail-batch {limit?}: invites and other mail to send now, held for two
-- minutes so a second tick does not send them too. Suppressed addresses are
-- marked and skipped. So are invites past the day's cap for their sender and
-- address (10, counted by sys_mail_done as they are delivered): resend's
-- limits are per invite, and without this a sender with many events - or a
-- free account that makes them - could still mail one inbox all day. Those are
-- marked, not deferred, so they never sit "due" (which would keep the
-- autopilot ticking) and the organiser sees why; resending tomorrow works.
create or replace function private.sys_mail_batch(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  n    int := least(greatest(coalesce((body ->> 'limit')::int, 50), 1), 100);
  ws   timestamptz := to_timestamp(floor(extract(epoch from now()) / 86400) * 86400);
  invs jsonb;
  mail jsonb;
begin
  update tournament_invites i set send = false, send_error = 'suppressed'
   where i.status = 'pending' and i.send and i.sent_at is null
     and exists (select 1 from private.email_suppressions s where s.email = i.email);

  with due as (
    select i.id, i.created_at, private.invite_mail_bucket(coalesce(t.org_id, t.owner_id), i.email) as b
      from tournament_invites i join tournaments t on t.id = i.tournament_id
     where i.status = 'pending' and i.send and i.sent_at is null
       and (i.mail_lease_until is null or i.mail_lease_until <= now())
  ), ranked as (
    select d.id, coalesce(h.n, 0) + row_number() over (partition by d.b order by d.created_at, d.id) as nth
      from due d left join private.hits h on h.bucket = d.b and h.window_start = ws
  )
  update tournament_invites i
     set send = false,
         send_error = 'not sent: this address already had 10 invitations from you today; send it again tomorrow'
    from ranked r
   where r.id = i.id and r.nth > 10;

  with picked as (
    select i.id from tournament_invites i
     where i.status = 'pending' and i.send and i.sent_at is null
       and (i.mail_lease_until is null or i.mail_lease_until <= now())
     order by i.created_at
     limit n
     for update skip locked
  ), held as (
    update tournament_invites i set mail_lease_until = now() + interval '2 minutes'
      from picked where i.id = picked.id
    returning i.*
  )
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', h.id, 'to', h.email, 'name', h.name, 'note', h.note, 'token', h.token, 'language', t.language,
           -- Which send this is: the API puts it in Resend's idempotency key,
           -- so a resend is never mistaken for a retry of the last send.
           'resend', h.resends > 0, 'resends', h.resends,
           'tournament', jsonb_build_object('id', t.id, 'slug', t.slug, 'title', t.title, 'starts_at', t.starts_at,
                                            'game', t.game, 'variant', t.variant, 'format', t.format,
                                            'clock', jsonb_build_object('base_s', t.clock_base_s, 'inc_s', t.clock_increment_s)),
           'org', case when o.id is null then null else
                  jsonb_build_object('slug', o.slug, 'name', o.name, 'website', o.website, 'support_email', o.support_email,
                                     'timezone', o.timezone, 'logo_url', o.brand ->> 'logo_url', 'plan', o.plan) end,
           -- Where "I'm in" goes when not the hosted page (F4): a page the
           -- embed was seen on lately, but only on an https origin the
           -- organiser put on its own list - checked against the list as it
           -- is now, not the row's `allowed` - and only with a plain path.
           -- An empty list, the default, means the hosted page: the ping that
           -- recorded a sighting is unauthenticated and could name anyone's
           -- site, and an invitation from Ocheso's own sender must never
           -- send someone to a page that asks for their sign-in code.
           'install', (select jsonb_build_object('origin', ins.origin, 'path', ins.last_path) from org_installs ins
                        where ins.org_id = o.id and ins.origin ~ '^https://'
                          and private.origin_listed(o.allowed_origins, ins.origin)
                          and private.plain_path(ins.last_path) is not null
                          and ins.last_seen_at > now() - interval '30 days'
                        order by ins.last_seen_at desc limit 1),
           'invited_by', (select display_name from profiles where id = h.invited_by))), '[]'::jsonb)
    into invs
    from held h join tournaments t on t.id = h.tournament_id left join organizations o on o.id = t.org_id;

  with picked as (
    select m.id from private.mail_outbox m
     where m.sent_at is null and m.attempts < 3 and (m.lease_until is null or m.lease_until <= now())
     order by m.created_at
     limit n
     for update skip locked
  ), held as (
    update private.mail_outbox m set lease_until = now() + interval '2 minutes'
      from picked where m.id = picked.id
    returning m.*
  )
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', h.id, 'kind', h.kind,
           'to', coalesce(h.to_email, (select lower(u.email) from auth.users u where u.id = h.to_user)),
           'data', h.data,
           -- The timezone too: "New start: Fri 19:00" means the organiser's 19:00.
           'org', (select jsonb_build_object('slug', o.slug, 'name', o.name, 'support_email', o.support_email,
                                             'timezone', o.timezone)
                     from organizations o where o.id = h.org_id))), '[]'::jsonb)
    into mail
    from held h;

  return jsonb_build_object('invites', invs, 'outbox', mail);
end $$;

-- sys-mail-done {invites: [{id, ok, error?}], outbox: [{id, ok, error?}], bounces?: [email]}
create or replace function private.sys_mail_done(body jsonb)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  r   jsonb;
  n   int := 0;
  inv tournament_invites;
begin
  for r in select * from jsonb_array_elements(coalesce(body -> 'invites', '[]'::jsonb)) loop
    update tournament_invites
       set sent_at = case when (r ->> 'ok')::boolean then now() end,
           send = (r ->> 'ok')::boolean,
           send_error = case when (r ->> 'ok')::boolean then null else left(coalesce(r ->> 'error', 'not sent'), 300) end,
           mail_lease_until = null
     where id = (r ->> 'id')::uuid
    returning * into inv;
    -- Delivered: one more for the sender's daily cap on this address.
    if found and (r ->> 'ok')::boolean then
      insert into private.hits as h (bucket, window_start, n)
      select private.invite_mail_bucket(coalesce(t.org_id, t.owner_id), inv.email),
             to_timestamp(floor(extract(epoch from now()) / 86400) * 86400), 1
        from tournaments t where t.id = inv.tournament_id
      on conflict (bucket, window_start) do update set n = h.n + 1;
    end if;
    n := n + 1;
  end loop;
  for r in select * from jsonb_array_elements(coalesce(body -> 'outbox', '[]'::jsonb)) loop
    update private.mail_outbox
       set sent_at = case when (r ->> 'ok')::boolean then now() end,
           attempts = attempts + 1,
           send_error = case when (r ->> 'ok')::boolean then null else left(coalesce(r ->> 'error', 'not sent'), 300) end,
           lease_until = null
     where id = (r ->> 'id')::bigint;
    n := n + 1;
  end loop;
  insert into private.email_suppressions (email, reason)
  select lower(btrim(x)), 'bounce' from jsonb_array_elements_text(coalesce(body -> 'bounces', '[]'::jsonb)) x
  on conflict (email) do nothing;
  return jsonb_build_object('done', n);
end $$;

revoke all on function private.autopilot_candidates() from public, anon, authenticated;
revoke all on function private.expired_games(int) from public, anon, authenticated;
revoke all on function private.series_due() from public, anon, authenticated;
revoke all on function private.mail_due() from public, anon, authenticated;
revoke all on function private.mail_kick_ok() from public, anon, authenticated;
revoke all on function private.autopilot_due() from public, anon, authenticated;
revoke all on function private.autopilot_snapshot(uuid, uuid, text[]) from public, anon, authenticated;
revoke all on function private.lease_check(uuid, uuid) from public, anon, authenticated;
revoke all on function private.sys_work(jsonb) from public, anon, authenticated;
revoke all on function private.sys_status(jsonb) from public, anon, authenticated;
revoke all on function private.sys_postpone(jsonb) from public, anon, authenticated;
revoke all on function private.sys_release(jsonb) from public, anon, authenticated;
revoke all on function private.sys_mail_batch(jsonb) from public, anon, authenticated;
revoke all on function private.sys_mail_done(jsonb) from public, anon, authenticated;

-- The dispatcher for the autopilot's own tick (D4). Round and game changes go
-- through the same rules as everyone's (private.do_*), as the system.
create or replace function public.system_call(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, p_payload::jsonb ->> 'kind');
  k    text := body ->> 'kind';
  r    rounds;
  made tournaments;
  res  jsonb;
begin
  case k
    when 'sys-work' then
      return private.sys_work(body);
    -- {lease, tournament, round (null for arena), start, games}
    when 'sys-pairings' then
      perform private.lease_check((body ->> 'tournament')::uuid, (body ->> 'lease')::uuid);
      select coalesce(jsonb_agg(to_jsonb(g)), '[]'::jsonb) into res
        from private.do_publish(body - 'lease', null, true, null) g;
      update private.autopilot_state set last_action = 'pairings', last_action_at = now()
       where tournament_id = (body ->> 'tournament')::uuid;
      return res;
    -- {lease, tournament, round (the round's id)}
    when 'sys-start-round' then
      perform private.lease_check((body ->> 'tournament')::uuid, (body ->> 'lease')::uuid);
      select * into r from rounds where id = (body ->> 'round')::uuid;
      if r.tournament_id is distinct from (body ->> 'tournament')::uuid then
        raise exception 'no such round' using errcode = 'no_data_found';
      end if;
      r := private.do_start_round(r.id, true);
      update private.autopilot_state set last_action = 'start-round', last_action_at = now()
       where tournament_id = r.tournament_id;
      return to_jsonb(r);
    -- {game, ply, result}: any tournament; no lease, the clock is the proof.
    when 'sys-flag' then
      return to_jsonb(private.do_flag(body, null, true, null));
    when 'sys-status' then
      return private.sys_status(body);
    when 'sys-postpone' then
      return private.sys_postpone(body);
    -- {series}: a failure is not an error here - it is recorded on the series
    -- and answered, so the tick can report it and move on.
    when 'sys-series' then
      made := private.series_next_safe((body ->> 'series')::uuid, 'sys-series');
      return jsonb_build_object('created', case when made.id is null then null else private.tournament_public_json(made) end,
                                'error', (select last_error from tournament_series where id = (body ->> 'series')::uuid));
    when 'sys-release' then
      return private.sys_release(body);
    when 'sys-mail-batch' then
      return private.sys_mail_batch(body);
    when 'sys-mail-done' then
      return private.sys_mail_done(body);
    else
      raise exception 'that request is for something else' using errcode = '28000';
  end case;
end $$;

-- Every 10 seconds, from pg_cron: poke the API when there is work. Returns
-- early - most of the time - when the feature is off, no URL is set, nothing
-- is due, or the last poke (under 55 s ago) has not been answered yet. The
-- body is signed with the tick key over exactly the bytes pg_net sends
-- (jsonb's text form), and the API checks it and the timestamp before
-- touching anything. The advisory lock is transaction-scoped: two cron runs
-- overlapping never both poke.
create or replace function private.autopilot_kick()
returns bigint language plpgsql security definer set search_path = public, extensions as $$
declare
  cfg  private.platform_settings;
  b    jsonb;
  req  bigint;
begin
  if not pg_try_advisory_xact_lock(hashtext('ocheso:autopilot-kick')) then
    return null;
  end if;
  select * into cfg from private.platform_settings;
  if not coalesce(cfg.autopilot_enabled, false) or cfg.api_tick_url is null then
    return null;
  end if;
  if exists (select 1 from private.kicks k
              where k.at > now() - interval '55 seconds'
                and not exists (select 1 from net._http_response r where r.id = k.request_id)) then
    return null;
  end if;
  if not private.autopilot_due() then
    return null;
  end if;
  b := jsonb_build_object('kind', 'tick', 'ts', extract(epoch from now())::bigint,
                          'nonce', encode(extensions.gen_random_bytes(12), 'hex'));
  req := net.http_post(
    url := cfg.api_tick_url,
    body := b,
    headers := jsonb_build_object('Content-Type', 'application/json',
                                  'X-Ocheso-Tick', encode(extensions.hmac(b::text, private.derived_key('ocheso:v1:tick'), 'sha256'), 'hex')),
    timeout_milliseconds := 60000);
  insert into private.kicks (request_id) values (req);
  return req;
end $$;
revoke all on function private.autopilot_kick() from public, anon, authenticated;

-- For Studio's autopilot card (D1 /v1/tournaments/{slug}/autopilot): what it
-- last did, what it is waiting for. Managers only.
create or replace function public.get_autopilot(p_tournament uuid)
returns jsonb language sql stable security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'enabled', t.autopilot, 'note', t.autopilot_note, 'status', t.status, 'starts_at', t.starts_at,
    'min_players', t.min_players, 'round_break_s', t.round_break_s, 'short_field', t.short_field,
    'approved', (select count(*) from participants p where p.tournament_id = t.id and p.status = 'approved'),
    'state', (select to_jsonb(st) - 'lease_id' - 'lease_until' from private.autopilot_state st where st.tournament_id = t.id),
    'due', (select to_jsonb(c.reasons) from private.autopilot_candidates() c where c.tournament_id = t.id),
    'platform_enabled', coalesce((select autopilot_enabled from private.platform_settings), false))
  from tournaments t where t.id = p_tournament and private.is_tournament_manager(t.id);
$$;

-- Studio's autopilot buttons that need the database: pause, resume, and
-- "+N min break" (hold), or lifting a hold. Starting and pairing now are the
-- manager's own actions (set_tournament_status, publish_pairings).
create or replace function public.autopilot_control(p_tournament uuid, p_action text, p_minutes int default 5)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
begin
  if not private.is_tournament_manager(p_tournament) then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  case p_action
    when 'pause' then
      update tournaments set autopilot = false where id = p_tournament;
    when 'resume' then
      update tournaments set autopilot = true where id = p_tournament;
    when 'extend-break' then
      insert into private.autopilot_state as st (tournament_id, hold_until)
      values (p_tournament, now() + make_interval(mins => least(greatest(p_minutes, 1), 120)))
      on conflict (tournament_id) do update
        set hold_until = greatest(coalesce(st.hold_until, now()), now()) + make_interval(mins => least(greatest(p_minutes, 1), 120));
    when 'clear-hold' then
      update private.autopilot_state set hold_until = null, next_check_at = null where tournament_id = p_tournament;
    else
      raise exception 'unknown autopilot action' using errcode = 'invalid_parameter_value';
  end case;
  return public.get_autopilot(p_tournament);
end $$;

-- =============================================================================
-- Triggers: the live feed (C7) and webhook events (C9)
-- =============================================================================
-- One set of triggers feeds both. Webhook events are rows in an outbox,
-- written in the same transaction as the change: they cannot be lost, and a
-- change that rolls back takes its events with it. Broadcasts are best effort:
-- a failure there must never fail a move, so each statement's sends sit in
-- one exception block - one, not one per row, because a block is a
-- subtransaction and a round of 2,000 games must not open 2,000 of them.

-- Tournaments: a topic for each new one; feed and events for what changes.
create or replace function private.on_tournament_insert()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
begin
  insert into private.live_topics (kind, ref) values ('t', new.id) on conflict do nothing;
  perform private.emit(new.id, 'tournament.created', private.tournament_hook(new));
  return null;
end $$;

-- The feed revision moves with the fields embeds show, in the same update.
create or replace function private.on_tournament_rev()
returns trigger language plpgsql as $$
begin
  if new.status is distinct from old.status or new.starts_at is distinct from old.starts_at
     or new.autopilot_note is distinct from old.autopilot_note then
    new.embed_rev := old.embed_rev + 1;
  end if;
  return new;
end $$;

create or replace function private.on_tournament_update()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  ev text;
begin
  if new.status is distinct from old.status or new.starts_at is distinct from old.starts_at
     or new.autopilot_note is distinct from old.autopilot_note then
    begin
      perform private.live_send('t', new.id, 'tournament',
                                jsonb_build_object('status', new.status, 'starts_at', new.starts_at,
                                                   'note', new.autopilot_note, 'rev', new.embed_rev));
    exception when others then
      null;
    end;
  end if;

  if new.status is distinct from old.status then
    -- Started, finished or cancelled: pending invites lapse and give their
    -- seats back (C5).
    if new.status in ('live', 'finished', 'archived') then
      update tournament_invites set status = 'lapsed', mail_lease_until = null
       where tournament_id = new.id and status = 'pending';
    end if;
    -- A series always has its next instance waiting once this one is under
    -- way - but making it must never stop this one starting (series_next_safe).
    if new.status = 'live' and new.series_id is not null then
      perform private.series_next_safe(new.series_id, 'instance-start');
    end if;
    ev := case
            when old.status = 'draft' and new.status = 'registration' then 'tournament.published'
            when new.status = 'live' then 'tournament.started'
            when new.status = 'finished' then 'tournament.finished'
            when new.status = 'archived' then 'tournament.archived'
            else 'tournament.updated'
          end;
    perform private.emit(new.id, ev, private.tournament_hook(new));
  elsif (new.title, new.description, new.starts_at, new.clock_base_s, new.clock_increment_s, new.rounds_count,
         new.arena_minutes, new.max_participants, new.is_listed, new.participants_visible, new.games_watchable,
         new.requires_code, new.auto_approve, new.identity_mode, new.invite_only, new.org_listed, new.rated,
         new.autopilot, new.min_players, new.round_break_s, new.language)
        is distinct from
        (old.title, old.description, old.starts_at, old.clock_base_s, old.clock_increment_s, old.rounds_count,
         old.arena_minutes, old.max_participants, old.is_listed, old.participants_visible, old.games_watchable,
         old.requires_code, old.auto_approve, old.identity_mode, old.invite_only, old.org_listed, old.rated,
         old.autopilot, old.min_players, old.round_break_s, old.language) then
    perform private.emit(new.id, 'tournament.updated', private.tournament_hook(new));
  end if;
  return null;
end $$;

drop trigger if exists tournaments_live_insert on public.tournaments;
create trigger tournaments_live_insert after insert on public.tournaments
  for each row execute function private.on_tournament_insert();
drop trigger if exists tournaments_rev on public.tournaments;
create trigger tournaments_rev before update on public.tournaments
  for each row execute function private.on_tournament_rev();
drop trigger if exists tournaments_live_update on public.tournaments;
create trigger tournaments_live_update after update on public.tournaments
  for each row execute function private.on_tournament_update();

-- Rounds: one row per statement in practice (publish, start, close).
create or replace function private.on_round_change()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  rev bigint;
  ev  text;
begin
  ev := case when tg_op = 'INSERT' then 'round.published'
             when new.status = 'live' and old.status is distinct from 'live' then 'round.started'
             when new.status = 'finished' and old.status is distinct from 'finished' then 'round.finished' end;
  if ev is not null then
    perform private.emit(new.tournament_id, ev,
                         jsonb_build_object('tournament', (select jsonb_build_object('id', t.id, 'slug', t.slug)
                                                             from tournaments t where t.id = new.tournament_id),
                                            'round', jsonb_build_object('number', new.number, 'status', new.status)));
  end if;
  begin
    rev := private.bump_rev(new.tournament_id);
    perform private.live_send('t', new.tournament_id, 'round',
                              jsonb_build_object('number', new.number, 'status', new.status, 'rev', rev));
  exception when others then
    null;
  end;
  return null;
end $$;

drop trigger if exists rounds_live on public.rounds;
create trigger rounds_live after insert or update of status on public.rounds
  for each row execute function private.on_round_change();

-- Games inserted: many at once when a round is published.
create or replace function private.on_games_insert()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  gr  public.games;
  g   record;
  rev bigint;
begin
  insert into private.live_topics (kind, ref) select 'g', id from new_games on conflict do nothing;
  if private.hooks_on() then
    for gr in select * from new_games where status = 'live' loop
      perform private.emit(gr.tournament_id, 'game.started', private.game_hook(gr));
    end loop;
  end if;
  -- One game is an arena pairing and news on the tournament feed; a round's
  -- worth is announced by its round event.
  if (select count(*) from new_games) = 1 then
    begin
      select to_jsonb(n) as gj, n.tournament_id into g from new_games n;
      rev := private.bump_rev(g.tournament_id);
      perform private.live_send('t', g.tournament_id, 'game', private.feed_game(g.gj, rev));
    exception when others then
      null;
    end;
  end if;
  return null;
end $$;

-- Games updated: every move (state to the game's topic), and status changes
-- (to the tournament feed, and as events).
create or replace function private.on_games_update()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  gr   public.games;
  c    record;
  revs jsonb := '{}'::jsonb;
begin
  if private.hooks_on() then
    for gr in select n.* from new_games n join old_games o on o.id = n.id
               where n.status is distinct from o.status and n.status in ('live', 'finished') loop
      perform private.emit(gr.tournament_id, case when gr.status = 'live' then 'game.started' else 'game.finished' end,
                           private.game_hook(gr));
    end loop;
  end if;
  begin
    for c in select distinct n.tournament_id from new_games n join old_games o on o.id = n.id
              where n.status is distinct from o.status loop
      revs := revs || jsonb_build_object(c.tournament_id::text, private.bump_rev(c.tournament_id));
    end loop;
    for c in select to_jsonb(n) as gj, n.id, n.tournament_id, n.status is distinct from o.status as moved_on
               from new_games n join old_games o on o.id = n.id
              where n.ply <> o.ply or n.status is distinct from o.status or n.draw_offer is distinct from o.draw_offer loop
      perform private.live_send('g', c.id, 'state', private.game_state(c.gj));
      if c.moved_on then
        perform private.live_send('t', c.tournament_id, 'game',
                                  private.feed_game(c.gj, (revs ->> c.tournament_id::text)::bigint));
      end if;
    end loop;
  exception when others then
    null;
  end;
  return null;
end $$;

drop trigger if exists games_live_insert on public.games;
create trigger games_live_insert after insert on public.games
  referencing new table as new_games for each statement execute function private.on_games_insert();
drop trigger if exists games_live_update on public.games;
create trigger games_live_update after update on public.games
  referencing old table as old_games new table as new_games for each statement execute function private.on_games_update();

-- Entries: the count on the feed, and an event per changed entry.
create or replace function private.on_participants_change()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  c   public.participants;
  ids uuid[];
  tid uuid;
  rev bigint;
begin
  -- Each statement's transition tables exist only for its own event, so each
  -- branch names only its own.
  if tg_op = 'INSERT' then
    if private.hooks_on() then
      for c in select * from new_rows loop
        perform private.emit(c.tournament_id, 'participant.joined', private.participant_hook(c));
      end loop;
    end if;
    select array_agg(distinct tournament_id) into ids from new_rows;
  elsif tg_op = 'UPDATE' then
    if private.hooks_on() then
      for c in select n.* from new_rows n join old_rows o on o.id = n.id where n.status is distinct from o.status loop
        perform private.emit(c.tournament_id,
                             case c.status when 'approved' then 'participant.approved' when 'rejected' then 'participant.rejected'
                                           when 'withdrawn' then 'participant.withdrawn' else 'participant.joined' end,
                             private.participant_hook(c));
      end loop;
    end if;
    select array_agg(distinct n.tournament_id) into ids
      from new_rows n join old_rows o on o.id = n.id where n.status is distinct from o.status;
  else
    if private.hooks_on() then
      for c in select * from old_rows loop
        perform private.emit(c.tournament_id, 'participant.removed', private.participant_hook(c));
      end loop;
    end if;
    select array_agg(distinct tournament_id) into ids from old_rows;
  end if;

  begin
    foreach tid in array coalesce(ids, '{}') loop
      rev := private.bump_rev(tid);
      perform private.live_send('t', tid, 'entries',
                                jsonb_build_object('count', (select count(*) from participants
                                                              where tournament_id = tid and status = 'approved'),
                                                   'rev', rev));
    end loop;
  exception when others then
    null;
  end;
  return null;
end $$;

drop trigger if exists participants_live_insert on public.participants;
create trigger participants_live_insert after insert on public.participants
  referencing new table as new_rows for each statement execute function private.on_participants_change();
drop trigger if exists participants_live_update on public.participants;
create trigger participants_live_update after update on public.participants
  referencing old table as old_rows new table as new_rows for each statement execute function private.on_participants_change();
drop trigger if exists participants_live_delete on public.participants;
create trigger participants_live_delete after delete on public.participants
  referencing old table as old_rows for each statement execute function private.on_participants_change();

-- Invites claimed, declined or lapsed: events, never broadcasts (an address
-- is the organiser's to know, not a page's).
create or replace function private.on_invites_update()
returns trigger language plpgsql security definer set search_path = public, extensions as $$
declare
  c record;
begin
  if not private.hooks_on() then
    return null;
  end if;
  for c in select n.* from new_rows n join old_rows o on o.id = n.id
            where n.status is distinct from o.status and n.status in ('claimed', 'declined', 'lapsed') loop
    perform private.emit(c.tournament_id, 'invite.' || c.status,
                         jsonb_build_object('tournament', (select jsonb_build_object('id', t.id, 'slug', t.slug)
                                                             from tournaments t where t.id = c.tournament_id),
                                            'invite', jsonb_build_object('id', c.id, 'email', c.email, 'name', c.name,
                                                                         'status', c.status, 'profile_id', c.claimed_by)));
  end loop;
  return null;
end $$;

drop trigger if exists tournament_invites_events on public.tournament_invites;
create trigger tournament_invites_events after update on public.tournament_invites
  referencing old table as old_rows new table as new_rows for each statement execute function private.on_invites_update();

revoke all on function private.on_tournament_insert() from public, anon, authenticated;
revoke all on function private.on_tournament_rev() from public, anon, authenticated;
revoke all on function private.on_tournament_update() from public, anon, authenticated;
revoke all on function private.on_round_change() from public, anon, authenticated;
revoke all on function private.on_games_insert() from public, anon, authenticated;
revoke all on function private.on_games_update() from public, anon, authenticated;
revoke all on function private.on_participants_change() from public, anon, authenticated;
revoke all on function private.on_invites_update() from public, anon, authenticated;

-- Topics for everything made before this file, so old events stream too.
insert into private.live_topics (kind, ref) select 't', id from public.tournaments on conflict do nothing;
insert into private.live_topics (kind, ref) select 'g', id from public.games where status <> 'finished' on conflict do nothing;

-- Realtime Authorization (C7): anyone may read a private broadcast on a
-- live: topic - holding the 128-bit topic is the permission - and nobody may
-- send one: there is no insert policy, so only the database's own
-- realtime.send() (as its owner) writes here. Guarded, because a database
-- without Realtime has no realtime.messages.
do $$
begin
  if to_regclass('realtime.messages') is not null then
    execute 'drop policy if exists ocheso_live_read on realtime.messages';
    execute $p$create policy ocheso_live_read on realtime.messages for select to anon, authenticated
               using (extension = 'broadcast' and realtime.topic() ~ '^live:[tg]:[0-9a-f]{32}$')$p$;
  end if;
end $$;

-- =============================================================================
-- Webhooks (C9)
-- =============================================================================

-- A new URL, or switching an endpoint back on, starts it with a clean slate.
create or replace function private.on_webhook_update()
returns trigger language plpgsql as $$
begin
  if new.url is distinct from old.url or (new.active and not old.active) then
    new.consecutive_failures := 0;
    new.first_failure_at := null;
    new.disabled_at := null;
    new.disabled_reason := null;
  end if;
  new.updated_at := now();
  return new;
end $$;
revoke all on function private.on_webhook_update() from public, anon, authenticated;

drop trigger if exists org_webhooks_update on public.org_webhooks;
create trigger org_webhooks_update before update on public.org_webhooks
  for each row execute function private.on_webhook_update();

create or replace function private.new_webhook_secret()
returns text language sql volatile as $$
  select 'whsec_' || encode(extensions.gen_random_bytes(24), 'base64');
$$;
revoke all on function private.new_webhook_secret() from public, anon, authenticated;

-- An endpoint and its secret, shown here once. Owners and admins, within the
-- plan's count (community has none).
create or replace function public.create_webhook(p_org uuid, p_url text, p_events text[] default '{}',
                                                 p_description text default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  o      organizations;
  w      org_webhooks;
  secret text := private.new_webhook_secret();
begin
  if not private.is_org_admin(p_org) then
    raise exception 'no such organisation' using errcode = 'no_data_found';
  end if;
  select * into o from organizations where id = p_org;
  if (select count(*) from org_webhooks where org_id = p_org) >= private.plan_limit(o.plan, 'webhooks') then
    raise exception 'the % plan allows % webhook endpoints', o.plan, private.plan_limit(o.plan, 'webhooks')
      using errcode = 'check_violation';
  end if;
  if not private.webhook_url_ok(p_url) then
    raise exception 'webhooks go to a public https address on port 443' using errcode = 'check_violation';
  end if;
  insert into org_webhooks (org_id, url, events, description, created_by)
  values (p_org, p_url, coalesce(p_events, '{}'), nullif(btrim(p_description), ''), auth.uid())
  returning * into w;
  insert into private.webhook_secrets (webhook_id, current) values (w.id, secret);
  return to_jsonb(w) || jsonb_build_object('secret', secret);
end $$;

-- A new secret; the old one keeps signing alongside it for 24 hours.
create or replace function public.rotate_webhook_secret(p_webhook uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  secret text := private.new_webhook_secret();
begin
  if not exists (select 1 from org_webhooks w where w.id = p_webhook and private.is_org_admin(w.org_id)) then
    raise exception 'no such webhook' using errcode = 'no_data_found';
  end if;
  update private.webhook_secrets
     set previous = current, current = secret, rotated_at = now()
   where webhook_id = p_webhook;
  return jsonb_build_object('secret', secret, 'previous_valid_until', now() + interval '24 hours');
end $$;

-- A webhook.test to this endpoint only, whatever events it subscribes to.
create or replace function public.send_test_webhook(p_webhook uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  w org_webhooks;
  d uuid;
begin
  select * into w from org_webhooks where id = p_webhook and private.is_org_admin(org_id);
  if not found then
    raise exception 'no such webhook' using errcode = 'no_data_found';
  end if;
  perform private.throttle('webhook-test:' || w.id, 30, 3600);
  perform private.emit_org(w.org_id, 'webhook.test',
                           jsonb_build_object('webhook', w.id, 'org', (select slug from organizations where id = w.org_id)),
                           w.id);
  select id into d from private.webhook_outbox where webhook_id = w.id and event = 'webhook.test'
   order by created_at desc limit 1;
  return jsonb_build_object('delivery', d, 'queued', true,
                            'webhooks_enabled', private.hooks_on());
end $$;

-- The last deliveries to an endpoint, for Studio. Never a response body:
-- none is stored.
create or replace function public.webhook_deliveries(p_webhook uuid, p_limit int default 20)
returns table (id uuid, event text, status text, attempts int, next_attempt_at timestamptz,
               response_status int, last_error text, created_at timestamptz, last_attempt_at timestamptz,
               delivered_at timestamptz)
language sql stable security definer set search_path = public, extensions as $$
  select d.id, d.event, d.status, d.attempts, d.next_attempt_at, d.response_status, d.last_error, d.created_at,
         d.last_attempt_at, d.delivered_at
    from private.webhook_outbox d join org_webhooks w on w.id = d.webhook_id
   where d.webhook_id = p_webhook and private.is_org_admin(w.org_id)
   order by d.created_at desc
   limit least(greatest(coalesce(p_limit, 20), 1), 100);
$$;

-- Try a delivery again now: one more attempt - if it fails too, it stays failed.
create or replace function public.retry_delivery(p_delivery uuid)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  d private.webhook_outbox;
begin
  select o.* into d from private.webhook_outbox o join org_webhooks w on w.id = o.webhook_id
   where o.id = p_delivery and private.is_org_admin(w.org_id)
   for update of o;
  if not found then
    raise exception 'no such delivery' using errcode = 'no_data_found';
  end if;
  if d.status = 'sending' then
    raise exception 'that delivery is on its way' using errcode = 'check_violation';
  end if;
  update private.webhook_outbox
     set status = 'pending', next_attempt_at = now(), attempts = least(attempts, 7)
   where id = d.id
  returning * into d;
  return jsonb_build_object('id', d.id, 'status', d.status, 'attempts', d.attempts, 'next_attempt_at', d.next_attempt_at);
end $$;

-- 30 s, 2 min, 10 min, 30 min, 2 h, 6 h, 12 h, 24 h, each ±10% so a recovering
-- receiver is not hit by every retry at once.
create or replace function private.webhook_backoff(p_attempts int)
returns interval language sql volatile as $$
  select (array[interval '30 seconds', interval '2 minutes', interval '10 minutes', interval '30 minutes',
                interval '2 hours', interval '6 hours', interval '12 hours', interval '24 hours'])
           [least(greatest(p_attempts, 1), 8)] * (0.9 + random() * 0.2);
$$;
revoke all on function private.webhook_backoff(int) from public, anon, authenticated;

-- One delivery's answer. Success clears the endpoint's failure count; a
-- failure schedules the next attempt (failed after 8), and an endpoint that
-- has failed for 3 days or 200 times running is switched off and its admins
-- are told.
create or replace function private.webhook_result(p_delivery uuid, p_status int, p_error text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  d  private.webhook_outbox;
  w  org_webhooks;
  why text;
begin
  select * into d from private.webhook_outbox where id = p_delivery;
  if p_status between 200 and 299 then
    update private.webhook_outbox
       set status = 'delivered', response_status = p_status, delivered_at = now(), last_error = null
     where id = d.id;
    update org_webhooks set consecutive_failures = 0, first_failure_at = null
     where id = d.webhook_id and consecutive_failures > 0;
    return;
  end if;
  -- What Studio shows (webhook_deliveries): the HTTP status, or for no
  -- response at all just "unreachable". pg_net's own words - connection
  -- refused, timed out, a TLS failure - would tell an org admin who pointed a
  -- webhook at a name resolving into our network which ports answer there.
  update private.webhook_outbox
     set status = case when attempts >= 8 then 'failed' else 'pending' end,
         response_status = p_status,
         last_error = case when p_status is not null then 'HTTP ' || p_status else 'unreachable' end,
         next_attempt_at = now() + private.webhook_backoff(attempts)
   where id = d.id;
  update org_webhooks
     set consecutive_failures = consecutive_failures + 1, first_failure_at = coalesce(first_failure_at, now())
   where id = d.webhook_id
  returning * into w;
  if w.disabled_at is null and (w.consecutive_failures >= 200 or w.first_failure_at < now() - interval '3 days') then
    why := case when w.consecutive_failures >= 200 then '200 deliveries in a row failed'
                else 'deliveries have failed for 3 days' end;
    update org_webhooks set active = false, disabled_at = now(), disabled_reason = why where id = w.id;
    insert into private.mail_outbox (kind, to_user, org_id, data)
    select 'webhook-disabled', m.user_id, w.org_id, jsonb_build_object('webhook', w.id, 'url', w.url, 'reason', why)
      from org_members m where m.org_id = w.org_id and m.role in ('owner', 'admin');
  end if;
end $$;
revoke all on function private.webhook_result(uuid, int, text) from public, anon, authenticated;

-- Standard Webhooks: v1,<base64 hmac_sha256(secret bytes, id.timestamp.body)>,
-- with the previous secret's signature beside it for a day after a rotation.
-- The body is the jsonb's text form - exactly the bytes pg_net sends.
create or replace function private.webhook_signature(p_secret text, p_msgid text, p_ts bigint, p_body text)
returns text language sql immutable as $$
  select 'v1,' || encode(extensions.hmac(convert_to(p_msgid || '.' || p_ts || '.' || p_body, 'UTF8'),
                                         decode(substr(p_secret, 7), 'base64'), 'sha256'), 'base64');
$$;
revoke all on function private.webhook_signature(text, text, bigint, text) from public, anon, authenticated;

-- Every 5 seconds, from pg_cron: collect what pg_net heard back, then send up
-- to 100 deliveries that are due.
create or replace function private.webhooks_pump()
returns int language plpgsql security definer set search_path = public, extensions as $$
declare
  d     record;
  n     int := 0;
  ts    bigint;
  msgid text;
  sig   text;
  req   bigint;
begin
  if not private.hooks_on() or not pg_try_advisory_xact_lock(hashtext('ocheso:webhooks-pump')) then
    return 0;
  end if;

  for d in
    select o.id, r.status_code, coalesce(r.error_msg, case when r.timed_out then 'timed out' end) as err
      from private.webhook_outbox o join net._http_response r on r.id = o.request_id
     where o.status = 'sending'
  loop
    perform private.webhook_result(d.id, d.status_code, d.err);
  end loop;
  -- Sent long ago with no answer filed at all: lost, not slow (10 s timeout).
  for d in
    select o.id from private.webhook_outbox o
     where o.status = 'sending' and o.last_attempt_at < now() - interval '5 minutes'
       and not exists (select 1 from net._http_response r where r.id = o.request_id)
  loop
    perform private.webhook_result(d.id, null, 'no response');
  end loop;

  for d in
    select o.id, o.payload, w.url, s.current, s.previous, s.rotated_at
      from private.webhook_outbox o
      join public.org_webhooks w on w.id = o.webhook_id
      join private.webhook_secrets s on s.webhook_id = w.id
     where o.status = 'pending' and o.next_attempt_at <= now()
       and ((w.active and w.disabled_at is null) or o.event = 'webhook.test')
     order by o.next_attempt_at
     limit 100
     for update of o skip locked
  loop
    ts := extract(epoch from now())::bigint;
    msgid := 'msg_' || replace(d.id::text, '-', '');
    sig := private.webhook_signature(d.current, msgid, ts, d.payload::text);
    if d.previous is not null and d.rotated_at > now() - interval '24 hours' then
      sig := sig || ' ' || private.webhook_signature(d.previous, msgid, ts, d.payload::text);
    end if;
    req := net.http_post(
      url := d.url,
      body := d.payload,
      headers := jsonb_build_object('Content-Type', 'application/json', 'User-Agent', 'Ocheso-Webhooks/1',
                                    'webhook-id', msgid, 'webhook-timestamp', ts::text, 'webhook-signature', sig),
      timeout_milliseconds := 10000);
    update private.webhook_outbox
       set status = 'sending', request_id = req, attempts = attempts + 1, last_attempt_at = now()
     where id = d.id;
    n := n + 1;
  end loop;
  return n;
end $$;
revoke all on function private.webhooks_pump() from public, anon, authenticated;

-- =============================================================================
-- Housekeeping
-- =============================================================================

-- Hourly: what has outlived its use (C10).
create or replace function private.gc()
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  res jsonb := '{}'::jsonb;
  c     int;
begin
  delete from private.hits where window_start < now() - interval '2 days';
  get diagnostics c = row_count; res := res || jsonb_build_object('hits', c);
  delete from private.player_tokens where expires_at < now() - interval '1 hour';
  get diagnostics c = row_count; res := res || jsonb_build_object('player_tokens', c);
  delete from private.embed_handoffs where created_at < now() - interval '1 day';
  get diagnostics c = row_count; res := res || jsonb_build_object('handoffs', c);
  delete from private.embed_sessions
   where expires_at < now() - interval '7 days' or revoked_at < now() - interval '7 days';
  get diagnostics c = row_count; res := res || jsonb_build_object('sessions', c);
  delete from private.kicks where at < now() - interval '1 day';
  delete from private.org_idempotency where created_at < now() - interval '24 hours';
  delete from private.webhook_outbox where status in ('delivered', 'failed') and created_at < now() - interval '30 days';
  delete from private.mail_outbox where sent_at < now() - interval '30 days' or created_at < now() - interval '90 days';
  delete from private.ops_log where at < now() - interval '90 days';
  delete from private.live_topics lt
   where (lt.kind = 'g' and not exists (select 1 from games g where g.id = lt.ref))
      or (lt.kind = 't' and not exists (select 1 from tournaments t where t.id = lt.ref));
  return res;
end $$;
revoke all on function private.gc() from public, anon, authenticated;

-- Daily: the rules profile_integrity enforces on every write, checked over
-- the whole table in case anything ever went around it (C4).
create or replace function private.audit_profiles()
returns int language plpgsql security definer set search_path = public, extensions as $$
declare
  n int;
begin
  insert into private.ops_log (source, message, detail)
  select 'profile-audit', 'account profile without an auth.users row', jsonb_build_object('profile', p.id)
    from profiles p where p.kind = 'account' and not exists (select 1 from auth.users u where u.id = p.id)
  union all
  select 'profile-audit', 'member profile sharing an auth.users id', jsonb_build_object('profile', p.id)
    from profiles p where p.kind = 'member' and exists (select 1 from auth.users u where u.id = p.id);
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function private.audit_profiles() from public, anon, authenticated;

-- The schedule, where pg_cron exists (as db/agents.sql). Scheduling is safe
-- with both features switched off: the kick and the pump return at once.
do $$
begin
  if exists (select 1 from pg_available_extensions where name = 'pg_cron') then
    create extension if not exists pg_cron with schema pg_catalog;
    perform cron.schedule('ocheso-autopilot', '10 seconds', 'select private.autopilot_kick()');
    perform cron.schedule('ocheso-webhooks', '5 seconds', 'select private.webhooks_pump()');
    perform cron.schedule('ocheso-platform-gc', '23 * * * *', 'select private.gc()');
    perform cron.schedule('ocheso-profile-audit', '41 3 * * *', 'select private.audit_profiles()');
    -- Ticks every few seconds leave thousands of run records a day; keep an hour.
    perform cron.schedule('ocheso-platform-tidy', '*/10 * * * *', $tidy$
      delete from cron.job_run_details
       where jobid in (select jobid from cron.job where jobname in ('ocheso-autopilot', 'ocheso-webhooks'))
         and end_time < now() - interval '1 hour'
    $tidy$);
  end if;
end $$;

-- =============================================================================
-- Row level security and grants
-- =============================================================================
alter table public.org_invites       enable row level security;
alter table public.org_keys          enable row level security;
alter table public.org_installs      enable row level security;
alter table public.tournament_series enable row level security;
alter table public.org_webhooks      enable row level security;

-- Staff invites, keys and webhooks: owners and admins. Installs and series:
-- the whole team (staff run events and embed them).
drop policy if exists org_invites_read on public.org_invites;
create policy org_invites_read on public.org_invites for select to authenticated using (private.is_org_admin(org_id));
drop policy if exists org_keys_read on public.org_keys;
create policy org_keys_read on public.org_keys for select to authenticated using (private.is_org_admin(org_id));
drop policy if exists org_keys_update on public.org_keys;
create policy org_keys_update on public.org_keys for update to authenticated
  using (private.is_org_admin(org_id)) with check (private.is_org_admin(org_id));
drop policy if exists org_installs_read on public.org_installs;
create policy org_installs_read on public.org_installs for select to authenticated using (private.org_role(org_id) is not null);
drop policy if exists tournament_series_read on public.tournament_series;
create policy tournament_series_read on public.tournament_series for select to authenticated using (private.org_role(org_id) is not null);
drop policy if exists org_webhooks_read on public.org_webhooks;
create policy org_webhooks_read on public.org_webhooks for select to authenticated using (private.is_org_admin(org_id));
drop policy if exists org_webhooks_update on public.org_webhooks;
create policy org_webhooks_update on public.org_webhooks for update to authenticated
  using (private.is_org_admin(org_id)) with check (private.is_org_admin(org_id));
drop policy if exists org_webhooks_delete on public.org_webhooks;
create policy org_webhooks_delete on public.org_webhooks for delete to authenticated using (private.is_org_admin(org_id));

revoke all on public.org_invites, public.org_keys, public.org_installs, public.tournament_series, public.org_webhooks
  from anon, authenticated;
grant select (id, org_id, email, role, status, invited_by, accepted_by, accepted_at, created_at)
  on public.org_invites to authenticated;
grant select (id, org_id, name, prefix, scopes, created_by, created_at, last_used_at, revoked_at)
  on public.org_keys to authenticated;
grant update (name) on public.org_keys to authenticated;
grant select on public.org_installs, public.tournament_series, public.org_webhooks to authenticated;
grant update (url, events, active, description) on public.org_webhooks to authenticated;
grant delete on public.org_webhooks to authenticated;

-- Signed-in only; each checks its caller.
revoke all on function public.add_invites(uuid, jsonb, boolean) from public, anon;
revoke all on function public.revoke_invite(uuid) from public, anon;
revoke all on function public.resend_invite(uuid) from public, anon;
revoke all on function public.claim_my_invites() from public, anon;
revoke all on function public.my_invites() from public, anon;
revoke all on function public.accept_invite(text) from public, anon;
revoke all on function public.decline_invite(text) from public, anon;
revoke all on function public.create_organization(text, text, text, jsonb, text[], text) from public, anon;
revoke all on function public.set_org_member_role(uuid, uuid, text) from public, anon;
revoke all on function public.remove_org_member(uuid, uuid) from public, anon;
revoke all on function public.leave_org(uuid) from public, anon;
revoke all on function public.transfer_org_ownership(uuid, uuid) from public, anon;
revoke all on function public.invite_org_member(uuid, text, text) from public, anon;
revoke all on function public.revoke_org_invite(uuid) from public, anon;
revoke all on function public.create_org_key(uuid, text, text[]) from public, anon;
revoke all on function public.revoke_org_key(uuid) from public, anon;
revoke all on function public.create_series(uuid, text, text, jsonb, int, time, text) from public, anon;
revoke all on function public.update_series(uuid, jsonb) from public, anon;
revoke all on function public.pause_series(uuid, boolean) from public, anon;
revoke all on function public.skip_series_date(uuid, date, boolean) from public, anon;
revoke all on function public.stop_series(uuid) from public, anon;
revoke all on function public.create_account_embed_session(text) from public, anon;
revoke all on function public.embed_handoff_bind(text) from public, anon;
revoke all on function public.list_my_embed_sessions() from public, anon;
revoke all on function public.revoke_my_embed_session(uuid) from public, anon;
revoke all on function public.create_webhook(uuid, text, text[], text) from public, anon;
revoke all on function public.rotate_webhook_secret(uuid) from public, anon;
revoke all on function public.send_test_webhook(uuid) from public, anon;
revoke all on function public.webhook_deliveries(uuid, int) from public, anon;
revoke all on function public.retry_delivery(uuid) from public, anon;
revoke all on function public.get_autopilot(uuid) from public, anon;
revoke all on function public.autopilot_control(uuid, text, int) from public, anon;
revoke all on function public.block_org_player(uuid, uuid, boolean) from public, anon;
revoke all on function public.get_org_usage(uuid) from public, anon;
grant execute on function public.add_invites(uuid, jsonb, boolean) to authenticated;
grant execute on function public.revoke_invite(uuid) to authenticated;
grant execute on function public.resend_invite(uuid) to authenticated;
grant execute on function public.claim_my_invites() to authenticated;
grant execute on function public.my_invites() to authenticated;
grant execute on function public.accept_invite(text) to authenticated;
grant execute on function public.decline_invite(text) to authenticated;
grant execute on function public.create_organization(text, text, text, jsonb, text[], text) to authenticated;
grant execute on function public.set_org_member_role(uuid, uuid, text) to authenticated;
grant execute on function public.remove_org_member(uuid, uuid) to authenticated;
grant execute on function public.leave_org(uuid) to authenticated;
grant execute on function public.transfer_org_ownership(uuid, uuid) to authenticated;
grant execute on function public.invite_org_member(uuid, text, text) to authenticated;
grant execute on function public.revoke_org_invite(uuid) to authenticated;
grant execute on function public.create_org_key(uuid, text, text[]) to authenticated;
grant execute on function public.revoke_org_key(uuid) to authenticated;
grant execute on function public.create_series(uuid, text, text, jsonb, int, time, text) to authenticated;
grant execute on function public.update_series(uuid, jsonb) to authenticated;
grant execute on function public.pause_series(uuid, boolean) to authenticated;
grant execute on function public.skip_series_date(uuid, date, boolean) to authenticated;
grant execute on function public.stop_series(uuid) to authenticated;
grant execute on function public.create_account_embed_session(text) to authenticated;
grant execute on function public.embed_handoff_bind(text) to authenticated;
grant execute on function public.list_my_embed_sessions() to authenticated;
grant execute on function public.revoke_my_embed_session(uuid) to authenticated;
grant execute on function public.create_webhook(uuid, text, text[], text) to authenticated;
grant execute on function public.rotate_webhook_secret(uuid) to authenticated;
grant execute on function public.send_test_webhook(uuid) to authenticated;
grant execute on function public.webhook_deliveries(uuid, int) to authenticated;
grant execute on function public.retry_delivery(uuid) to authenticated;
grant execute on function public.get_autopilot(uuid) to authenticated;
grant execute on function public.autopilot_control(uuid, text, int) to authenticated;
grant execute on function public.block_org_player(uuid, uuid, boolean) to authenticated;
grant execute on function public.get_org_usage(uuid) to authenticated;

-- Public reads: what embeds, hosted pages and the invite page show visitors.
revoke all on function public.get_people(uuid) from public;
revoke all on function public.get_live_topic(text) from public;
revoke all on function public.get_game_topic(uuid) from public;
revoke all on function public.get_embed_policy(text, text, uuid) from public;
revoke all on function public.get_org_public(text) from public;
revoke all on function public.get_org_schedule(text) from public;
revoke all on function public.get_series_current(text, text) from public;
revoke all on function public.get_invite_preview(text) from public;
grant execute on function public.get_people(uuid) to anon, authenticated;
grant execute on function public.get_live_topic(text) to anon, authenticated;
grant execute on function public.get_game_topic(uuid) to anon, authenticated;
grant execute on function public.get_embed_policy(text, text, uuid) to anon, authenticated;
grant execute on function public.get_org_public(text) to anon, authenticated;
grant execute on function public.get_org_schedule(text) to anon, authenticated;
grant execute on function public.get_series_current(text, text) to anon, authenticated;
grant execute on function public.get_invite_preview(text) to anon, authenticated;

-- The three dispatchers: called by the API as anon. The signature is the gate.
revoke all on function public.embed_call(text, text) from public;
revoke all on function public.org_call(text, text) from public;
revoke all on function public.system_call(text, text) from public;
grant execute on function public.embed_call(text, text) to anon, authenticated;
grant execute on function public.org_call(text, text) to anon, authenticated;
grant execute on function public.system_call(text, text) to anon, authenticated;
