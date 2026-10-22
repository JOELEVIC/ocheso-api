-- =============================================================================
-- Ocheso — agents: human-like opponents people build, hire and plug into their
-- own platforms
-- =============================================================================
-- Applied after db/schema.sql and db/play.sql, by hand, idempotent like them.
--
-- TWO KINDS OF CALLER.
--   * The owner, signed in on the site: builds agents, mints keys, reads usage.
--     Row level security, as everywhere else: every row here has an owner_id
--     and nobody else sees it.
--   * A platform the owner has given a key to (`och_...`): asks an agent for
--     its move. It has no Supabase account, so RLS cannot know it. Instead the
--     API checks the key and signs what it asks for with the referee's key
--     (db/play.sql), and the machine functions below accept only signed
--     requests, for a key that exists, is not revoked, and covers that agent.
--     Keys are made here, from random bytes, and only their SHA-256 is kept:
--     the key itself exists once, in the reply to the owner who made it.
--
-- WHAT THE API STILL CANNOT DO. It holds no service-role key. A persona reaches
-- the table only through save_agent(), which takes a persona the API validated
-- and signed for the signed-in owner; a client writing the table directly can
-- change an agent's name, notes and status, never its persona.
--
-- REALTIME. A platform that would rather not hold a request open while the
-- agent "thinks" opens a session with realtime on and listens on a broadcast
-- channel whose name is 128 random bits, returned only to the key holder. A
-- move already due is broadcast as it is recorded; a later one goes into an
-- outbox stamped with when a person would have played it, and a one-second
-- pg_cron tick broadcasts what is due. Anyone who learnt the
-- channel name could also post to it, so every payload is signed with the
-- session's own secret, which the SDK snippets verify.
-- =============================================================================

do $$ begin
  create type public.agent_status as enum ('draft', 'active', 'paused');
exception when duplicate_object then null; end $$;

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------
create table if not exists public.agents (
  id          uuid primary key default gen_random_uuid(),
  owner_id    uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  name        text not null check (char_length(btrim(name)) between 2 and 40),
  game        public.game_type not null default 'chess' check (game = 'chess'),
  -- The library entry it started from, and the agent it was copied from.
  archetype   text check (archetype ~ '^[A-Za-z0-9-]{2,40}$'),
  parent_id   uuid references public.agents (id) on delete set null,
  -- Persona v2 (agents/persona.py), exactly as the API parsed it.
  persona     jsonb not null check (jsonb_typeof(persona) = 'object'),
  rating      int generated always as ((persona ->> 'rating')::int) stored,
  status      public.agent_status not null default 'draft',
  notes       text not null default '' check (char_length(notes) <= 2000),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists agents_owner_idx on public.agents (owner_id);

create table if not exists public.agent_keys (
  id           uuid primary key default gen_random_uuid(),
  owner_id     uuid not null references public.profiles (id) on delete cascade,
  name         text not null check (char_length(btrim(name)) between 1 and 60),
  -- The first characters of the key, so a list can say which is which.
  prefix       text not null,
  -- SHA-256 of the whole key, hex. Never granted to any client role.
  hash         text not null unique check (hash ~ '^[0-9a-f]{64}$'),
  -- Which agents it may drive; null means all of the owner's.
  agent_ids    uuid[],
  created_at   timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at   timestamptz
);
create index if not exists agent_keys_owner_idx on public.agent_keys (owner_id);

-- One game an agent is playing on a platform: its mood carries from move to
-- move here, and so does the ply count that stops two moves being recorded
-- for one turn.
create table if not exists public.agent_sessions (
  id              uuid primary key default gen_random_uuid(),
  agent_id        uuid not null references public.agents (id) on delete cascade,
  owner_id        uuid not null references public.profiles (id) on delete cascade,
  key_id          uuid references public.agent_keys (id) on delete set null,
  external_ref    text check (char_length(external_ref) <= 120),
  color           text check (color in ('white', 'black')),
  cadence         text not null check (cadence ~ '^\d{1,3}\+\d{1,3}$'),
  opponent_rating int check (opponent_rating between 100 and 3500),
  realtime        boolean not null default false,
  channel         text not null unique default encode(extensions.gen_random_bytes(16), 'hex'),
  -- Signs realtime payloads. Never granted to any client role.
  secret          text not null default encode(extensions.gen_random_bytes(32), 'hex'),
  state           jsonb not null default '{}'::jsonb,
  plies           int not null default 0,
  status          text not null default 'live' check (status in ('live', 'finished')),
  result          text check (result in ('win', 'loss', 'draw', 'aborted')),
  started_at      timestamptz not null default now(),
  last_move_at    timestamptz,
  finished_at     timestamptz
);
create index if not exists agent_sessions_agent_idx on public.agent_sessions (agent_id, started_at desc);
create index if not exists agent_sessions_owner_idx on public.agent_sessions (owner_id, started_at desc);

-- Per agent per day. Difficulty readings belong to no agent: the nil uuid.
create table if not exists public.agent_usage (
  owner_id  uuid not null references public.profiles (id) on delete cascade,
  agent_id  uuid not null,
  day       date not null default current_date,
  moves     int not null default 0,
  sessions  int not null default 0,
  gauges    int not null default 0,
  primary key (owner_id, agent_id, day)
);

create table if not exists private.agent_outbox (
  id         bigserial primary key,
  topic      text not null,
  event      text not null,
  payload    jsonb not null,
  deliver_at timestamptz not null
);
create index if not exists agent_outbox_due_idx on private.agent_outbox (deliver_at);
revoke all on private.agent_outbox from public, anon, authenticated;

drop trigger if exists agents_touch on public.agents;
create trigger agents_touch before update on public.agents
  for each row execute function public.touch_updated_at();

-- -----------------------------------------------------------------------------
-- Helpers
-- -----------------------------------------------------------------------------
-- A request the API signed for a key holder: like private.ruling, without the
-- caller check (a platform has no auth.uid()); the key in it is checked next.
create or replace function private.machine_request(p_payload text, p_sig text, p_kind text)
returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare
  key  text;
  body jsonb;
begin
  select secret into key from private.referee;
  if p_sig is null or encode(extensions.hmac(p_payload, key, 'sha256'), 'hex') <> p_sig then
    raise exception 'the API did not sign this' using errcode = '28000';
  end if;
  body := p_payload::jsonb;
  if body ->> 'kind' is distinct from p_kind then
    raise exception 'that request is for something else' using errcode = '28000';
  end if;
  if (body ->> 'exp')::bigint < extract(epoch from now()) then
    raise exception 'that request has expired; try again' using errcode = '28000';
  end if;
  return body;
end $$;
revoke all on function private.machine_request(text, text, text) from public, anon, authenticated;

create or replace function private.key_by_hash(p_hash text)
returns public.agent_keys language plpgsql security definer set search_path = public, extensions as $$
declare k public.agent_keys;
begin
  select * into k from public.agent_keys where hash = p_hash;
  if not found then
    raise exception 'that key is not valid' using errcode = '28000';
  end if;
  if k.revoked_at is not null then
    raise exception 'that key was revoked' using errcode = '28000';
  end if;
  -- Written at most once a minute: a busy key would otherwise rewrite its row
  -- on every move.
  if k.last_used_at is null or k.last_used_at < now() - interval '1 minute' then
    update public.agent_keys set last_used_at = now() where id = k.id;
  end if;
  return k;
end $$;
revoke all on function private.key_by_hash(text) from public, anon, authenticated;

-- The agent a key may drive, playable now (or, to end a game, at all).
drop function if exists private.agent_for_key(public.agent_keys, uuid);
create or replace function private.agent_for_key(k public.agent_keys, p_agent uuid, p_playable boolean default true)
returns public.agents language plpgsql stable security definer set search_path = public as $$
declare a public.agents;
begin
  select * into a from public.agents where id = p_agent and owner_id = k.owner_id;
  if not found or (k.agent_ids is not null and not p_agent = any (k.agent_ids)) then
    raise exception 'this key cannot use that agent' using errcode = 'P0002';
  end if;
  if p_playable and a.status <> 'active' then
    raise exception 'that agent is %; activate it to play', a.status using errcode = '23514';
  end if;
  return a;
end $$;
revoke all on function private.agent_for_key(public.agent_keys, uuid, boolean) from public, anon, authenticated;

create or replace function private.count_usage(p_owner uuid, p_agent uuid, p_moves int, p_sessions int, p_gauges int)
returns void language sql security definer set search_path = public as $$
  insert into public.agent_usage as u (owner_id, agent_id, day, moves, sessions, gauges)
  values (p_owner, p_agent, current_date, p_moves, p_sessions, p_gauges)
  on conflict (owner_id, agent_id, day) do update
    set moves = u.moves + excluded.moves, sessions = u.sessions + excluded.sessions,
        gauges = u.gauges + excluded.gauges;
$$;
revoke all on function private.count_usage(uuid, uuid, int, int, int) from public, anon, authenticated;

create or replace function private.agent_json(a public.agents)
returns jsonb language sql immutable as $$
  select jsonb_build_object('id', a.id, 'name', a.name, 'game', a.game, 'rating', a.rating,
                            'status', a.status, 'persona', a.persona)
$$;

-- The session as the key holder sees it: with its secret, which signs its
-- realtime payloads, and its state.
create or replace function private.session_json(s public.agent_sessions)
returns jsonb language sql immutable as $$
  select jsonb_build_object('id', s.id, 'agent', s.agent_id, 'externalRef', s.external_ref, 'color', s.color,
                            'cadence', s.cadence, 'opponentRating', s.opponent_rating, 'realtime', s.realtime,
                            'channel', s.channel, 'secret', s.secret, 'state', s.state, 'plies', s.plies,
                            'status', s.status, 'result', s.result, 'startedAt', s.started_at)
$$;

create or replace function private.session_for_key(k public.agent_keys, p_session uuid)
returns public.agent_sessions language plpgsql security definer set search_path = public as $$
declare s public.agent_sessions;
begin
  select * into s from public.agent_sessions where id = p_session and owner_id = k.owner_id for update;
  if not found or (k.agent_ids is not null and not s.agent_id = any (k.agent_ids)) then
    raise exception 'no such session' using errcode = 'P0002';
  end if;
  return s;
end $$;
revoke all on function private.session_for_key(public.agent_keys, uuid) from public, anon, authenticated;

-- Broadcast a payload when it is due: now, if it already is (inside this
-- transaction, so it goes out on commit), or through the outbox, whose tick is
-- once a second - aimed half a tick early so it lands around `at`.
create or replace function private.agent_deliver(p_topic text, p_event text, p_payload jsonb, p_at_ms double precision)
returns void language plpgsql security definer set search_path = public as $$
declare at timestamptz := least(to_timestamp(p_at_ms / 1000), now() + interval '10 minutes');
begin
  if at <= now() + interval '500 milliseconds' then
    perform realtime.send(p_payload, p_event, p_topic, false);
  else
    insert into private.agent_outbox (topic, event, payload, deliver_at)
    values (p_topic, p_event, p_payload, at - interval '500 milliseconds');
  end if;
end $$;
revoke all on function private.agent_deliver(text, text, jsonb, double precision) from public, anon, authenticated;

-- -----------------------------------------------------------------------------
-- The owner's side
-- -----------------------------------------------------------------------------
-- Create or update an agent's persona. The API parsed the persona strictly
-- (agents/persona.py) and signed it for the signed-in owner; this stores
-- exactly what it signed.
create or replace function public.save_agent(p_payload text, p_sig text)
returns public.agents language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.ruling(p_payload, p_sig, 'agent-save');
  a    public.agents;
  me   uuid := auth.uid();
begin
  if body ? 'id' then
    update public.agents
       set persona = body -> 'persona',
           name = coalesce(body ->> 'name', name),
           notes = coalesce(body ->> 'notes', notes)
     where id = (body ->> 'id')::uuid and owner_id = me
    returning * into a;
    if not found then
      raise exception 'no such agent' using errcode = 'P0002';
    end if;
    return a;
  end if;
  if (select count(*) from public.agents where owner_id = me) >= 50 then
    raise exception 'you have 50 agents; delete one first' using errcode = '23514';
  end if;
  if body ->> 'parent' is not null
     and not exists (select 1 from public.agents where id = (body ->> 'parent')::uuid and owner_id = me) then
    raise exception 'no such agent to copy' using errcode = 'P0002';
  end if;
  insert into public.agents (owner_id, name, archetype, parent_id, persona, notes, status)
  values (me, body ->> 'name', body ->> 'archetype', (body ->> 'parent')::uuid, body -> 'persona',
          coalesce(body ->> 'notes', ''), coalesce((body ->> 'status')::public.agent_status, 'draft'))
  returning * into a;
  return a;
end $$;

-- A new key. The key is returned here and never again: only its hash is kept.
create or replace function public.create_agent_key(p_name text, p_agents uuid[] default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  me  uuid := auth.uid();
  raw text := 'och_' || encode(extensions.gen_random_bytes(24), 'hex');
  k   public.agent_keys;
begin
  if me is null then
    raise exception 'sign in to do this' using errcode = '28000';
  end if;
  if (select count(*) from public.agent_keys where owner_id = me and revoked_at is null) >= 20 then
    raise exception 'you have 20 live keys; revoke one first' using errcode = '23514';
  end if;
  if p_agents is not null and (
       cardinality(p_agents) = 0
       or exists (select 1 from unnest(p_agents) x
                   where not exists (select 1 from public.agents where id = x and owner_id = me))) then
    raise exception 'a key can only cover your own agents' using errcode = '22023';
  end if;
  insert into public.agent_keys (owner_id, name, prefix, hash, agent_ids)
  values (me, btrim(p_name), left(raw, 12), encode(extensions.digest(raw, 'sha256'), 'hex'), p_agents)
  returning * into k;
  return jsonb_build_object('id', k.id, 'name', k.name, 'prefix', k.prefix, 'agentIds', k.agent_ids,
                            'createdAt', k.created_at, 'key', raw);
end $$;

-- Revoked for good: a revoked key cannot be brought back, only replaced.
create or replace function public.revoke_agent_key(p_key uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.agent_keys set revoked_at = coalesce(revoked_at, now())
   where id = p_key and owner_id = auth.uid();
  if not found then
    raise exception 'no such key' using errcode = 'P0002';
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- The platform's side (signed by the API, for a key)
-- -----------------------------------------------------------------------------
-- What a key may drive. With `personas`, each agent's persona too - for the
-- API's own use (presence, seats, challenge answers); the API never returns
-- a persona to a platform.
create or replace function public.agent_machine_key(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, 'agent-key');
  k    public.agent_keys := private.key_by_hash(body ->> 'key');
  with_persona boolean := coalesce((body ->> 'personas')::boolean, false);
begin
  if (body ->> 'gauge')::boolean then
    perform private.count_usage(k.owner_id, '00000000-0000-0000-0000-000000000000', 0, 0, 1);
  end if;
  return jsonb_build_object(
    'key', jsonb_build_object('id', k.id, 'name', k.name, 'owner', k.owner_id),
    'agents', coalesce((select jsonb_agg(jsonb_build_object('id', a.id, 'name', a.name, 'game', a.game,
                                                              'rating', a.rating, 'status', a.status)
                                          || case when with_persona then jsonb_build_object('persona', a.persona)
                                                  else '{}'::jsonb end
                                          order by a.created_at)
                          from public.agents a
                         where a.owner_id = k.owner_id
                           and (k.agent_ids is null or a.id = any (k.agent_ids))), '[]'::jsonb));
end $$;

-- One move, no session: the agent as it is, no mood carried between calls.
create or replace function public.agent_machine_use(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, 'agent-use');
  k    public.agent_keys := private.key_by_hash(body ->> 'key');
  a    public.agents := private.agent_for_key(k, (body ->> 'agent')::uuid);
begin
  perform private.count_usage(k.owner_id, a.id, 1, 0, 0);
  return private.agent_json(a);
end $$;

create or replace function public.agent_machine_open(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, 'agent-open');
  k    public.agent_keys := private.key_by_hash(body ->> 'key');
  a    public.agents := private.agent_for_key(k, (body ->> 'agent')::uuid);
  s    public.agent_sessions;
begin
  -- The same game asked for again (a platform's server restarted mid-game):
  -- the session it already has, mood and all, not a second one.
  if body ->> 'externalRef' is not null then
    select * into s from public.agent_sessions
     where owner_id = k.owner_id and agent_id = a.id and external_ref = body ->> 'externalRef' and status = 'live'
     order by started_at desc limit 1;
    if found then
      return jsonb_build_object('session', private.session_json(s), 'agent', private.agent_json(a), 'resumed', true);
    end if;
  end if;
  if (select count(*) from public.agent_sessions
       where owner_id = k.owner_id and status = 'live' and started_at > now() - interval '1 day') >= 500 then
    raise exception 'too many live sessions; end some first' using errcode = '23514';
  end if;
  insert into public.agent_sessions (agent_id, owner_id, key_id, external_ref, color, cadence, opponent_rating,
                                     realtime, state)
  values (a.id, k.owner_id, k.id, body ->> 'externalRef', body ->> 'color', body ->> 'cadence',
          (body ->> 'opponentRating')::int, coalesce((body ->> 'realtime')::boolean, false),
          coalesce(body -> 'state', '{}'::jsonb))
  returning * into s;
  perform private.count_usage(k.owner_id, a.id, 0, 1, 0);
  return jsonb_build_object('session', private.session_json(s), 'agent', private.agent_json(a));
end $$;

-- A session and its agent, to decide the next move. Paused agents stop here,
-- even mid-game: pausing is how an owner stops an agent at once. Ending a
-- game (`ending`) is still allowed.
create or replace function public.agent_machine_session(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, 'agent-session');
  k    public.agent_keys := private.key_by_hash(body ->> 'key');
  s    public.agent_sessions := private.session_for_key(k, (body ->> 'session')::uuid);
  a    public.agents := private.agent_for_key(k, s.agent_id, not coalesce((body ->> 'ending')::boolean, false));
begin
  return jsonb_build_object('session', private.session_json(s), 'agent', private.agent_json(a));
end $$;

-- Record a decided move: the new state, one more ply, and - for a realtime
-- session - the broadcast, due when a person would have played. Refused if
-- another move was recorded since the session was read.
create or replace function public.agent_machine_record(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, 'agent-record');
  k    public.agent_keys := private.key_by_hash(body ->> 'key');
  s    public.agent_sessions := private.session_for_key(k, (body ->> 'session')::uuid);
begin
  if s.status <> 'live' then
    raise exception 'that session has ended' using errcode = '23514';
  end if;
  if s.plies <> (body ->> 'plies')::int then
    raise exception 'another move was recorded first' using errcode = '40001';
  end if;
  update public.agent_sessions
     set state = body -> 'state', plies = plies + 1, last_move_at = now()
   where id = s.id;
  if s.realtime and body ? 'deliver' then
    perform private.agent_deliver('agent:' || s.channel, body -> 'deliver' ->> 'event', body -> 'deliver' -> 'payload',
                                  (body -> 'deliver' ->> 'at')::double precision);
  end if;
  perform private.count_usage(k.owner_id, s.agent_id, 1, 0, 0);
  return jsonb_build_object('plies', s.plies + 1);
end $$;

create or replace function public.agent_machine_end(p_payload text, p_sig text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.machine_request(p_payload, p_sig, 'agent-end');
  k    public.agent_keys := private.key_by_hash(body ->> 'key');
  s    public.agent_sessions := private.session_for_key(k, (body ->> 'session')::uuid);
begin
  if s.status = 'live' then
    update public.agent_sessions
       set status = 'finished', result = body ->> 'result', finished_at = now(),
           state = coalesce(body -> 'state', state)
     where id = s.id
    returning * into s;
    if s.realtime and body ? 'deliver' then
      perform private.agent_deliver('agent:' || s.channel, body -> 'deliver' ->> 'event', body -> 'deliver' -> 'payload',
                                    (body -> 'deliver' ->> 'at')::double precision);
    end if;
  end if;
  return private.session_json(s) - 'secret';
end $$;

-- -----------------------------------------------------------------------------
-- Delivery: what is due, broadcast. Run every second by pg_cron.
-- -----------------------------------------------------------------------------
create or replace function private.deliver_agent_outbox()
returns int language plpgsql security definer set search_path = public as $$
declare
  r record;
  n int := 0;
begin
  for r in delete from private.agent_outbox where deliver_at <= now() returning topic, event, payload loop
    perform realtime.send(r.payload, r.event, r.topic, false);
    n := n + 1;
  end loop;
  return n;
end $$;
revoke all on function private.deliver_agent_outbox() from public, anon, authenticated;

do $$
begin
  if exists (select 1 from pg_available_extensions where name = 'pg_cron') then
    create extension if not exists pg_cron with schema pg_catalog;
    perform cron.schedule('ocheso-agent-outbox', '1 seconds', 'select private.deliver_agent_outbox()');
    -- A tick a second leaves 86,400 run records a day; keep an hour of them.
    perform cron.schedule('ocheso-agent-outbox-tidy', '*/10 * * * *', $tidy$
      delete from cron.job_run_details
       where jobid = (select jobid from cron.job where jobname = 'ocheso-agent-outbox')
         and end_time < now() - interval '1 hour'
    $tidy$);
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- Row level security
-- -----------------------------------------------------------------------------
alter table public.agents         enable row level security;
alter table public.agent_keys     enable row level security;
alter table public.agent_sessions enable row level security;
alter table public.agent_usage    enable row level security;

drop policy if exists agents_owner_read on public.agents;
create policy agents_owner_read on public.agents for select to authenticated using (owner_id = auth.uid());
drop policy if exists agents_owner_update on public.agents;
create policy agents_owner_update on public.agents for update to authenticated
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());
drop policy if exists agents_owner_delete on public.agents;
create policy agents_owner_delete on public.agents for delete to authenticated using (owner_id = auth.uid());

drop policy if exists agent_keys_owner_read on public.agent_keys;
create policy agent_keys_owner_read on public.agent_keys for select to authenticated using (owner_id = auth.uid());
drop policy if exists agent_keys_owner_update on public.agent_keys;
create policy agent_keys_owner_update on public.agent_keys for update to authenticated
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());

drop policy if exists agent_sessions_owner_read on public.agent_sessions;
create policy agent_sessions_owner_read on public.agent_sessions for select to authenticated using (owner_id = auth.uid());

drop policy if exists agent_usage_owner_read on public.agent_usage;
create policy agent_usage_owner_read on public.agent_usage for select to authenticated using (owner_id = auth.uid());

-- -----------------------------------------------------------------------------
-- Grants: columns, not rows, decide what a client may write
-- -----------------------------------------------------------------------------
revoke all on public.agents, public.agent_keys, public.agent_sessions, public.agent_usage from anon, authenticated;

grant select on public.agents, public.agent_usage to authenticated;
grant update (name, notes, status) on public.agents to authenticated;
grant delete on public.agents to authenticated;

grant select (id, owner_id, name, prefix, agent_ids, created_at, last_used_at, revoked_at)
  on public.agent_keys to authenticated;
grant update (name) on public.agent_keys to authenticated;

grant select (id, agent_id, owner_id, key_id, external_ref, color, cadence, opponent_rating, realtime,
              state, plies, status, result, started_at, last_move_at, finished_at)
  on public.agent_sessions to authenticated;

revoke all on function public.save_agent(text, text) from public, anon;
revoke all on function public.create_agent_key(text, uuid[]) from public, anon;
revoke all on function public.revoke_agent_key(uuid) from public, anon;
grant execute on function public.save_agent(text, text) to authenticated;
grant execute on function public.create_agent_key(text, uuid[]) to authenticated;
grant execute on function public.revoke_agent_key(uuid) to authenticated;

-- Platforms call through the API as anon; the signature is the gate.
revoke all on function public.agent_machine_key(text, text) from public;
revoke all on function public.agent_machine_use(text, text) from public;
revoke all on function public.agent_machine_open(text, text) from public;
revoke all on function public.agent_machine_session(text, text) from public;
revoke all on function public.agent_machine_record(text, text) from public;
revoke all on function public.agent_machine_end(text, text) from public;
grant execute on function public.agent_machine_key(text, text) to anon, authenticated;
grant execute on function public.agent_machine_use(text, text) to anon, authenticated;
grant execute on function public.agent_machine_open(text, text) to anon, authenticated;
grant execute on function public.agent_machine_session(text, text) to anon, authenticated;
grant execute on function public.agent_machine_record(text, text) to anon, authenticated;
grant execute on function public.agent_machine_end(text, text) to anon, authenticated;

-- private.agent_json / session_json are plain helpers with no table access.
revoke all on function private.agent_json(public.agents) from public, anon, authenticated;
revoke all on function private.session_json(public.agent_sessions) from public, anon, authenticated;
