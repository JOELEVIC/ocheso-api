-- =============================================================================
-- Ocheso — play: rounds, games, moves, clocks
-- =============================================================================
-- Applied after db/schema.sql, by hand, idempotent like it.
--
-- THE PROBLEM THIS FILE SOLVES. Every request runs as its caller, so a player
-- holds a token that can call these functions directly, around the API. The
-- rules of chess and draughts live in Python, not here. So who stops a player
-- from writing any position they like?
--
-- THE REFEREE. ocheso-api checks each move with a real rules engine and signs
-- its ruling - HMAC-SHA256 over the exact payload - with a key only it and this
-- database hold (private.referee, readable by nobody). Functions here accept a
-- ruling only when:
--   * the signature verifies, and the ruling has not expired;
--   * it was made for the caller (payload.by = auth.uid());
--   * the caller is the player to move, and the game is at the very ply and
--     position the referee judged - a ruling cannot be replayed later;
--   * the clock, kept here from now(), says they still have time.
-- The key can sign rulings and nothing else. It is not a service-role key: it
-- reads no rows and bypasses no policy, and the API still holds none.
--
-- Clocks are this database's: the time a move takes is now() minus when the
-- turn began, measured where nobody can lie about either.
-- =============================================================================

do $$ begin
  create type public.round_status as enum ('pending', 'live', 'finished');
exception when duplicate_object then null; end $$;
do $$ begin
  create type public.game_status as enum ('scheduled', 'live', 'finished');
exception when duplicate_object then null; end $$;
-- Who won. 'none' is a double forfeit: a result in which nobody scores.
do $$ begin
  create type public.game_result as enum ('white', 'black', 'draw', 'none');
exception when duplicate_object then null; end $$;

-- When it went live. Arena windows run from here, and nobody sets it but the
-- status trigger below.
alter table public.tournaments add column if not exists started_at timestamptz;

create or replace function public.stamp_tournament_start()
returns trigger language plpgsql as $$
begin
  if new.status = 'live' and old.status is distinct from 'live' then
    new.started_at := coalesce(new.started_at, now());
  end if;
  return new;
end $$;
drop trigger if exists tournaments_started on public.tournaments;
create trigger tournaments_started before update of status on public.tournaments
  for each row execute function public.stamp_tournament_start();

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------
create table if not exists public.rounds (
  id            uuid primary key default gen_random_uuid(),
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  number        int not null check (number between 1 and 200),
  status        public.round_status not null default 'pending',
  started_at    timestamptz,
  finished_at   timestamptz,
  created_at    timestamptz not null default now(),
  unique (tournament_id, number)
);

create table if not exists public.games (
  id              uuid primary key default gen_random_uuid(),
  tournament_id   uuid not null references public.tournaments (id) on delete cascade,
  -- null for arena games, which belong to no round.
  round_id        uuid references public.rounds (id) on delete cascade,
  board           int,
  white_id        uuid references public.profiles (id),
  -- null for a bye: scored at once, never played.
  black_id        uuid references public.profiles (id),
  status          public.game_status not null default 'scheduled',
  result          public.game_result,
  termination     text,
  -- FEN for chess; PDN FEN for draughts ("W:W31,32:BK1,2"). Opaque here: the
  -- referee is the only thing that reads it.
  position        text not null,
  turn            text not null default 'white' check (turn in ('white', 'black')),
  ply             int not null default 0,
  -- The moves legal in this position, as the referee listed them. A hint for
  -- the board, so it can draw targets without a rules engine of its own; every
  -- move is still judged again when it is made.
  legal           jsonb not null default '[]',
  last_move       text,
  white_ms        int not null,
  black_ms        int not null,
  increment_ms    int not null default 0,
  -- When the side to move's clock started running. null until the game starts.
  turn_started_at timestamptz,
  draw_offer      text check (draw_offer in ('white', 'black')),
  -- A knockout tie-break game, played because this one was drawn.
  tiebreak_of     uuid references public.games (id) on delete set null,
  started_at      timestamptz,
  finished_at     timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint games_two_players check (white_id is distinct from black_id),
  constraint games_finished_has_result check ((status = 'finished') = (result is not null))
);
create index if not exists games_tournament_idx on public.games (tournament_id);
create index if not exists games_round_idx on public.games (round_id);
create index if not exists games_white_idx on public.games (white_id);
create index if not exists games_black_idx on public.games (black_id);

drop trigger if exists games_touch on public.games;
create trigger games_touch before update on public.games
  for each row execute function public.touch_updated_at();

create table if not exists public.moves (
  game_id        uuid not null references public.games (id) on delete cascade,
  -- Copied from the game so the read policy needs no join.
  tournament_id  uuid not null references public.tournaments (id) on delete cascade,
  ply            int not null check (ply >= 1),
  move           text not null,
  -- How people write it: "Nf3", "32-28", "28x19x10".
  san            text,
  position_after text not null,
  -- The mover's clock after the move, increment included.
  clock_ms       int not null,
  created_at     timestamptz not null default now(),
  primary key (game_id, ply)
);
create index if not exists moves_tournament_idx on public.moves (tournament_id);

-- Arena: who is waiting for their next game.
create table if not exists public.arena_queue (
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  user_id       uuid not null references public.profiles (id) on delete cascade,
  since         timestamptz not null default now(),
  primary key (tournament_id, user_id)
);

-- The referee's key. One row, readable by no client role; only the SECURITY
-- DEFINER functions below see it. ocheso-api is given the same value as
-- REFEREE_SECRET when this file is first applied.
create table if not exists private.referee (
  id         boolean primary key default true check (id),
  secret     text not null default encode(extensions.gen_random_bytes(32), 'hex'),
  created_at timestamptz not null default now()
);
insert into private.referee default values on conflict do nothing;
revoke all on private.referee from public, anon, authenticated;

-- -----------------------------------------------------------------------------
-- Helpers (private: callable by policies and the functions below, not by RPC)
-- -----------------------------------------------------------------------------

-- A ruling, verified. Raises unless the referee signed exactly this text, for
-- this caller, recently.
create or replace function private.ruling(p_payload text, p_sig text, p_kind text)
returns jsonb language plpgsql stable security definer set search_path = public, extensions as $$
declare
  key  text;
  body jsonb;
begin
  select secret into key from private.referee;
  if p_sig is null or encode(extensions.hmac(p_payload, key, 'sha256'), 'hex') <> p_sig then
    raise exception 'the referee did not sign this' using errcode = '28000';
  end if;
  body := p_payload::jsonb;
  if body ->> 'kind' is distinct from p_kind then
    raise exception 'that ruling is for something else' using errcode = '28000';
  end if;
  if (body ->> 'exp')::bigint < extract(epoch from now()) then
    raise exception 'that ruling has expired; try again' using errcode = '28000';
  end if;
  if (body ->> 'by')::uuid is distinct from auth.uid() then
    raise exception 'that ruling was made for someone else' using errcode = '28000';
  end if;
  return body;
end $$;
revoke all on function private.ruling(text, text, text) from public, anon, authenticated;

-- Time left on the clock of the side to move, right now.
create or replace function private.time_left(g public.games)
returns int language sql stable as $$
  select (case g.turn when 'white' then g.white_ms else g.black_ms end)
         - coalesce((extract(epoch from (now() - g.turn_started_at)) * 1000)::int, 0);
$$;

create or replace function private.side_of(g public.games, u uuid)
returns text language sql immutable as $$
  select case u when g.white_id then 'white' when g.black_id then 'black' end;
$$;

-- Whether anyone may watch this tournament's games.
create or replace function private.games_public(t uuid)
returns boolean language sql stable security definer set search_path = public, extensions as $$
  select exists (select 1 from tournaments
                  where id = t and is_listed and participants_visible and games_watchable and status <> 'draft');
$$;

-- Ratings move after each rated game: Elo, K 32 under 2100, 24 under 2400,
-- 16 above. Rated means two players, a result on the board, and at least a
-- move each - a no-show flag or a first-move resignation says nothing about
-- strength, and an arbiter's result (a forfeit, a correction) is not a game.
-- Corrections to a finished result do not re-rate.
create or replace function private.rate(g public.games)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare
  kind text;
  rw   int;
  rb   int;
  ew   numeric;
  sw   numeric;
begin
  if g.black_id is null or g.result not in ('white', 'black', 'draw')
     or g.termination in ('arbiter', 'bye') or g.ply < 2 then
    return;
  end if;
  select game::text into kind from tournaments where id = g.tournament_id;
  if kind = 'chess' then
    select chess_rating into rw from profiles where id = g.white_id;
    select chess_rating into rb from profiles where id = g.black_id;
  else
    select checkers_rating into rw from profiles where id = g.white_id;
    select checkers_rating into rb from profiles where id = g.black_id;
  end if;
  ew := 1 / (1 + power(10::numeric, (rb - rw) / 400.0));
  sw := case g.result when 'white' then 1 when 'black' then 0 else 0.5 end;
  rw := greatest(100, least(3500, rw + round((case when rw < 2100 then 32 when rw < 2400 then 24 else 16 end) * (sw - ew))::int));
  rb := greatest(100, least(3500, rb + round((case when rb < 2100 then 32 when rb < 2400 then 24 else 16 end) * (ew - sw))::int));
  if kind = 'chess' then
    update profiles set chess_rating = rw where id = g.white_id;
    update profiles set chess_rating = rb where id = g.black_id;
  else
    update profiles set checkers_rating = rw where id = g.white_id;
    update profiles set checkers_rating = rb where id = g.black_id;
  end if;
end $$;
revoke all on function private.rate(public.games) from public, anon, authenticated;

-- Ends a game, freezes the mover's clock where it stood, and closes the round
-- when it was the last one open.
create or replace function private.finish_game(p_game uuid, p_result public.game_result, p_termination text)
returns public.games language plpgsql security definer set search_path = public, extensions as $$
declare
  g public.games;
begin
  -- SET expressions read the row as it was, so `status = 'live'` below is the
  -- status before this update.
  update games set
    white_ms = case when status = 'live' and turn = 'white' and turn_started_at is not null
                    then greatest(0, white_ms - (extract(epoch from (now() - turn_started_at)) * 1000)::int)
                    else white_ms end,
    black_ms = case when status = 'live' and turn = 'black' and turn_started_at is not null
                    then greatest(0, black_ms - (extract(epoch from (now() - turn_started_at)) * 1000)::int)
                    else black_ms end,
    status = 'finished', result = p_result, termination = p_termination,
    finished_at = now(), draw_offer = null, legal = '[]'
  where id = p_game
  returning * into g;
  perform private.rate(g);
  perform private.close_round(g.round_id);
  return g;
end $$;

create or replace function private.close_round(p_round uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if p_round is null then
    return;
  end if;
  update rounds set status = 'finished', finished_at = now()
   where id = p_round and status <> 'finished'
     and not exists (select 1 from games where round_id = p_round and status <> 'finished');
end $$;

revoke all on function private.finish_game(uuid, public.game_result, text) from public, anon, authenticated;
revoke all on function private.close_round(uuid) from public, anon, authenticated;

-- -----------------------------------------------------------------------------
-- Pairings: rounds, tie-breaks, arena games
-- -----------------------------------------------------------------------------
-- The referee pairs; this checks the result is something the caller may
-- publish and that every name in it is entitled to a board.
--
-- payload: { kind: "pairings", by, exp, tournament, round (null for arena),
--            start: bool,
--            games: [{ board, white, black (null = bye), position, turn,
--                      legal, tiebreak_of }] }
create or replace function public.publish_pairings(p_payload text, p_sig text)
returns setof public.games
language plpgsql security definer set search_path = public, extensions as $$
declare
  body   jsonb := private.ruling(p_payload, p_sig, 'pairings');
  t      tournaments;
  r      rounds;
  item   jsonb;
  g      games;
  w      uuid;
  b      uuid;
  seen   uuid[] := '{}';
  start  boolean := coalesce((body ->> 'start')::boolean, false);
  taken  int;
  num    int := (body ->> 'round')::int;
begin
  select * into t from tournaments where id = (body ->> 'tournament')::uuid for update;
  if not found then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  if t.status <> 'live' then
    raise exception 'the tournament is not under way' using errcode = 'check_violation';
  end if;

  if t.format = 'arena' then
    -- Arena games are made when a player asks for their next one. The caller
    -- must be one of the two, and the window must still be open.
    if now() > t.started_at + make_interval(mins => t.arena_minutes) then
      raise exception 'the arena has closed' using errcode = 'check_violation';
    end if;
    start := true;
  else
    if not private.is_tournament_manager(t.id) then
      raise exception 'no such tournament' using errcode = 'no_data_found';
    end if;
    select * into r from rounds where tournament_id = t.id and number = num for update;
    if not found then
      if exists (select 1 from rounds where tournament_id = t.id and status <> 'finished') then
        raise exception 'finish the current round first' using errcode = 'check_violation';
      end if;
      if num is distinct from coalesce((select max(number) from rounds where tournament_id = t.id), 0) + 1 then
        raise exception 'that is not the next round' using errcode = 'check_violation';
      end if;
      insert into rounds (tournament_id, number) values (t.id, num) returning * into r;
    elsif t.format <> 'knockout' then
      -- Only a knockout adds games to a round it has already paired: the
      -- tie-breaks that settle a drawn match.
      raise exception 'that round is already paired' using errcode = 'unique_violation';
    end if;
  end if;

  for item in select * from jsonb_array_elements(body -> 'games') loop
    w := (item ->> 'white')::uuid;
    b := nullif(item ->> 'black', '')::uuid;
    if w = any (seen) or b = any (seen) then
      raise exception 'a player is paired twice' using errcode = 'check_violation';
    end if;
    seen := seen || w;
    if b is not null then
      seen := seen || b;
    end if;
    if exists (select 1 from unnest(array[w, b]) p(id)
                where p.id is not null
                  and not exists (select 1 from participants
                                   where tournament_id = t.id and user_id = p.id and status = 'approved')) then
      raise exception 'only approved players can be paired' using errcode = 'check_violation';
    end if;

    if t.format = 'arena' then
      if b is null or auth.uid() not in (w, b) then
        raise exception 'an arena game is made by one of its two players' using errcode = 'insufficient_privilege';
      end if;
      if exists (select 1 from games where tournament_id = t.id and status <> 'finished'
                  and (white_id in (w, b) or black_id in (w, b))) then
        raise exception 'one of these players is already in a game' using errcode = 'unique_violation';
      end if;
      -- Out of the queue in the same statement that pairs them, so two
      -- requests racing for the same opponent cannot both win.
      delete from arena_queue where tournament_id = t.id and user_id in (w, b);
      get diagnostics taken = row_count;
      if taken <> 2 then
        raise exception 'your opponent is no longer waiting' using errcode = 'check_violation';
      end if;
    end if;

    if b is null then
      insert into games (tournament_id, round_id, board, white_id, status, result, termination,
                         position, white_ms, black_ms, increment_ms, finished_at)
      values (t.id, r.id, (item ->> 'board')::int, w, 'finished', 'white', 'bye',
              '-', 0, 0, 0, now())
      returning * into g;
    else
      insert into games (tournament_id, round_id, board, white_id, black_id, status, position, turn,
                         legal, white_ms, black_ms, increment_ms, turn_started_at, started_at, tiebreak_of)
      values (t.id, r.id, (item ->> 'board')::int, w, b,
              case when start then 'live' else 'scheduled' end::public.game_status,
              item ->> 'position', coalesce(item ->> 'turn', 'white'), coalesce(item -> 'legal', '[]'),
              t.clock_base_s * 1000, t.clock_base_s * 1000, t.clock_increment_s * 1000,
              case when start then now() end, case when start then now() end,
              nullif(item ->> 'tiebreak_of', '')::uuid)
      returning * into g;
    end if;
    return next g;
  end loop;

  if r.id is not null then
    if start then
      update rounds set status = 'live', started_at = coalesce(started_at, now()), finished_at = null
       where id = r.id;
    elsif r.status = 'finished' then
      -- Tie-break games published without starting reopen the round.
      update rounds set status = 'pending', finished_at = null where id = r.id;
    end if;
    perform private.close_round(r.id);
  end if;
end $$;

-- Starts the clocks on a round published without starting.
create or replace function public.start_round(p_round uuid)
returns public.rounds
language plpgsql security definer set search_path = public, extensions as $$
declare
  r rounds;
begin
  select * into r from rounds where id = p_round for update;
  if not found or not private.is_tournament_manager(r.tournament_id) then
    raise exception 'no such round' using errcode = 'no_data_found';
  end if;
  update games set status = 'live', turn_started_at = now(), started_at = now()
   where round_id = r.id and status = 'scheduled';
  update rounds set status = 'live', started_at = coalesce(started_at, now())
   where id = r.id and status = 'pending'
  returning * into r;
  return r;
end $$;

-- -----------------------------------------------------------------------------
-- Playing
-- -----------------------------------------------------------------------------
-- payload: { kind: "move", by, exp, game, ply, before, move, san, after, turn,
--            legal, result?, termination? }
create or replace function public.play_move(p_payload text, p_sig text)
returns public.games
language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.ruling(p_payload, p_sig, 'move');
  g    games;
  side text;
  remaining int;
begin
  select * into g from games where id = (body ->> 'game')::uuid for update;
  if not found then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  if g.status <> 'live' then
    raise exception 'this game is not in progress' using errcode = 'check_violation';
  end if;
  side := private.side_of(g, auth.uid());
  if side is null then
    raise exception 'you are not playing this game' using errcode = 'insufficient_privilege';
  end if;
  if side <> g.turn then
    raise exception 'it is not your move' using errcode = 'check_violation';
  end if;
  if (body ->> 'ply')::int <> g.ply or body ->> 'before' is distinct from g.position then
    raise exception 'the position has moved on; reload the game' using errcode = 'check_violation';
  end if;
  remaining := private.time_left(g);
  if remaining <= 0 then
    raise exception 'your time has run out' using errcode = 'check_violation';
  end if;

  insert into moves (game_id, tournament_id, ply, move, san, position_after, clock_ms)
  values (g.id, g.tournament_id, g.ply + 1, body ->> 'move', body ->> 'san', body ->> 'after', remaining + g.increment_ms);

  update games set
    position = body ->> 'after',
    turn = body ->> 'turn',
    ply = ply + 1,
    legal = coalesce(body -> 'legal', '[]'),
    last_move = body ->> 'move',
    white_ms = case when side = 'white' then remaining + increment_ms else white_ms end,
    black_ms = case when side = 'black' then remaining + increment_ms else black_ms end,
    turn_started_at = now(),
    -- Moving declines an offer from your opponent; your own offer stands.
    draw_offer = case when draw_offer = side then draw_offer end
  where id = g.id
  returning * into g;

  if body ->> 'result' is not null then
    g := private.finish_game(g.id, (body ->> 'result')::public.game_result, body ->> 'termination');
  end if;
  return g;
end $$;

-- The side to move has run out of time. Anyone in the game, or running the
-- tournament, may say so; this checks it against its own clock. The referee
-- rules on the result, because "out of time" is a draw when the opponent could
-- never have won.
-- payload: { kind: "flag", by, exp, game, ply, result }
create or replace function public.claim_flag(p_payload text, p_sig text)
returns public.games
language plpgsql security definer set search_path = public, extensions as $$
declare
  body jsonb := private.ruling(p_payload, p_sig, 'flag');
  g    games;
begin
  select * into g from games where id = (body ->> 'game')::uuid for update;
  if not found then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  if private.side_of(g, auth.uid()) is null and not private.is_tournament_staff(g.tournament_id) then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  if g.status <> 'live' then
    raise exception 'this game is not in progress' using errcode = 'check_violation';
  end if;
  if (body ->> 'ply')::int <> g.ply then
    raise exception 'the position has moved on; reload the game' using errcode = 'check_violation';
  end if;
  if private.time_left(g) > 0 then
    raise exception 'there is still time on the clock' using errcode = 'check_violation';
  end if;
  if body ->> 'result' not in (case g.turn when 'white' then 'black' else 'white' end, 'draw') then
    raise exception 'that is not a result of running out of time' using errcode = 'check_violation';
  end if;
  return private.finish_game(g.id, (body ->> 'result')::public.game_result, 'timeout');
end $$;

create or replace function public.resign(p_game uuid)
returns public.games
language plpgsql security definer set search_path = public, extensions as $$
declare
  g    games;
  side text;
begin
  select * into g from games where id = p_game for update;
  side := case when found then private.side_of(g, auth.uid()) end;
  if side is null then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  if g.status <> 'live' then
    raise exception 'this game is not in progress' using errcode = 'check_violation';
  end if;
  return private.finish_game(g.id, (case side when 'white' then 'black' else 'white' end)::public.game_result, 'resignation');
end $$;

-- Offer a draw, or accept the one on the table.
create or replace function public.offer_draw(p_game uuid)
returns public.games
language plpgsql security definer set search_path = public, extensions as $$
declare
  g    games;
  side text;
begin
  select * into g from games where id = p_game for update;
  side := case when found then private.side_of(g, auth.uid()) end;
  if side is null then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  if g.status <> 'live' then
    raise exception 'this game is not in progress' using errcode = 'check_violation';
  end if;
  if g.draw_offer is not null and g.draw_offer <> side then
    return private.finish_game(g.id, 'draw', 'agreement');
  end if;
  update games set draw_offer = side where id = g.id returning * into g;
  return g;
end $$;

create or replace function public.decline_draw(p_game uuid)
returns public.games
language plpgsql security definer set search_path = public, extensions as $$
declare
  g    games;
  side text;
begin
  select * into g from games where id = p_game for update;
  side := case when found then private.side_of(g, auth.uid()) end;
  if side is null then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  update games set draw_offer = null where id = g.id and draw_offer is not null and draw_offer <> side
  returning * into g;
  return g;
end $$;

-- The arbiter's word: forfeits, corrections, a game played over the board.
-- Owner and co-admins only.
create or replace function public.set_result(p_game uuid, p_result public.game_result)
returns public.games
language plpgsql security definer set search_path = public, extensions as $$
declare
  g games;
begin
  select * into g from games where id = p_game for update;
  if not found or not private.is_tournament_manager(g.tournament_id) then
    raise exception 'no such game' using errcode = 'no_data_found';
  end if;
  if g.black_id is null then
    raise exception 'a bye has no result to set' using errcode = 'check_violation';
  end if;
  if g.status = 'finished' then
    update games set result = p_result, termination = 'arbiter' where id = g.id returning * into g;
    return g;
  end if;
  return private.finish_game(g.id, p_result, 'arbiter');
end $$;

-- -----------------------------------------------------------------------------
-- Arena queue
-- -----------------------------------------------------------------------------
create or replace function public.arena_join(p_tournament uuid)
returns public.arena_queue
language plpgsql security definer set search_path = public, extensions as $$
declare
  t   tournaments;
  row arena_queue;
begin
  select * into t from tournaments where id = p_tournament;
  if not found or not exists (select 1 from participants where tournament_id = t.id and user_id = auth.uid()
                                                          and status = 'approved') then
    raise exception 'no such tournament' using errcode = 'no_data_found';
  end if;
  if t.format <> 'arena' or t.status <> 'live'
     or now() > t.started_at + make_interval(mins => t.arena_minutes) then
    raise exception 'the arena is not open' using errcode = 'check_violation';
  end if;
  if exists (select 1 from games where tournament_id = t.id and status <> 'finished'
              and auth.uid() in (white_id, black_id)) then
    raise exception 'finish your game first' using errcode = 'check_violation';
  end if;
  insert into arena_queue (tournament_id, user_id) values (t.id, auth.uid())
  on conflict (tournament_id, user_id) do update set since = arena_queue.since
  returning * into row;
  return row;
end $$;

create or replace function public.arena_leave(p_tournament uuid)
returns void
language sql security definer set search_path = public, extensions as $$
  delete from arena_queue where tournament_id = p_tournament and user_id = auth.uid();
$$;

-- Results for standings and pairings, without positions or moves. Visible
-- wherever the player list is - get_roster's rule: anyone who can open the
-- event, unless the organiser hides who has entered. For an unlisted event that
-- means people holding its link, which is what knowing its id amounts to: ids
-- of unlisted events are not readable anywhere else.
drop function if exists public.get_results(uuid);
create or replace function public.get_results(p_tournament uuid)
returns table (
  game_id uuid, round_number int, round_status public.round_status, board int, white_id uuid, black_id uuid,
  status public.game_status, result public.game_result, termination text,
  tiebreak_of uuid, finished_at timestamptz
)
language sql stable security definer set search_path = public, extensions as $$
  select g.id, r.number, r.status, g.board, g.white_id, g.black_id, g.status, g.result, g.termination,
         g.tiebreak_of, g.finished_at
    from games g
    join tournaments t on t.id = g.tournament_id
    left join rounds r on r.id = g.round_id
   where g.tournament_id = p_tournament
     and ((t.status <> 'draft' and t.participants_visible)
          or private.is_tournament_staff(p_tournament)
          or private.is_tournament_participant(p_tournament))
   order by r.number nulls last, g.board nulls last, g.created_at;
$$;

create or replace function public.server_now()
returns timestamptz language sql stable as $$ select now() $$;

-- -----------------------------------------------------------------------------
-- Row level security
-- -----------------------------------------------------------------------------
alter table public.rounds      enable row level security;
alter table public.games       enable row level security;
alter table public.moves       enable row level security;
alter table public.arena_queue enable row level security;

-- Pairings are as public as the player list.
drop policy if exists rounds_read on public.rounds;
create policy rounds_read on public.rounds for select to anon, authenticated using (
  private.roster_is_public(tournament_id)
  or private.is_tournament_staff(tournament_id)
  or private.is_tournament_participant(tournament_id)
);

-- Positions and moves: your own games, everything if you run or are entered in
-- the tournament, and everything public when the organiser allows watching.
drop policy if exists games_read on public.games;
create policy games_read on public.games for select to anon, authenticated using (
  auth.uid() in (white_id, black_id)
  or private.is_tournament_staff(tournament_id)
  or private.is_tournament_participant(tournament_id)
  or private.games_public(tournament_id)
);

drop policy if exists moves_read on public.moves;
create policy moves_read on public.moves for select to anon, authenticated using (
  exists (select 1 from games g where g.id = game_id)
);

drop policy if exists arena_queue_read on public.arena_queue;
create policy arena_queue_read on public.arena_queue for select to authenticated using (
  user_id = auth.uid()
  or private.is_tournament_staff(tournament_id)
  or private.is_tournament_participant(tournament_id)
);

-- Read-only to clients. Every write is one of the functions above.
revoke all on public.rounds, public.games, public.moves, public.arena_queue from anon, authenticated;
grant select on public.rounds, public.games, public.moves to anon, authenticated;
grant select on public.arena_queue to authenticated;

revoke all on function public.publish_pairings(text, text) from public, anon;
revoke all on function public.start_round(uuid) from public, anon;
revoke all on function public.play_move(text, text) from public, anon;
revoke all on function public.claim_flag(text, text) from public, anon;
revoke all on function public.resign(uuid) from public, anon;
revoke all on function public.offer_draw(uuid) from public, anon;
revoke all on function public.decline_draw(uuid) from public, anon;
revoke all on function public.set_result(uuid, public.game_result) from public, anon;
revoke all on function public.arena_join(uuid) from public, anon;
revoke all on function public.arena_leave(uuid) from public, anon;
grant execute on function public.publish_pairings(text, text) to authenticated;
grant execute on function public.start_round(uuid) to authenticated;
grant execute on function public.play_move(text, text) to authenticated;
grant execute on function public.claim_flag(text, text) to authenticated;
grant execute on function public.resign(uuid) to authenticated;
grant execute on function public.offer_draw(uuid) to authenticated;
grant execute on function public.decline_draw(uuid) to authenticated;
grant execute on function public.set_result(uuid, public.game_result) to authenticated;
grant execute on function public.arena_join(uuid) to authenticated;
grant execute on function public.arena_leave(uuid) to authenticated;

revoke all on function public.get_results(uuid) from public;
grant execute on function public.get_results(uuid) to anon, authenticated;
grant execute on function public.server_now() to anon, authenticated;

-- Trigger functions are not RPCs.
revoke all on function public.stamp_tournament_start() from public, anon, authenticated;

-- -----------------------------------------------------------------------------
-- Realtime: boards update as moves land. Supabase applies the read policies
-- above to every subscriber, so a socket shows exactly what a select would.
-- -----------------------------------------------------------------------------
do $$
declare
  t text;
begin
  if not exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    return;
  end if;
  foreach t in array array['rounds', 'games', 'moves'] loop
    if not exists (select 1 from pg_publication_tables
                    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
