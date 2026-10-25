-- The parts of Supabase that db/schema.sql depends on, for testing it against
-- plain Postgres. NEVER apply this to a real Supabase project - auth already
-- exists there, and this would shadow it.
--
-- Two details are copied deliberately, because a test that skips them proves
-- less than it appears to:
--   * auth.uid() reads the JWT claim exactly as Supabase's does, so "acting as"
--     a user here is the same mechanism a real request uses.
--   * public tables get ALL granted to anon and authenticated by default, as on
--     Supabase. Without that, the schema's revoke-then-grant would be tested
--     against a role that never had anything to revoke, and would pass for the
--     wrong reason.

-- Where Supabase keeps it. Installing it into public here would let the
-- schema's pinned search_paths pass a test they would fail in production.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create schema if not exists auth;

create table if not exists auth.users (
  id                 uuid primary key,
  email              text,
  raw_user_meta_data jsonb not null default '{}'::jsonb
);

create or replace function auth.uid() returns uuid language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

do $$ begin create role anon nologin; exception when duplicate_object then null; end $$;
do $$ begin create role authenticated nologin; exception when duplicate_object then null; end $$;

grant usage on schema public, auth, extensions to anon, authenticated;
grant execute on function auth.uid() to anon, authenticated;

alter default privileges in schema public grant all on tables    to anon, authenticated;
alter default privileges in schema public grant all on sequences to anon, authenticated;
alter default privileges in schema public grant all on functions to anon, authenticated;

-- Supabase's own default search_path for API roles.
alter role anon          set search_path = "$user", public, extensions;
alter role authenticated set search_path = "$user", public, extensions;

-- Realtime's broadcast-from-the-database function, with Supabase's signature.
-- Here it only records what would have been sent, so tests can read it.
create schema if not exists realtime;
create table if not exists realtime.sent (
  id      bigserial primary key,
  topic   text not null,
  event   text not null,
  payload jsonb not null,
  private boolean not null,
  at      timestamptz not null default now()
);
create or replace function realtime.send(payload jsonb, event text, topic text, private boolean default true)
returns void language sql as $$
  insert into realtime.sent (topic, event, payload, private) values (topic, event, payload, private);
$$;

-- Auth's sign-in bookkeeping, which db/platforms.sql claims email invites
-- from: a confirmed address and each sign-in. Tests set them by hand the way
-- GoTrue would (confirming the code, signing in again).
alter table auth.users add column if not exists email_confirmed_at timestamptz;
alter table auth.users add column if not exists last_sign_in_at    timestamptz;
alter table auth.users add column if not exists created_at         timestamptz not null default now();

-- Realtime Authorization reads private broadcasts through RLS on this table,
-- with the channel's topic in realtime.topic(). Only the columns the policy in
-- db/platforms.sql names.
create table if not exists realtime.messages (
  id          bigserial primary key,
  topic       text not null,
  extension   text not null default 'broadcast',
  event       text,
  payload     jsonb,
  private     boolean not null default true,
  inserted_at timestamptz not null default now()
);
alter table realtime.messages enable row level security;
grant usage on schema realtime to anon, authenticated;
grant select on realtime.messages to anon, authenticated;
create or replace function realtime.topic() returns text language sql stable as $$
  select nullif(current_setting('realtime.topic', true), '')
$$;
grant execute on function realtime.topic() to anon, authenticated;

-- pg_net, recorded instead of sent: net.http_post() files the request in
-- net.sent and returns its id, as the real one does; a test plays the remote
-- server by writing net._http_response, which is where pg_net puts answers.
create schema if not exists net;
create table if not exists net.sent (
  id                   bigserial primary key,
  url                  text not null,
  body                 jsonb,
  headers              jsonb,
  timeout_milliseconds int,
  at                   timestamptz not null default now()
);
create table if not exists net._http_response (
  id           bigint primary key,
  status_code  int,
  content_type text,
  headers      jsonb,
  content      text,
  timed_out    boolean,
  error_msg    text,
  created      timestamptz not null default now()
);
create or replace function net.http_post(
  url text,
  body jsonb default '{}'::jsonb,
  params jsonb default '{}'::jsonb,
  headers jsonb default '{"Content-Type": "application/json"}'::jsonb,
  timeout_milliseconds int default 5000
) returns bigint language sql as $$
  insert into net.sent (url, body, headers, timeout_milliseconds)
  values (url, body, headers, timeout_milliseconds) returning id;
$$;
