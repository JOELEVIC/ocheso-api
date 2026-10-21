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
