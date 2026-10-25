# Testing the schema

`db/schema.sql` puts authorisation in row level security, so this is where that
authorisation is proven. `test_rls.py` acts as an owner, a co-admin, a
moderator, a player, a stranger and an anonymous visitor, and asserts what each
can and cannot do — as real Postgres roles with a JWT subject set, the same
mechanism a request through PostgREST uses. `test_play.py`, `test_agents.py`
and `test_platforms.py` do the same for play, agents and platforms
(organisations, member profiles, email invites, embed sessions, the signed
dispatchers, autopilot, the live feed, webhooks, throttles).

The database is four files, applied in order, each in its own transaction, by
`db/apply.sh`: `schema.sql` → `play.sql` → `agents.sql` → `platforms.sql`.
Every file is idempotent.

```bash
initdb -D /tmp/och-pg -U postgres --locale=C && pg_ctl -D /tmp/och-pg -o "-p 55434" start

# Everything: each suite on its own fresh database, the schema applied twice
# (the second pass proves every file re-applies over itself).
PG="-h 127.0.0.1 -p 55434 -U postgres" PYTHON=python3 db/test/test_db.sh

# Or one suite by hand:
createdb -h 127.0.0.1 -p 55434 -U postgres ocheso_test
psql -h 127.0.0.1 -p 55434 -U postgres -d ocheso_test -f db/test/supabase_shim.sql
db/apply.sh -h 127.0.0.1 -p 55434 -U postgres -d ocheso_test
python3 db/test/test_platforms.py postgresql://postgres@127.0.0.1:55434/ocheso_test

# End to end, through PostgREST and the real API (all three apply the full order):
PG="-h 127.0.0.1 -p 55434 -U postgres" PYTHON=python3 db/test/e2e_play.sh
PG="-h 127.0.0.1 -p 55434 -U postgres" PYTHON=python3 db/test/e2e_agents.sh
PG="-h 127.0.0.1 -p 55434 -U postgres" PYTHON=python3 db/test/e2e_platforms.sh
```

`e2e_platforms.py` plays Ocheso for Platforms whole: an organisation, its key
and webhook, a Swiss on autopilot for the partner's own users (player tokens,
embed sessions, every game through `/v1/embed/games/*`), email invites claimed
at sign-up, sign-in and page load, the Google handoff, and the isolation
between organisations. Its autopilot ticks are made by the database:
`private.autopilot_kick()` signs the tick into the shim's `net.sent`, the suite
posts those exact bytes and header to `/v1/internal/tick`, and answers in
`net._http_response`, as pg_net would.

`supabase_shim.sql` stands in for the parts of Supabase the schema relies on.
**Never apply it to a real Supabase project.** It copies two details on
purpose, because a test that skips them passes for the wrong reasons: Supabase's
default grants of ALL to `anon`/`authenticated` (so the schema's revokes are
really exercised), and pgcrypto living in the `extensions` schema (so pinned
search paths are really exercised).

For platforms it also stands in for three services the database talks to,
recording instead of acting so the tests can play the other side:

- **Auth**: `auth.users.email_confirmed_at` and `last_sign_in_at`. A test
  "confirms the code" or "signs in" by updating them, which is what fires the
  invite claims.
- **Realtime**: `realtime.send()` records into `realtime.sent`, and a minimal
  `realtime.messages` with `realtime.topic()` carries the broadcast policy.
- **pg_net**: `net.http_post()` records into `net.sent` and returns its id; a
  test answers a request by inserting into `net._http_response`, as pg_net does.

pg_cron is not in the shim: where it is missing the schedules are simply not
created, and the tests call the scheduled functions (`private.autopilot_kick`,
`private.webhooks_pump`, `private.gc`) directly.
