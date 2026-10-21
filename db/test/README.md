# Testing the schema

`db/schema.sql` puts authorisation in row level security, so this is where that
authorisation is proven. `test_rls.py` acts as an owner, a co-admin, a
moderator, a player, a stranger and an anonymous visitor, and asserts what each
can and cannot do — as real Postgres roles with a JWT subject set, the same
mechanism a request through PostgREST uses.

```bash
initdb -D /tmp/och-pg -U postgres --locale=C && pg_ctl -D /tmp/och-pg -o "-p 55434" start
createdb -h 127.0.0.1 -p 55434 -U postgres ocheso_test
psql -h 127.0.0.1 -p 55434 -U postgres -d ocheso_test -f db/test/supabase_shim.sql
psql -h 127.0.0.1 -p 55434 -U postgres -d ocheso_test -f db/schema.sql
python3 db/test/test_rls.py postgresql://postgres@127.0.0.1:55434/ocheso_test
```

`supabase_shim.sql` stands in for the parts of Supabase the schema relies on.
**Never apply it to a real Supabase project.** It copies two details on
purpose, because a test that skips them passes for the wrong reasons: Supabase's
default grants of ALL to `anon`/`authenticated` (so the schema's revokes are
really exercised), and pgcrypto living in the `extensions` schema (so pinned
search paths are really exercised).
