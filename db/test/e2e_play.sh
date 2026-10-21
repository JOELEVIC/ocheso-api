#!/bin/sh
# Sets up a throwaway local database and PostgREST, then plays whole
# tournaments through the API (db/test/e2e_play.py). Local only.
#
#   PG="-h /tmp/och -p 55434 -U postgres" PYTHON=python3 db/test/e2e_play.sh
set -eu
cd "$(dirname "$0")/../.."
PG=${PG:-"-h 127.0.0.1 -p 55434 -U postgres"}
PYTHON=${PYTHON:-python3}
DBNAME=ocheso_e2e
PORT=${E2E_PORT:-3010}
SECRET="e2e-local-only-secret-$(date +%s)-not-for-anything-real"

dropdb $PG --if-exists $DBNAME
createdb $PG $DBNAME
for f in db/test/supabase_shim.sql db/schema.sql db/play.sql; do
  psql $PG -d $DBNAME -X -q -v ON_ERROR_STOP=1 -f "$f" >/dev/null 2>&1
done
# PostgREST logs in as an authenticator and becomes anon or authenticated.
psql $PG -d $DBNAME -X -q -c "do \$\$ begin create role authenticator login noinherit; exception when duplicate_object then null; end \$\$; grant anon, authenticated to authenticator;"

HOST=$(echo "$PG" | sed -E 's/.*-h ([^ ]+).*/\1/')
PGPORT=$(echo "$PG" | sed -E 's/.*-p ([^ ]+).*/\1/')
URI="postgresql://authenticator@/$DBNAME?host=$HOST&port=$PGPORT"

PGRST_DB_URI="$URI" PGRST_DB_SCHEMAS=public PGRST_DB_ANON_ROLE=anon \
  PGRST_JWT_SECRET="$SECRET" PGRST_SERVER_PORT=$PORT PGRST_LOG_LEVEL=crit \
  postgrest >/tmp/ocheso-e2e-postgrest.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT
sleep 2

E2E_DB="postgresql://postgres@/$DBNAME?host=$HOST&port=$PGPORT" E2E_JWT_SECRET="$SECRET" \
  E2E_REST="http://127.0.0.1:$PORT" $PYTHON db/test/e2e_play.py
