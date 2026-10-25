#!/bin/sh
# Every database test, each on its own throwaway database: the shim, then the
# whole schema through db/apply.sh - twice, because the second pass is what
# proves every file can be re-applied over itself. Local only.
#
#   PG="-h 127.0.0.1 -p 55434 -U postgres" PYTHON=python3 db/test/test_db.sh
set -eu
cd "$(dirname "$0")/../.."
PG=${PG:-"-h 127.0.0.1 -p 55434 -U postgres"}
PYTHON=${PYTHON:-python3}
HOST=$(echo "$PG" | sed -E 's/.*-h ([^ ]+).*/\1/')
PGPORT=$(echo "$PG" | sed -E 's/.*-p ([^ ]+).*/\1/')
out=$(mktemp)
trap 'rm -f "$out"' EXIT
status=0
for suite in rls play agents platforms; do
  db="ocheso_test_$suite"
  dropdb $PG --if-exists "$db" 2>/dev/null
  createdb $PG "$db"
  psql $PG -d "$db" -X -q -v ON_ERROR_STOP=1 -f db/test/supabase_shim.sql >/dev/null 2>&1
  db/apply.sh $PG -d "$db" >/dev/null
  db/apply.sh $PG -d "$db" >/dev/null
  echo "== test_$suite"
  $PYTHON "db/test/test_$suite.py" "postgresql://postgres@$HOST:$PGPORT/$db" >"$out" 2>&1 || status=1
  grep -v '^ok' "$out" || true
done
exit $status
