#!/bin/sh
# Applies the database, in order, each file in its own transaction:
#   schema.sql -> play.sql -> agents.sql -> platforms.sql
# Every file is idempotent, so running this again is safe. psql's own
# arguments pass straight through - a connection string or -h/-p/-U/-d:
#
#   db/apply.sh "postgresql://postgres@127.0.0.1:55434/ocheso_test"
#   db/apply.sh -h 127.0.0.1 -p 55434 -U postgres -d ocheso_test
#
# This applies what is in the files to whatever database it is pointed at.
# Pointing it at production is a deliberate act (docs/OCHESO_PLATFORMS.md, H5);
# test databases need db/test/supabase_shim.sql first, and that file must
# never go near a real Supabase project.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
for f in schema.sql play.sql agents.sql platforms.sql; do
  echo "applying $f"
  PGOPTIONS="${PGOPTIONS:--c client_min_messages=warning}" \
    psql "$@" -X -q -v ON_ERROR_STOP=1 -1 -f "$here/$f" >/dev/null
done
echo "done"
