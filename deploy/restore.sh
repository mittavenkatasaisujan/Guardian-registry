#!/bin/sh
# Restore a backup into a NEW database (never over the live one):
#   docker compose -f deploy/docker-compose.yml exec backup /restore.sh /backups/guardian-....dump guardian_restored
# Then point a node at it (GR_DB=postgresql://.../guardian_restored), check
# GET /v1/admin/audit/verify, and only then switch over.
set -eu
umask 077
dump="${1:?usage: restore.sh <dump file> <new database name>}"
target="${2:?usage: restore.sh <dump file> <new database name>}"
printf 'db:5432:*:%s:%s\n' "${PGUSER}" "$(cat /run/secrets/db_password)" > /tmp/pgpass
if psql -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${target}'" | grep -q 1; then
  echo "database ${target} already exists; pick a new name" >&2
  exit 1
fi
createdb "${target}"
pg_restore --no-owner --exit-on-error --dbname="${target}" "${dump}"
echo "restored ${dump} into ${target}"
