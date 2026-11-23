#!/bin/sh
# Nightly logical backup of the registry database (runs in the "backup" container).
# Custom-format pg_dump: compressed, and restorable table by table with pg_restore.
# Keeps BACKUP_KEEP_DAYS days. Copy /backups off the machine too (object storage with
# versioning and a retention lock): a backup on the same disk is not a backup.
set -eu
umask 077
printf 'db:5432:*:%s:%s\n' "${PGUSER}" "$(cat /run/secrets/db_password)" > /tmp/pgpass
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="/backups/guardian-${stamp}.dump"
pg_dump --format=custom --no-owner --file="${out}.part"
mv "${out}.part" "${out}"
pg_restore --list "${out}" > /dev/null   # the archive is readable
find /backups -name 'guardian-*.dump' -mtime +"${BACKUP_KEEP_DAYS:-14}" -delete
echo "backup ok: ${out} ($(du -h "${out}" | cut -f1))"
