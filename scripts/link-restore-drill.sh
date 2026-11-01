#!/bin/sh
# Restore drill for the production tinycloud-link backups (TC-887).
# Run by an operator, never on the CVM: it needs the age PRIVATE key.
#
#   link-restore-drill.sh [--file <dump.age>]
#
# 1. Without --file, find the newest backup object in the R2 bucket and download it.
# 2. Decrypt with the identity in AGE_IDENTITY_FILE.
# 3. pg_restore into a THROWAWAY Postgres and print the row count of every table
#    the service owns (names, acme_account, cert_issuances).
#
# Env:
#   AGE_IDENTITY_FILE                       age identity (private key) file. Required.
#   LINK_BACKUP_R2_ENDPOINT / _BUCKET / _ACCESS_KEY_ID / _SECRET_ACCESS_KEY
#                                           R2 read credentials. Not needed with --file.
#   RESTORE_DATABASE_URL                    Scratch database to restore into. It is wiped
#                                           (--clean --if-exists) and MUST be disposable.
#                                           Default: start a throwaway postgres:17-alpine
#                                           container with docker and remove it afterwards.
#   RESTORE_EXPECT_MIN_NAMES / _ACME_ACCOUNT / _CERT_ISSUANCES
#                                           Optional per-table floors; fail if a count is lower.
set -eu

die() { echo "restore-drill: $*" >&2; exit 1; }

file=
while [ $# -gt 0 ]; do
  case "$1" in
    --file) [ $# -ge 2 ] || die "--file needs a path"; file=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "${AGE_IDENTITY_FILE:-}" ] && [ -r "$AGE_IDENTITY_FILE" ] || die "AGE_IDENTITY_FILE must point to a readable age identity file"
for tool in age pg_restore psql; do command -v "$tool" >/dev/null 2>&1 || die "$tool is required"; done

# pg_restore must be >= 17 to read the 17 archive. curl >= 8 is needed for the download: older
# curl (e.g. 7.81 on Ubuntu 22.04) does not sign x-amz-content-sha256 with --aws-sigv4, so R2 rejects it.
pg_major=$(pg_restore --version | sed -n 's/^pg_restore (PostgreSQL) \([0-9][0-9]*\).*/\1/p')
case "$pg_major" in ''|*[!0-9]*) die "cannot parse pg_restore version: $(pg_restore --version)" ;; esac
[ "$pg_major" -ge 17 ] || die "pg_restore $pg_major is too old; version 17 or newer is required to read the backup archive"
if [ -z "$file" ]; then
  command -v curl >/dev/null 2>&1 || die "curl is required"
  curl_major=$(curl --version | sed -n '1s/^curl \([0-9][0-9]*\)\..*/\1/p')
  case "$curl_major" in ''|*[!0-9]*) die "cannot parse curl version: $(curl --version | head -n 1)" ;; esac
  [ "$curl_major" -ge 8 ] || die "curl $curl_major is too old; version 8 or newer is required (7.x does not sign x-amz-content-sha256 for --aws-sigv4)"
fi

work=$(mktemp -d)
container=
cleanup() {
  [ -z "$container" ] || docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

s3() { # s3 <path-and-query> [curl args...]; credentials go to curl on stdin, not argv
  path=$1; shift
  printf 'user = "%s:%s"\n' "$LINK_BACKUP_R2_ACCESS_KEY_ID" "$LINK_BACKUP_R2_SECRET_ACCESS_KEY" | curl --config - \
    --fail --silent --show-error --aws-sigv4 "aws:amz:auto:s3" \
    -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" "$@" \
    "${LINK_BACKUP_R2_ENDPOINT%/}/${LINK_BACKUP_R2_BUCKET}${path}"
}

if [ -z "$file" ]; then
  for name in LINK_BACKUP_R2_ENDPOINT LINK_BACKUP_R2_BUCKET LINK_BACKUP_R2_ACCESS_KEY_ID LINK_BACKUP_R2_SECRET_ACCESS_KEY; do
    eval "value=\${$name:-}"
    [ -n "$value" ] || die "$name is required (or pass --file)"
  done
  # Keys embed a UTC timestamp, so lexical order is chronological. 6 h cadence x 14 d
  # retention is ~56 objects, well inside one 1000-key ListObjectsV2 page.
  s3 "/?list-type=2&prefix=tinycloud-link/" > "$work/list.xml"
  latest=$(grep -o '<Key>[^<]*</Key>' "$work/list.xml" | sed 's/<[^>]*>//g' | grep '\.dump\.age$' | sort | tail -n 1)
  [ -n "$latest" ] || die "no backup objects found in the bucket"
  echo "restore-drill: latest backup is ${latest}"
  s3 "/${latest}" -o "$work/dump.age"
  file=$work/dump.age
fi
[ -r "$file" ] || die "cannot read $file"

age -d -i "$AGE_IDENTITY_FILE" -o "$work/dump" "$file" || die "decryption failed (wrong identity?)"
echo "restore-drill: decrypted ($(wc -c < "$work/dump") bytes)"

if [ -z "${RESTORE_DATABASE_URL:-}" ]; then
  command -v docker >/dev/null 2>&1 || die "set RESTORE_DATABASE_URL to a scratch database, or install docker"
  password=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  container=$(docker run -d --rm -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=restore_drill -p 127.0.0.1::5432 postgres:17-alpine)
  port=$(docker port "$container" 5432/tcp | sed 's/.*://' | head -n 1)
  RESTORE_DATABASE_URL="postgresql://postgres:${password}@127.0.0.1:${port}/restore_drill"
  tries=0
  until psql "$RESTORE_DATABASE_URL" -Atqc 'select 1' >/dev/null 2>&1; do
    tries=$((tries + 1)); [ "$tries" -lt 60 ] || die "throwaway postgres did not become ready"
    sleep 1
  done
fi

# --no-owner/--no-privileges: the production role `tinycloud_link` does not exist in the scratch database.
pg_restore --clean --if-exists --no-owner --no-privileges --exit-on-error -d "$RESTORE_DATABASE_URL" "$work/dump" || die "pg_restore failed"

check_table() { # check_table <table> <minimum or empty>
  count=$(psql "$RESTORE_DATABASE_URL" -Atqc "select count(*) from $1") || die "cannot count rows in $1 (table missing from the backup?)"
  echo "restore-drill: $1 rows = ${count}"
  if [ -n "$2" ] && [ "$count" -lt "$2" ]; then
    die "expected at least $2 rows in $1"
  fi
}
check_table names "${RESTORE_EXPECT_MIN_NAMES:-}"
check_table acme_account "${RESTORE_EXPECT_MIN_ACME_ACCOUNT:-}"
check_table cert_issuances "${RESTORE_EXPECT_MIN_CERT_ISSUANCES:-}"
echo "restore-drill: OK"
