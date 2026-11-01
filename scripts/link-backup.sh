#!/bin/sh
# Encrypted Postgres backup loop for the production tinycloud-link CVM (TC-887).
#
# Entrypoint of the `postgres-backup` sidecar image (Dockerfile.backup:
# postgres:17-alpine@sha256 base + age + curl, this script baked in). The compose
# service runs it with `init: true` and a tmpfs /tmp. Same design as the location
# registry's registry-backup.sh (TC-1447).
#
# pg_dump -Fc -> age -r <public recipient> -> S3 PUT to Cloudflare R2.
# The CVM holds only the age PUBLIC recipient; the identity (private key) is
# operator-held off-CVM. The plaintext dump exists only briefly in a tmpfs
# (RAM-backed, never the container's overlay disk) and is deleted before upload.
# The R2 credentials are handed to curl on stdin, never in its argv.
#
# Env: PGHOST PGUSER PGPASSWORD PGDATABASE (libpq), LINK_BACKUP_R2_ENDPOINT,
# LINK_BACKUP_R2_BUCKET, LINK_BACKUP_R2_ACCESS_KEY_ID,
# LINK_BACKUP_R2_SECRET_ACCESS_KEY, LINK_BACKUP_AGE_RECIPIENT,
# BACKUP_INTERVAL_SECONDS (default 21600 = 6 h), BACKUP_RETRY_SECONDS (default 600),
# BACKUP_ONCE=1 (one attempt, exit status reflects it; used by CI).
set -eu

for name in PGHOST PGUSER PGPASSWORD PGDATABASE LINK_BACKUP_R2_ENDPOINT LINK_BACKUP_R2_BUCKET LINK_BACKUP_R2_ACCESS_KEY_ID LINK_BACKUP_R2_SECRET_ACCESS_KEY LINK_BACKUP_AGE_RECIPIENT; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || { echo "backup: $name is required" >&2; exit 1; }
done
case "$LINK_BACKUP_AGE_RECIPIENT" in
  age1*) ;;
  AGE-SECRET-KEY-*) echo "backup: LINK_BACKUP_AGE_RECIPIENT is a PRIVATE key; refusing to start" >&2; exit 1 ;;
  *) echo "backup: LINK_BACKUP_AGE_RECIPIENT must be an age1... public recipient" >&2; exit 1 ;;
esac

# mktemp honours TMPDIR and falls back to /tmp, which the compose service mounts as tmpfs.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Exit promptly on `docker stop`; EXIT then removes $work.
trap 'exit 143' TERM INT

# Interruptible sleep: a trap only runs between commands, so a foreground sleep would delay TERM handling.
nap() { sleep "$1" & wait $!; }

backup_once() {
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  key="tinycloud-link/${PGDATABASE}-${stamp}.dump.age"
  # `|| return 1`: set -e is ignored inside `if backup_once`, so fail each step explicitly.
  # Dump to a file, not a pipe, so a pg_dump failure cannot upload a truncated archive under POSIX sh.
  pg_dump -Fc -f "$work/dump" || return 1
  age -r "$LINK_BACKUP_AGE_RECIPIENT" -o "$work/dump.age" "$work/dump" || return 1
  rm -f "$work/dump"
  # printf is a shell builtin, so the credentials never appear in a process argument list.
  # R2 access keys are hex, so no quoting of the config values is needed.
  printf 'user = "%s:%s"\n' "$LINK_BACKUP_R2_ACCESS_KEY_ID" "$LINK_BACKUP_R2_SECRET_ACCESS_KEY" | curl --config - \
    --fail --silent --show-error --max-time 600 \
    --aws-sigv4 "aws:amz:auto:s3" \
    -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
    -H "If-None-Match: *" \
    -T "$work/dump.age" \
    "${LINK_BACKUP_R2_ENDPOINT%/}/${LINK_BACKUP_R2_BUCKET}/${key}" || return 1
  size=$(wc -c < "$work/dump.age")
  rm -f "$work/dump.age"
  echo "backup: uploaded ${key} (${size} bytes)"
}

if [ "${BACKUP_ONCE:-}" = 1 ]; then
  backup_once
  exit 0
fi

while true; do
  if backup_once; then
    nap "${BACKUP_INTERVAL_SECONDS:-21600}"
  else
    echo "backup: FAILED; retrying in ${BACKUP_RETRY_SECONDS:-600}s" >&2
    rm -f "$work/dump" "$work/dump.age"
    nap "${BACKUP_RETRY_SECONDS:-600}"
  fi
done
