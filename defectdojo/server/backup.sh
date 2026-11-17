#!/usr/bin/env bash
# Back up DefectDojo while it runs: the database, the uploaded files, .env (secrets) and
# the certificates, into backups/<date>-<time>/. Older backups are deleted after --keep days.
#
#   sudo ./backup.sh                 # keep 14 days
#   sudo ./backup.sh --keep 30
#   sudo ./backup.sh --dir /mnt/backup/defectdojo
#
# Copy the backups to another machine as well: a backup on the same disk doesn't survive
# the loss of that disk. They hold the secrets in .env, so keep them private.
set -euo pipefail

KEEP=14
DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --keep) KEEP=${2:?--keep needs a number of days}; shift 2 ;;
        --dir) DIR=${2:?--dir needs a folder}; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$(readlink -f "$0")")"
[ "$(id -u)" -eq 0 ] || { echo "Run it as root: sudo $0" >&2; exit 1; }
[ -f .env ] || { echo "no .env here: run setup.sh first" >&2; exit 1; }
DIR=${DIR:-$(pwd)/backups}
mkdir -p "$DIR"; chmod 700 "$DIR"
out="$DIR/$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 "$out"

echo "backing up to $out"
docker compose exec -T postgres pg_dump -U defectdojo -d defectdojo -Fc > "$out/database.dump"
docker compose exec -T uwsgi tar -C /app/media -czf - . > "$out/media.tar.gz"
tar -czf "$out/config.tar.gz" .env certs ca extra_settings
. ./.env
echo "$DD_VERSION" > "$out/VERSION"
chmod 600 "$out"/*

# a dump that is too small means pg_dump failed quietly
[ "$(stat -c %s "$out/database.dump")" -gt 1024 ] || { echo "ERROR: the database dump is empty" >&2; exit 1; }
du -sh "$out" | cut -f1 | xargs -I{} echo "done: {} (DefectDojo $DD_VERSION)"

if [ "$KEEP" -gt 0 ]; then
    find "$DIR" -mindepth 1 -maxdepth 1 -type d -name '20*' -mtime +"$KEEP" -exec rm -rf {} +
fi
