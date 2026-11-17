#!/usr/bin/env bash
# Restore a backup made by backup.sh. This REPLACES the current database and uploaded files.
#
#   sudo ./restore.sh backups/20261117-020000
#
# On a new server: copy this folder (or the repository's defectdojo/server folder) and the
# backup there, then run restore.sh. It puts back .env and the certificates from the backup
# when this folder has none, so the secrets match the database. Then it starts DefectDojo
# with the version the backup was made with.
set -euo pipefail

src=${1:-}
yes=0; [ "${2:-}" = "--yes" ] && yes=1
[ -n "$src" ] && [ -f "$src/database.dump" ] || { echo "Usage: sudo $0 <backup folder> [--yes]" >&2; exit 2; }
src=$(readlink -f "$src")
cd "$(dirname "$(readlink -f "$0")")"
[ "$(id -u)" -eq 0 ] || { echo "Run it as root: sudo $0 $*" >&2; exit 1; }

if [ ! -f .env ]; then
    echo "no .env here: taking .env, certificates and settings from the backup"
    tar -xzf "$src/config.tar.gz"
elif ! tar -xzOf "$src/config.tar.gz" .env 2>/dev/null | grep -q "^DD_CREDENTIAL_AES_256_KEY=$(sed -n 's/^DD_CREDENTIAL_AES_256_KEY=//p' .env)$"; then
    echo "WARNING: this backup was made with another .env. Credentials stored in DefectDojo (for"
    echo "example tool configurations) can only be read with the original DD_CREDENTIAL_AES_256_KEY,"
    echo "which is in $src/config.tar.gz."
fi
. ./.env
ver=$(cat "$src/VERSION" 2>/dev/null || echo "$DD_VERSION")
[ "$ver" = "$DD_VERSION" ] || echo "NOTE: the backup is from DefectDojo $ver, .env says $DD_VERSION; restoring with $ver, upgrade afterwards."

if [ "$yes" -ne 1 ]; then
    read -r -p "Replace the DefectDojo database and files with $src? Type yes: " a
    [ "$a" = yes ] || { echo "cancelled"; exit 1; }
fi

export DD_VERSION="$ver"
docker compose down
docker compose up -d postgres valkey
until docker compose exec -T postgres pg_isready -U defectdojo -d defectdojo >/dev/null 2>&1; do sleep 2; done
docker compose exec -T postgres dropdb -U defectdojo --if-exists defectdojo
docker compose exec -T postgres createdb -U defectdojo -O defectdojo defectdojo
docker compose exec -T postgres pg_restore -U defectdojo -d defectdojo --no-owner --role=defectdojo < "$src/database.dump"
docker compose up -d
docker compose exec -T uwsgi sh -c 'find /app/media -mindepth 1 -delete; tar -C /app/media -xzf -' < "$src/media.tar.gz"
echo "restored $src (DefectDojo $ver)."
[ "$ver" = "$(sed -n 's/^DD_VERSION=//p' .env)" ] || echo "To upgrade: ./backup.sh && docker compose pull && docker compose up -d"
