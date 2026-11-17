#!/usr/bin/env bash
# DefectDojo for vulnagent: first-time setup, and safe to run again.
#
#   sudo ./setup.sh --host dojo.example.local     # HTTPS with a certificate from a local CA
#   sudo ./setup.sh --host 10.0.0.5 --http        # plain HTTP on 8080 (closed lab networks only)
#
# It writes .env with random secrets (never overwritten), creates the certificate,
# starts DefectDojo, waits until it answers, and creates the API user "vulnagent" for
# the agents. Run it again to start DefectDojo after a change, or with --agent-token
# to print the agents' API key again.
set -euo pipefail

DD_VERSION_DEFAULT=3.5.200
NGINX_UID=1001            # the user the defectdojo-nginx image runs as

usage() {
    cat <<'EOF'
Usage: sudo ./setup.sh [options]

  --host NAME        DNS name or IP address the agents and browsers use (default: this
                     machine's full host name). Put it in the certificate and allowed hosts.
  --http             Plain HTTP on port 8080 instead of HTTPS on 8443. Only for closed
                     lab networks: API keys then cross the network in clear text.
  --install-docker   Install Docker and the Compose plugin with apt (Debian, Ubuntu).
  --renew-cert       Issue a new server certificate from the local CA (keeps the CA).
  --agent-token      Only print the API key of the "vulnagent" user again.
  --new-agent-token  Replace that key with a new one (the old key stops working).
  --no-agent-user    Don't create the "vulnagent" API user.
  --no-pull          Don't download the images (they were loaded with docker load).
  -h, --help         This help.
EOF
}

HOST=""; HTTP=0; INSTALL_DOCKER=0; RENEW=0; TOKEN_ONLY=0; NEW_TOKEN=0; AGENT_USER=1; PULL=1
while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST=${2:?--host needs a value}; shift 2 ;;
        --host=*) HOST=${1#--host=}; shift ;;
        --http) HTTP=1; shift ;;
        --install-docker) INSTALL_DOCKER=1; shift ;;
        --renew-cert) RENEW=1; shift ;;
        --agent-token) TOKEN_ONLY=1; shift ;;
        --new-agent-token) TOKEN_ONLY=1; NEW_TOKEN=1; shift ;;
        --no-agent-user) AGENT_USER=0; shift ;;
        --no-pull) PULL=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

cd "$(dirname "$(readlink -f "$0")")"
[ "$(id -u)" -eq 0 ] || { echo "Run it as root: sudo $0 $*" >&2; exit 1; }

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# random string of letters and digits (safe in .env, URLs and shell)
rand() { local s=""; while [ ${#s} -lt "$1" ]; do s+=$(head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9'); done; printf '%s' "${s:0:$1}"; }

# the agent API user: get or create, Maintainer globally (it creates one product per machine)
agent_token() {
    docker compose exec -T -e "VULNAGENT_NEW_TOKEN=$NEW_TOKEN" uwsgi python manage.py shell 2>/dev/null <<'PY' | sed -n 's/^VULNAGENT_TOKEN=//p'
import os
from dojo.models import Dojo_User
from dojo.authorization.models import Global_Role, Role
from rest_framework.authtoken.models import Token
u, created = Dojo_User.objects.get_or_create(username="vulnagent", defaults={
    "first_name": "vulnagent", "last_name": "agents", "email": "vulnagent@localhost", "is_active": True})
if created:
    u.set_unusable_password()
    u.save()
role = Role.objects.get(name="Maintainer")
gr, _ = Global_Role.objects.get_or_create(user=u, defaults={"role": role})
if gr.role_id != role.id:
    gr.role = role
    gr.save()
if os.environ.get("VULNAGENT_NEW_TOKEN") == "1":
    Token.objects.filter(user=u).delete()
t, _ = Token.objects.get_or_create(user=u)
print("VULNAGENT_TOKEN=" + t.key)
PY
}

# ---------------------------------------------------------------- 1. Docker
if ! docker compose version >/dev/null 2>&1; then
    if [ "$INSTALL_DOCKER" -eq 1 ]; then
        say "installing Docker"
        command -v apt-get >/dev/null || die "--install-docker works only with apt (Debian, Ubuntu). Install Docker Engine and the Compose plugin, then run this again."
        . /etc/os-release
        pkgs="docker.io docker-compose-v2"
        [ "${ID:-}" = debian ] && pkgs="docker.io docker-compose"
        apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pkgs openssl curl
        systemctl enable --now docker
        docker compose version >/dev/null 2>&1 || die "Docker is installed, but 'docker compose' doesn't work. Install the Compose v2 plugin."
    else
        die "Docker with the Compose plugin is needed ('docker compose version' failed). Run with --install-docker on Debian/Ubuntu, or see README.md."
    fi
fi
command -v openssl >/dev/null || die "openssl is needed"

if [ "$TOKEN_ONLY" -eq 1 ]; then
    tok=$(agent_token) || true
    [ -n "$tok" ] || die "could not read the token: is DefectDojo running (docker compose ps)?"
    echo "$tok"; exit 0
fi

# ---------------------------------------------------------------- 2. .env
mkdir -p certs ca extra_settings backups
chmod 700 ca backups
if [ ! -f .env ]; then
    say "writing .env with new random secrets"
    [ -n "$HOST" ] || HOST=$(hostname -f 2>/dev/null || hostname)
    ips=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' | grep -v ':' || true)
    names="$HOST"; for ip in $ips localhost 127.0.0.1; do case ",$names," in *",$ip,"*) ;; *) names="$names,$ip" ;; esac; done
    if [ "$HTTP" -eq 1 ]; then
        https=false; cookies=False; site="http://$HOST:8080"; origins="[]"
    else
        https=true; cookies=True; site="https://$HOST:8443"
        origins=$(printf '%s\n' ${names//,/ } | sed 's|.*|https://&:8443|' | paste -sd, -)
    fi
    adminpw=$(rand 24)
    until printf '%s' "$adminpw" | grep -q '[A-Z]' && printf '%s' "$adminpw" | grep -q '[a-z]' && printf '%s' "$adminpw" | grep -q '[0-9]'; do adminpw=$(rand 24); done
    umask 077
    cat > .env <<EOF
# DefectDojo for vulnagent. Written by setup.sh on $(date -u +%Y-%m-%d). Keep this file secret
# and back it up: without DD_CREDENTIAL_AES_256_KEY a database backup can't be fully restored.

# version: change it, then run ./backup.sh && docker compose pull && docker compose up -d
DD_VERSION=$DD_VERSION_DEFAULT
DD_IMAGE_REGISTRY=docker.io

# how the server is reached
DD_HOSTNAME=$HOST
DD_HTTPS=$https
DD_SECURE_COOKIES=$cookies
DD_SITE_URL=$site
DD_ALLOWED_HOSTS=$names
DD_CSRF_TRUSTED_ORIGINS=$origins
DD_BIND_ADDRESS=0.0.0.0
DD_PORT=8080
DD_TLS_PORT=8443

# admin user, created on the first start only (change the password in DefectDojo afterwards)
DD_ADMIN_USER=admin
DD_ADMIN_MAIL=admin@defectdojo.local
DD_ADMIN_PASSWORD=$adminpw

# secrets
DD_DATABASE_PASSWORD=$(rand 32)
DD_SECRET_KEY=$(rand 50)
DD_CREDENTIAL_AES_256_KEY=$(rand 32)
EOF
    umask 022
    chmod 600 .env
else
    say "keeping the existing .env"
    [ -z "$HOST" ] || echo "   (--host is used only when .env is created; edit DD_HOSTNAME, DD_SITE_URL, DD_ALLOWED_HOSTS and DD_CSRF_TRUSTED_ORIGINS in .env to change it)"
fi
set -a; . ./.env; set +a

# ---------------------------------------------------------------- 3. certificate
if [ "$DD_HTTPS" = true ]; then
    if [ ! -f certs/nginx.crt ] || [ "$RENEW" -eq 1 ]; then
        if [ -f certs/nginx.crt ] && [ ! -f ca/ca.key ]; then
            die "certs/nginx.crt was not made by setup.sh (no ca/ca.key): replace certs/nginx.crt and certs/nginx.key yourself"
        fi
        if [ ! -f ca/ca.key ]; then
            say "creating a local certificate authority (ca/defectdojo-ca.crt, valid 10 years)"
            openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 3650 \
                -keyout ca/ca.key -out ca/defectdojo-ca.crt \
                -subj "/CN=DefectDojo local CA ($DD_HOSTNAME)" \
                -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
                -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
            chmod 600 ca/ca.key
        fi
        say "issuing the server certificate for $DD_ALLOWED_HOSTS (valid 825 days)"
        san=""
        for n in ${DD_ALLOWED_HOSTS//,/ }; do
            [ "$n" = "*" ] && continue
            if [[ "$n" =~ ^[0-9.]+$ ]]; then san="$san,IP:$n"; else san="$san,DNS:$n"; fi
        done
        tmp=$(mktemp -d)
        openssl req -new -nodes -newkey rsa:2048 -keyout "$tmp/server.key" -out "$tmp/server.csr" -subj "/CN=$DD_HOSTNAME" 2>/dev/null
        printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "${san#,}" > "$tmp/ext"
        openssl x509 -req -in "$tmp/server.csr" -CA ca/defectdojo-ca.crt -CAkey ca/ca.key -CAcreateserial -CAserial ca/ca.srl \
            -days 825 -sha256 -extfile "$tmp/ext" -out "$tmp/server.crt" 2>/dev/null
        cat "$tmp/server.crt" ca/defectdojo-ca.crt > certs/nginx.crt
        install -m 640 "$tmp/server.key" certs/nginx.key
        rm -rf "$tmp"
        [ "$RENEW" -eq 1 ] && docker compose restart nginx >/dev/null 2>&1 || true
    fi
    # the nginx container runs as uid 1001 (group 0): it must be able to read the key
    chown "$NGINX_UID:0" certs/nginx.key certs/nginx.crt
    chmod 640 certs/nginx.key; chmod 644 certs/nginx.crt
    openssl x509 -in certs/nginx.crt -noout -checkend 2592000 >/dev/null || echo "WARNING: certs/nginx.crt expires within 30 days: run ./setup.sh --renew-cert, or replace it"
fi
if [ "$RENEW" -eq 1 ]; then
    [ "$DD_HTTPS" = true ] && echo "certificate renewed" || echo "HTTPS is off (DD_HTTPS=false in .env): no certificate to renew"
    exit 0
fi

# ---------------------------------------------------------------- 4. start
if [ "$PULL" -eq 1 ]; then
    say "downloading DefectDojo $DD_VERSION (about 1.5 GB the first time)"
    docker compose pull -q
fi
say "starting"
docker compose up -d

say "waiting for the database setup (the first start takes 3 to 5 minutes)"
for i in $(seq 1 180); do
    cid=$(docker compose ps -aq initializer)
    st=$( [ -n "$cid" ] && docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$cid" || echo "none 0")
    case "$st" in
        "exited 0") break ;;
        exited*) docker compose logs --tail 40 initializer; die "the initializer failed (above). Fix it, then run ./setup.sh again." ;;
    esac
    sleep 5
done
[ "${st:-}" = "exited 0" ] || die "the initializer did not finish within 15 minutes: docker compose logs initializer"

if [ "$DD_HTTPS" = true ]; then url="https://127.0.0.1:$DD_TLS_PORT/login"; else url="http://127.0.0.1:$DD_PORT/login"; fi
if command -v curl >/dev/null; then
    for i in $(seq 1 60); do
        code=$(curl -sk -o /dev/null -w '%{http_code}' "$url" || true)
        case "$code" in 200|302) break ;; esac
        sleep 5
    done
    case "${code:-}" in 200|302) echo "DefectDojo answers ($url: HTTP $code)" ;; *) echo "WARNING: $url answered '${code:-nothing}' after 5 minutes: docker compose logs uwsgi nginx" ;; esac
fi

# ---------------------------------------------------------------- 5. agent API user
tok=""
if [ "$AGENT_USER" -eq 1 ]; then
    tok=$(agent_token) || true
    [ -n "$tok" ] || echo "WARNING: could not create the vulnagent API user: create it in DefectDojo (Users > Add user, global role Maintainer) and copy its API v2 key"
fi

# ---------------------------------------------------------------- 6. summary
pub=$(printf '%s' "$DD_SITE_URL" | sed 's|/*$||')
cat <<EOF

==========================================================================
DefectDojo $DD_VERSION is running: $pub
  Admin:     $DD_ADMIN_USER / $DD_ADMIN_PASSWORD   (also in .env; change it after the first login)
EOF
[ -n "$tok" ] && echo "  Agent key: $tok   (user vulnagent; print it again with ./setup.sh --agent-token)"
if [ "$DD_HTTPS" = true ]; then cat <<EOF
  CA:        $(pwd)/ca/defectdojo-ca.crt   (copy it to the agents, see README.md)
EOF
fi
cat <<EOF

Firewall: the agents and browsers need TCP $( [ "$DD_HTTPS" = true ] && echo "$DD_TLS_PORT (and $DD_PORT, which redirects)" || echo "$DD_PORT" ).
Backups:  ./backup.sh   (add it to cron, see README.md)
==========================================================================
EOF
