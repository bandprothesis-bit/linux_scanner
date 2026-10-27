#!/bin/sh
# Push vulnagent to many hosts over SSH and install it.
#   ./deploy-fleet.sh hosts.txt [config.json]
# hosts.txt: one "user@host" per line (# comments allowed). The remote user
# needs sudo. If config.json is given it is installed as /etc/vulnagent/config.json
# (overwriting the remote one); otherwise an existing remote config is kept.
set -eu

HOSTS=${1:?usage: $0 hosts.txt [config.json]}
CONFIG=${2:-}
HERE=$(cd "$(dirname "$0")" && pwd)
TARBALL=$(mktemp /tmp/vulnagent.XXXXXX.tgz)
trap 'rm -f "$TARBALL"' EXIT
tar -C "$HERE" -czf "$TARBALL" vulnagent.py config.example.json install.sh bootstrap.sh README.md systemd

grep -v '^\s*#' "$HOSTS" | grep -v '^\s*$' | while read -r host; do
    echo "==> $host"
    if ! scp -q "$TARBALL" "$host:/tmp/vulnagent.tgz" </dev/null; then
        echo "    scp failed"; continue
    fi
    if [ -n "$CONFIG" ]; then
        scp -q "$CONFIG" "$host:/tmp/vulnagent-config.json" </dev/null
    fi
    ssh -t "$host" 'set -e; d=$(mktemp -d); tar -C "$d" -xzf /tmp/vulnagent.tgz;
        sudo sh "$d/install.sh";
        if [ -f /tmp/vulnagent-config.json ]; then sudo install -m 0640 /tmp/vulnagent-config.json /etc/vulnagent/config.json; rm -f /tmp/vulnagent-config.json; fi;
        rm -rf "$d" /tmp/vulnagent.tgz' </dev/null || echo "    install failed on $host"
done
