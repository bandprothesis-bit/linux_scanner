#!/bin/sh
# Install the DefectDojo add-on: after every daily vulnagent run, the report is
# uploaded to DefectDojo. Installs vulnagent itself first if it is missing.
#   sudo DD_API_TOKEN=xxxx sh defectdojo/install.sh --url https://defectdojo.example.local
#   sudo sh defectdojo/install.sh            (keeps an existing /etc/vulnagent/defectdojo.json)
#   sudo sh defectdojo/install.sh --uninstall
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=/usr/local/sbin/vulnagent-dojo
CONF=/etc/vulnagent/defectdojo.json
DROPIN_DIR=/etc/systemd/system/vulnagent.service.d
CRON=/etc/cron.d/vulnagent

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo sh $0)" >&2; exit 1; }

URL=""
while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL=${2:?--url needs a value}; shift 2 ;;
        --url=*) URL=${1#--url=}; shift ;;
        --uninstall)
            rm -f "$BIN" "$DROPIN_DIR/defectdojo.conf"
            rmdir "$DROPIN_DIR" 2>/dev/null || true
            command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
            [ -f "$CRON" ] && sed -i 's|; \[ \$? -le 1 \] && /usr/local/sbin/vulnagent-dojo.*$||' "$CRON"
            echo "DefectDojo add-on removed ($CONF kept)."
            exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [ ! -x /usr/local/sbin/vulnagent ]; then
    echo "vulnagent is not installed yet - installing it first"
    sh "$HERE/../install.sh"
fi

install -m 0755 "$HERE/vulnagent-dojo.py" "$BIN"
install -d -m 0750 /etc/vulnagent
if [ ! -f "$CONF" ]; then
    install -m 0600 "$HERE/defectdojo.example.json" "$CONF"
    echo "created $CONF"
fi
# fill in url / token given on the command line or in the environment
if [ -n "$URL" ] || [ -n "${DD_API_TOKEN:-}" ]; then
    DD_URL="$URL" python3 - "$CONF" <<'EOF'
import json, os, sys
p = sys.argv[1]
with open(p) as f:
    c = json.load(f)
if os.environ.get("DD_URL"):
    c["url"] = os.environ["DD_URL"]
if os.environ.get("DD_API_TOKEN"):
    c["api_token"] = os.environ["DD_API_TOKEN"]
with open(p, "w") as f:
    json.dump(c, f, indent=2)
EOF
    chmod 0600 "$CONF"
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    install -d "$DROPIN_DIR"
    install -m 0644 "$HERE/defectdojo.conf" "$DROPIN_DIR/defectdojo.conf"
    systemctl daemon-reload
    echo "upload hooked into vulnagent.service ($DROPIN_DIR/defectdojo.conf)"
elif [ -f "$CRON" ] && ! grep -q vulnagent-dojo "$CRON"; then
    # exit 0/1 = scan completed; 2/3 = error or already running
    sed -i 's|\(run >/var/log/vulnagent.log 2>&1\)$|\1; [ $? -le 1 ] \&\& /usr/local/sbin/vulnagent-dojo >>/var/log/vulnagent.log 2>\&1|' "$CRON"
    echo "upload hooked into $CRON"
fi

echo
if grep -q '"api_token": ""' "$CONF" || grep -q 'defectdojo.example.local' "$CONF"; then
    echo "Next: put your DefectDojo url and API token in $CONF"
fi
echo "Test the connection:  sudo vulnagent-dojo        (uploads the latest report)"
echo "Full run now:         sudo systemctl start vulnagent.service"
