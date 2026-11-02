#!/bin/sh
# Install the Microsoft Defender -> DefectDojo connector with a daily systemd timer.
# Run it on the DefectDojo server (or any Linux host that reaches both
# DefectDojo and the Microsoft APIs).
#   sudo sh defectdojo/install-defender.sh
#   sudo sh defectdojo/install-defender.sh --uninstall
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=/usr/local/sbin/defender-dojo
CONF=/etc/vulnagent/defender.json
UNIT_DIR=/etc/systemd/system

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo sh $0)" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now defender-dojo.timer 2>/dev/null || true
    rm -f "$BIN" "$UNIT_DIR/defender-dojo.service" "$UNIT_DIR/defender-dojo.timer"
    systemctl daemon-reload
    echo "Defender connector removed ($CONF kept)."
    exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required for the daily timer" >&2; exit 1; }

install -m 0755 "$HERE/defender-dojo.py" "$BIN"
install -d -m 0750 /etc/vulnagent
if [ ! -f "$CONF" ]; then
    install -m 0600 "$HERE/defender.example.json" "$CONF"
    echo "created $CONF - add the DefectDojo token and your customers"
else
    echo "keeping existing $CONF"
fi
install -m 0644 "$HERE/defender-dojo.service" "$HERE/defender-dojo.timer" "$UNIT_DIR/"
systemctl daemon-reload
systemctl enable --now defender-dojo.timer
systemctl list-timers defender-dojo.timer --no-pager || true

cat <<EOF

Next:
  1. sudo nano $CONF                       (DefectDojo token, customers)
  2. sudo $BIN --test                      (checks sign-in, counts devices)
  3. sudo systemctl start defender-dojo    (first import now)
EOF
