#!/bin/sh
# Install / uninstall vulnagent as a systemd timer (or cron job if systemd is absent).
#   sudo ./install.sh            install or upgrade (keeps an existing config)
#   sudo ./install.sh --uninstall
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=/usr/local/sbin/vulnagent
CONF_DIR=/etc/vulnagent
DOC_DIR=/usr/local/share/doc/vulnagent
UNIT_DIR=/etc/systemd/system
CRON=/etc/cron.d/vulnagent

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now vulnagent.timer 2>/dev/null || true
        rm -f "$UNIT_DIR/vulnagent.service" "$UNIT_DIR/vulnagent.timer"
        systemctl daemon-reload
    fi
    rm -f "$BIN" "$CRON"
    rm -rf "$DOC_DIR"
    echo "vulnagent removed. Config ($CONF_DIR) and reports (/var/lib/vulnagent) were kept."
    exit 0
fi

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' \
    || { echo "python >= 3.6 is required" >&2; exit 1; }

install -m 0755 "$HERE/vulnagent.py" "$BIN"
install -d -m 0750 "$CONF_DIR" /var/lib/vulnagent
if [ ! -f "$CONF_DIR/config.json" ]; then
    install -m 0640 "$HERE/config.example.json" "$CONF_DIR/config.json"
    echo "created $CONF_DIR/config.json (auto_apply is OFF - review it before enabling)"
else
    echo "keeping existing $CONF_DIR/config.json"
fi
install -d "$DOC_DIR"
install -m 0644 "$HERE/README.md" "$HERE/config.example.json" "$DOC_DIR/" 2>/dev/null || true

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    install -m 0644 "$HERE/systemd/vulnagent.service" "$HERE/systemd/vulnagent.timer" "$UNIT_DIR/"
    systemctl daemon-reload
    systemctl enable --now vulnagent.timer
    echo "systemd timer enabled:"
    systemctl list-timers vulnagent.timer --no-pager || true
else
    echo "30 3 * * * root $BIN -q -c $CONF_DIR/config.json run >/var/log/vulnagent.log 2>&1" > "$CRON"
    chmod 0644 "$CRON"
    echo "no systemd: installed cron job $CRON"
fi

echo
echo "Try it now:   sudo vulnagent scan"
echo "Dry-run patch: sudo vulnagent patch"
echo "Reports:       /var/lib/vulnagent/reports/latest.html"
