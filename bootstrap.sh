#!/bin/sh
# Download (or update) vulnagent from the private GitHub repo onto this machine.
#
# Copy this one file to the machine, then either:
#
#   A) SSH deploy key (one per machine):
#        ./bootstrap.sh
#      First run creates ~/.ssh/linux_scanner_deploy and prints the public key.
#      Add it in GitHub: repo -> Settings -> Deploy keys (read-only), re-run.
#
#   B) Read-only token (one token for all machines, no git needed):
#        GITHUB_TOKEN=github_pat_xxx ./bootstrap.sh
#      Token: GitHub -> Settings -> Developer settings -> Fine-grained tokens,
#      repository access = this repo only, permission Contents: Read-only.
#
# Re-running the script updates to the latest version.
# Options:  --install   also run install.sh (needs root; enables the daily timer)
#           --scan      run a scan right away from the downloaded copy
# Env:      DEST (default ~/linux_scanner), BRANCH (default main),
#           KEY  (default ~/.ssh/linux_scanner_deploy)
set -eu

REPO=${REPO:-bandprothesis-bit/linux_scanner}
BRANCH=${BRANCH:-main}
DEST=${DEST:-$HOME/linux_scanner}
KEY=${KEY:-$HOME/.ssh/linux_scanner_deploy}
DO_INSTALL=0
DO_SCAN=0
for arg in "$@"; do
    case "$arg" in
        --install) DO_INSTALL=1 ;;
        --scan) DO_SCAN=1 ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

if [ -n "${GITHUB_TOKEN:-}" ]; then
    # ---- token: download a tarball through the GitHub API ----------------
    command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    code=$(curl -sSL -o "$tmp/src.tgz" -w '%{http_code}' \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$REPO/tarball/$BRANCH")
    if [ "$code" != "200" ]; then
        echo "download failed (HTTP $code). Check that the token can read $REPO." >&2
        exit 1
    fi
    mkdir -p "$tmp/x"
    tar -xzf "$tmp/src.tgz" -C "$tmp/x" --strip-components=1
    [ -f "$tmp/x/vulnagent.py" ] || { echo "unexpected archive content" >&2; exit 1; }
    rm -rf "$DEST.new"
    mv "$tmp/x" "$DEST.new"
    rm -rf "$DEST"
    mv "$DEST.new" "$DEST"
    echo "downloaded $REPO@$BRANCH to $DEST"
else
    # ---- SSH deploy key -------------------------------------------------
    command -v git >/dev/null 2>&1 || { echo "git is required (or use GITHUB_TOKEN=...)" >&2; exit 1; }
    if [ ! -f "$KEY" ]; then
        mkdir -p "$(dirname "$KEY")"
        chmod 700 "$(dirname "$KEY")"
        ssh-keygen -q -t ed25519 -N "" -C "linux_scanner@$(hostname)" -f "$KEY"
        echo "created SSH key $KEY"
    fi
    export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
    if ! git ls-remote "git@github.com:$REPO.git" >/dev/null 2>&1; then
        echo
        echo "This machine's key is not authorised for $REPO yet."
        echo "Add it in GitHub: https://github.com/$REPO/settings/keys -> Add deploy key"
        echo "(title: $(hostname), leave 'Allow write access' unticked):"
        echo
        cat "$KEY.pub"
        echo
        echo "Then run this script again."
        exit 1
    fi
    if [ -d "$DEST/.git" ]; then
        git -C "$DEST" fetch -q origin "$BRANCH"
        git -C "$DEST" checkout -q "$BRANCH"
        git -C "$DEST" reset -q --hard "origin/$BRANCH"
        echo "updated $DEST to $(git -C "$DEST" rev-parse --short HEAD)"
    else
        git clone -q --branch "$BRANCH" "git@github.com:$REPO.git" "$DEST"
        git -C "$DEST" config core.sshCommand "$GIT_SSH_COMMAND"
        echo "cloned $REPO into $DEST ($(git -C "$DEST" rev-parse --short HEAD))"
    fi
fi

chmod +x "$DEST/vulnagent.py" "$DEST/install.sh" "$DEST/bootstrap.sh" 2>/dev/null || true

if [ "$DO_INSTALL" -eq 1 ]; then
    as_root sh "$DEST/install.sh"
fi
if [ "$DO_SCAN" -eq 1 ]; then
    as_root python3 "$DEST/vulnagent.py" scan || true
fi

cat <<EOF

Run it from the downloaded copy (no install needed):
  sudo python3 $DEST/vulnagent.py scan             # check only, changes nothing
  sudo python3 $DEST/vulnagent.py patch            # show what would be patched
  sudo python3 $DEST/vulnagent.py patch --apply    # patch
Install as a daily service:   sudo sh $DEST/install.sh
Update later:                 re-run this script
EOF
