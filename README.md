# vulnagent

A Linux agent that finds out what is installed on the machine, checks it against public vulnerability databases, and patches what can be patched safely. It is a single Python file that needs only the Python 3.6+ standard library.

## What it checks

| Layer | Source of truth | Vulnerability data |
|---|---|---|
| OS packages | dpkg / rpm / apk / pacman | Package manager's pending (security) updates + [OSV.dev](https://osv.dev) (Debian, Ubuntu, Alpine advisories) |
| Runtimes: PHP, Java, Python, Node.js, Ruby, Go | Binaries in PATH, `/usr/lib/jvm`, `/opt`, … | [endoflife.date](https://endoflife.date) (EOL branch / missing patch release); Go stdlib via OSV |
| PHP libraries | `composer.lock`, `vendor/composer/installed.json` | OSV (Packagist / GHSA / FriendsOfPHP) |
| Java libraries | `*.jar/*.war/*.ear`, including nested and fat jars (`WEB-INF/lib`, `BOOT-INF/lib`) | OSV (Maven / GHSA), so it catches log4shell inside a WAR |
| Python libraries | `*.dist-info` / `*.egg-info` in venvs, `/usr/local`, user site | OSV (PyPI) |
| Node libraries | `node_modules/**/package.json` (projects and global) | OSV (npm) |
| Ruby gems | `Gemfile.lock` | OSV (RubyGems) |

## Getting it onto a machine

The repository is private, so each machine has to authenticate. Copy `bootstrap.sh` to the machine (scp, or paste it into a file) and use one of the two options below.

**Option A: SSH deploy key, one per machine.**

```bash
sh bootstrap.sh
```

The first run creates `~/.ssh/linux_scanner_deploy` and prints its public key. Add that key under the repo's **Settings → Deploy keys** with write access left unticked, then run the script again.

**Option B: one read-only token for every machine.** Create the token under GitHub **Settings → Developer settings → Fine-grained tokens**, with access to this repository only and the permission *Contents: Read-only*. This option needs only curl, not git.

```bash
GITHUB_TOKEN=github_pat_xxx sh bootstrap.sh
```

Either way the code lands in `~/linux_scanner` (change it with `DEST=`). Re-running the script updates it to the latest version. `--scan` runs a scan right away, and `--install` installs the daily service.

You can run it straight from that folder without installing:

```bash
sudo python3 ~/linux_scanner/vulnagent.py scan
```

Without an `/etc/vulnagent/config.json`, it uses the built-in defaults, so nothing is patched unless you pass `patch --apply`.

## Quick start

```bash
sudo ./install.sh
```

```bash
sudo vulnagent scan
```

```bash
sudo vulnagent patch
```

```bash
sudo vulnagent patch --apply
```

`scan` changes nothing. `patch` shows the plan as a dry run. `patch --apply` executes the plan.
The installer puts the agent in `/usr/local/sbin/vulnagent`, the config in `/etc/vulnagent/config.json`, and enables a daily systemd timer (03:30 ± 45 min) that runs `vulnagent run`. It falls back to cron when systemd is absent.

Reports are written to `/var/lib/vulnagent/reports/` as `latest.json`, `latest.html` and dated history files. See `examples/sample-report.html`.

## Commands

| Command | Does |
|---|---|
| `vulnagent inventory [--json]` | Lists packages, runtimes and libraries. No network access. |
| `vulnagent scan` | Inventory, vulnerability lookup and remediation plan. Read-only. |
| `vulnagent patch [--apply] [--os-mode MODE] [--libs]` | Like `scan`, then executes the plan when `--apply` is given, then rescans. |
| `vulnagent run` | Agent mode used by the timer. Patches only if `"auto_apply": true`, then reports and notifies. |

Useful flags: `--paths /srv /opt` (limit the filesystem scan), `--no-os`, `--no-libs`, `--min-severity high`, `--json`, `--limit N`, `-v`.

Exit codes: `0` nothing found · `1` vulnerabilities present · `2` an error occurred (for example OSV unreachable) · `3` another run is in progress.

## How patching works (and what it will not do)

Nothing is changed unless you pass `--apply` or set `"auto_apply": true`. Library patching is additionally off per ecosystem until you enable it.

| What | Action | Enabled by |
|---|---|---|
| OS packages (apt) | `apt-get install --only-upgrade <pkgs>`, non-interactive, keeps your config files | `patch.os` |
| OS packages (dnf/yum) | `dnf upgrade --security` (or full upgrade) with `--exclude` | `patch.os` |
| OS packages (zypper) | `zypper patch --category security` | `patch.os` |
| OS packages (apk) | `apk upgrade <vulnerable pkgs>` | `patch.os` |
| OS packages (pacman) | `pacman -Syu` (Arch does not support partial upgrades) | `patch.os` |
| Python venv | `<venv>/bin/python -m pip install --upgrade pkg==fixed` | `patch.pypi` |
| Python in /usr/local | same, using the system pip | `patch.pypi` + `patch.pip_allow_system` |
| npm project | `npm audit fix` (never `--force`) | `patch.npm` |
| npm global | `npm install -g pkg@fixed` | `patch.npm` |
| Composer project | `composer update <pkgs> --with-dependencies` (respects your version constraints) | `patch.composer` |
| Bundler project | `bundle update --conservative <gems>` | `patch.rubygems` |
| JARs inside apps, EOL runtimes, libraries without a fix | **Reported as manual actions only** | – |

`patch.os` modes:

- `security`: only updates from the distro's security channel (Debian/Ubuntu `-security`, RHEL errata, SUSE security patches).
- `vulnerable`: `security`, plus any upgradable package OSV reports as vulnerable.
- `all`: every pending update.
- `none`: never touch OS packages.

Safety measures:

- Project commands (`npm`, `composer`, `bundle`, venv `pip`) run **as the owner of the project directory**, not as root.
- Before patching, `package.json`, `package-lock.json`, `composer.json`, `composer.lock`, `Gemfile` and `Gemfile.lock` are backed up. The OS package list is also saved, to `/var/lib/vulnagent/backups/<timestamp>/`.
- `exclude_packages` holds packages back from both reporting and patching.
- A lock file prevents overlapping runs.
- After patching it checks whether a reboot or service restart is needed (`/var/run/reboot-required`, `needrestart`, `needs-restarting`). It restarts services or reboots **only** if you enable `restart_services` / `auto_reboot`.

Recommended rollout: run `scan` for a week, then turn on `auto_apply` with `"os": "security"`. Enable library patching only on hosts whose applications have tests or a staging copy.

## Configuration

Copy `config.example.json` to `/etc/vulnagent/config.json`. The most important keys:

- `scan_paths` / `exclude_paths`: where to look for application libraries. Package caches (`.m2`, `.gradle`, `.npm`, `.cache`) and VCS directories are always skipped.
- `os_ecosystem_override`: OSV ecosystem for OS packages. Debian, Ubuntu and Alpine are detected automatically. Derivatives such as Kali or Raspbian need it set explicitly, for example `"Debian:13"`.
- `ignore_unfixed_os`: hides distro CVEs that have no fix yet (default true; there are usually hundreds).
- `check_backports`: hides findings in OS-shipped libraries when the OS package's changelog names the CVE (default true).
- `min_severity`, `ignore_vulns` (IDs or CVE aliases), `exclude_packages`.
- `notify.webhook_url`: Slack, Mattermost, Discord or Teams incoming webhook; sends a summary with the CRITICAL/HIGH items.
- `notify.report_upload_url` and `report_upload_token`: POST the full JSON report to a central collector, for fleet dashboards or a SIEM.

## Many machines

```bash
./deploy-fleet.sh hosts.txt my-config.json
```

This copies the agent to every `user@host` in `hosts.txt` over SSH and installs it with sudo. Each host then reports to the same webhook or collector. With Ansible or Salt, ship `vulnagent.py`, the config and the two systemd units the same way.

For a central web console, send every machine's findings to DefectDojo with the add-on in [`defectdojo/`](defectdojo/README.md).

## Limitations

- **Distro backports:** Debian, Ubuntu, RHEL, Rocky and SUSE often fix a CVE without changing the upstream version number. For OS packages the agent uses the distro's own advisories, which handles this.

  For libraries *shipped by OS packages* (for example `/usr/lib/python3.6/site-packages` on Rocky 8), the agent reads the owning package's changelog (`rpm -q --changelog`, or `/usr/share/doc/<pkg>/changelog.Debian.gz`). When the changelog names the CVE, the finding is hidden. The report shows how many were hidden and lists them under `backported` in the JSON. Turn this off with `"check_backports": false`.

  Backports whose changelog does not name the CVE, and the runtime "outdated" checks, can still be false positives. These findings are grouped as "shipped inside OS packages" and fixed through OS updates only. Never upgrade them with `pip` or `npm`, because system tools such as `dnf` depend on them.
- **RPM distros:** OS CVE details come from `dnf/yum updateinfo` (advisory IDs), not OSV.
- **Unidentified JARs:** JARs without `META-INF/maven/.../pom.properties` cannot be identified reliably. They are counted in the report but not checked.
- **Containers:** The agent does not scan container images or statically linked binaries other than Go. Use Trivy or Grype for container images.
- **Network access:** The agent needs outbound HTTPS to `api.osv.dev` and `endoflife.date`. Vulnerability details are cached in `/var/lib/vulnagent/cache`.
