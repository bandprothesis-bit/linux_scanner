#!/usr/bin/env python3
"""
vulnagent - Linux vulnerability inventory & auto-patching agent.

What it does on every run:
  1. Inventory  - OS packages (dpkg/rpm/apk/pacman), language runtimes
                  (PHP, Java, Python, Node.js, Ruby, Go) and application
                  libraries found on disk (PyPI, npm, Composer/Packagist,
                  RubyGems, Maven JAR/WAR/EAR incl. nested/fat jars).
  2. Assess     - matches everything against OSV.dev (CVE/GHSA/DSA/USN...),
                  checks runtimes against endoflife.date (EOL / missing
                  patch releases) and asks the package manager which
                  (security) updates are pending.
  3. Patch      - builds a remediation plan and, only when asked
                  (--apply or "auto_apply": true), executes it: OS security
                  updates, pip/npm/composer/bundler upgrades, etc. Things that
                  cannot be patched safely (e.g. JARs bundled in an app) are
                  reported as manual actions.
  4. Report     - JSON + HTML report, exit code for monitoring, optional
                  webhook (Slack/Mattermost/Discord/Teams-style) and upload of
                  the full JSON report to a central collector.

Only the Python 3.6+ standard library is required.
"""

import argparse
import concurrent.futures
import datetime
import fcntl
import glob
import html
import io
import json
import logging
import math
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

VERSION = "1.0.0"
log = logging.getLogger("vulnagent")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
EOL_URL = "https://endoflife.date/api/v1/products/%s/"

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
OS_MODES = ("none", "security", "vulnerable", "all")

DEFAULT_CONFIG = {
    "state_dir": "/var/lib/vulnagent",
    "scan_os_packages": True,
    "scan_runtimes": True,
    "scan_libraries": True,
    "scan_paths": ["/opt", "/srv", "/var/www", "/usr/local", "/usr/lib",
                   "/usr/share", "/home", "/root"],
    "exclude_paths": ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp",
                      "/var/lib/docker", "/var/lib/containerd", "/snap",
                      "/var/lib/vulnagent", "/usr/lib/modules",
                      "/usr/lib/firmware", "/usr/share/doc", "/usr/share/man",
                      "/usr/share/locale", "/usr/share/icons"],
    "max_scan_depth": 14,
    "same_filesystem": True,
    "max_archive_mb": 300,
    "refresh_package_index": True,
    # OSV ecosystem used for OS packages. Auto-detected for Debian, Ubuntu and
    # Alpine; set e.g. "Debian:13" for derivatives (Kali, Raspbian, ...).
    "os_ecosystem_override": "",
    "ignore_unfixed_os": True,
    "report_os_managed_libraries": True,
    "min_severity": "LOW",
    "ignore_vulns": [],
    "exclude_packages": [],
    "auto_apply": False,
    "patch": {
        "os": "security",           # none | security | vulnerable | all
        "pypi": False,
        "npm": False,
        "composer": False,
        "rubygems": False,
        "pip_allow_system": False,
        "restart_services": False,  # needrestart -r a (Debian/Ubuntu)
        "auto_reboot": False,
        "reboot_delay_minutes": 5,
    },
    "notify": {
        "webhook_url": "",
        "only_on_findings": True,
        "report_upload_url": "",
        "report_upload_token": "",
    },
    "http_timeout": 30,
    "workers": 16,
    "keep_reports": 30,
}

SKIP_DIR_NAMES = {".git", ".svn", ".hg", "__pycache__", ".cache", ".m2",
                  ".gradle", ".npm", ".pnpm-store", ".yarn", "Trash"}
OS_PREFIXES = ("/usr/lib/", "/usr/lib64/", "/usr/share/", "/lib/", "/lib64/",
               "/usr/libexec/", "/usr/bin/", "/usr/sbin/")
POM_RE = re.compile(r"META-INF/maven/[^/]+/[^/]+/pom\.properties$")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def run(cmd, cwd=None, timeout=600, env=None):
    """Run a command, never raise. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, encoding="utf-8",
                           errors="replace", timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss: %s" % (timeout, " ".join(cmd))
    except OSError as e:
        return 126, "", str(e)


def which(name):
    return shutil.which(name, path=os.environ.get("PATH", "") +
                        ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")


def is_root():
    return os.geteuid() == 0


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False, default=str)
    os.replace(tmp, path)


def deep_merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if k.startswith("_"):
            continue  # "_comment" keys
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def http_json(url, payload=None, timeout=30, retries=4, headers=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    hdrs = {"Content-Type": "application/json", "User-Agent": "vulnagent/" + VERSION}
    hdrs.update(headers or {})
    err = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8")
                return json.loads(body) if body.strip() else {}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code < 500 and e.code != 429:
                raise RuntimeError("HTTP %s from %s" % (e.code, url))
            err = e
        except (urllib.error.URLError, socket.timeout, ConnectionError, ValueError) as e:
            err = e
        time.sleep(2 ** attempt)
    raise RuntimeError("request to %s failed: %s" % (url, err))


def path_owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except (OSError, KeyError):
        return None


def as_user(user, cmd):
    """Prefix cmd so it runs as `user` (only meaningful when we are root)."""
    if not user or not is_root() or user == "root":
        return cmd
    if which("runuser"):
        return ["runuser", "-u", user, "--"] + cmd
    return ["sudo", "-H", "-u", user, "--"] + cmd


def under_os_prefix(path):
    return (path.rstrip("/") + "/").startswith(OS_PREFIXES)


def norm_name(eco, name):
    name = (name or "").strip()
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


# --------------------------------------------------------------------------
# version comparison
# --------------------------------------------------------------------------

_PRE_RANK = {"dev": 0, "snapshot": 0, "ea": 0, "a": 1, "alpha": 1, "m": 1,
             "milestone": 1, "b": 2, "beta": 2, "c": 3, "rc": 3, "cr": 3,
             "pre": 3, "preview": 3}


def _gen_key(v):
    v = v.strip().lstrip("vV").split("+", 1)[0].lower()
    out = []
    for t in re.findall(r"\d+|[a-z]+", v):
        if t.isdigit():
            out.append((2, int(t), ""))
        elif t in _PRE_RANK:
            out.append((0, _PRE_RANK[t], t))
        else:
            out.append((1, 0, t))
    return out


def gen_cmp(a, b):
    """Generic comparator good enough for semver, PEP 440, Maven, Alpine."""
    ka, kb = _gen_key(a), _gen_key(b)
    n = max(len(ka), len(kb))
    pad = (1, 0, "")
    ka += [pad] * (n - len(ka))
    kb += [pad] * (n - len(kb))
    return (ka > kb) - (ka < kb)


def _deb_verrevcmp(a, b):
    """Port of dpkg's verrevcmp()."""
    def order(s, i):
        if i >= len(s):
            return 0
        c = s[i]
        if c.isdigit():
            return 0
        if c.isalpha():
            return ord(c)
        if c == "~":
            return -1
        return ord(c) + 256

    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac, bc = order(a, i), order(b, j)
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def deb_cmp(a, b):
    def split(v):
        epoch = 0
        if ":" in v:
            e, v = v.split(":", 1)
            epoch = int(e) if e.isdigit() else 0
        up, rev = (v.rsplit("-", 1) if "-" in v else (v, ""))
        return epoch, up, rev

    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return (ea > eb) - (ea < eb)
    r = _deb_verrevcmp(ua, ub) or _deb_verrevcmp(ra, rb)
    return (r > 0) - (r < 0)


def vcmp(eco, a, b):
    if eco.startswith(("Debian", "Ubuntu")):
        return deb_cmp(a, b)
    return gen_cmp(a, b)


def vmax(eco, versions):
    best = None
    for v in versions:
        if v and (best is None or vcmp(eco, v, best) > 0):
            best = v
    return best


# --------------------------------------------------------------------------
# severity
# --------------------------------------------------------------------------

_CVSS3 = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
          "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0.0}}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    """CVSS v3.x base score from a vector string."""
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        c, i, a = (_CVSS3["CIA"][m[k]] for k in ("C", "I", "A"))
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        impact = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * pr * _CVSS3["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))
    except (KeyError, ValueError, IndexError):
        return None


def score_label(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def vuln_severity(v):
    score = None
    label = None
    for s in v.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            sc = cvss3_score(s.get("score", ""))
            if sc is not None:
                score = max(score or 0.0, sc)
        elif s.get("type") == "Ubuntu" and not label:
            label = str(s.get("score", "")).upper()
    ds = (v.get("database_specific") or {}).get("severity")
    if isinstance(ds, str):
        label = ds.upper()
    for aff in v.get("affected") or []:
        es = (aff.get("ecosystem_specific") or {}).get("severity")
        if isinstance(es, str) and not label:
            label = es.upper()
    if score is not None:
        return score_label(score), score
    label = {"MODERATE": "MEDIUM", "IMPORTANT": "HIGH", "NEGLIGIBLE": "LOW",
             "UNIMPORTANT": "LOW"}.get(label, label)
    return (label if label in SEVERITIES else "UNKNOWN"), None


def sev_rank(s):
    return SEVERITIES.index(s) if s in SEVERITIES else 0


# --------------------------------------------------------------------------
# OS detection and OS packages
# --------------------------------------------------------------------------

PM_BY_ID = {"debian": "apt", "ubuntu": "apt", "kali": "apt", "linuxmint": "apt",
            "raspbian": "apt", "pop": "apt", "rhel": "dnf", "fedora": "dnf",
            "centos": "dnf", "rocky": "dnf", "almalinux": "dnf", "ol": "dnf",
            "amzn": "dnf", "suse": "zypper", "opensuse": "zypper", "sles": "zypper",
            "opensuse-leap": "zypper", "opensuse-tumbleweed": "zypper",
            "alpine": "apk", "arch": "pacman", "manjaro": "pacman",
            "endeavouros": "pacman"}


def read_os_release():
    info = {}
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(p) as f:
                for line in f:
                    k, sep, v = line.strip().partition("=")
                    if sep:
                        info[k] = v.strip().strip("\"'")
            break
        except OSError:
            continue
    return info


def detect_pkg_manager(osr):
    for i in [osr.get("ID", "")] + osr.get("ID_LIKE", "").split():
        pm = PM_BY_ID.get(i)
        if pm:
            if pm == "dnf" and not which("dnf") and which("yum"):
                return "yum"
            return pm
    for pm, binary in (("apt", "apt-get"), ("dnf", "dnf"), ("yum", "yum"),
                       ("zypper", "zypper"), ("apk", "apk"), ("pacman", "pacman")):
        if which(binary):
            return pm
    return None


def osv_os_ecosystem(osr, cfg):
    if cfg.get("os_ecosystem_override"):
        return cfg["os_ecosystem_override"]
    oid, ver = osr.get("ID", ""), osr.get("VERSION_ID", "")
    if oid == "debian" and ver:
        return "Debian:" + ver.split(".")[0]
    if oid == "ubuntu" and ver:
        return "Ubuntu:%s%s" % (ver, ":LTS" if "LTS" in osr.get("VERSION", "") else "")
    if oid == "alpine" and ver:
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    return None


def refresh_index(pm):
    cmds = {"apt": ["apt-get", "update", "-qq"], "dnf": ["dnf", "-q", "makecache"],
            "yum": ["yum", "-q", "makecache"], "zypper": ["zypper", "--non-interactive", "-q", "refresh"],
            "apk": ["apk", "update", "-q"]}
    if pm in cmds:
        rc, _, err = run(cmds[pm], timeout=900)
        if rc != 0:
            log.warning("package index refresh failed: %s", err.strip()[-300:])


def inventory_os(pm):
    pkgs = []
    if pm == "apt":
        rc, out, _ = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Source}\n"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 4 or not parts[0].startswith("ii"):
                continue
            _, name, ver, src = parts[:4]
            m = re.match(r"^(\S+)(?: \((\S+)\))?$", src.strip())
            pkgs.append({"name": name, "version": ver,
                         "source": m.group(1) if m else name,
                         "source_version": (m.group(2) if m and m.group(2) else ver)})
    elif pm in ("dnf", "yum", "zypper"):
        rc, out, _ = run(["rpm", "-qa", "--qf", "%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n"])
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) < 4 or parts[0].startswith("gpg-pubkey"):
                continue
            name, epoch, vr, srpm = parts
            ver = vr if epoch in ("(none)", "0", "") else "%s:%s" % (epoch, vr)
            src = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", srpm) if srpm != "(none)" else name
            pkgs.append({"name": name, "version": ver, "source": src, "source_version": ver})
    elif pm == "apk":
        cur = {}
        try:
            with open("/lib/apk/db/installed", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        if cur.get("P"):
                            pkgs.append({"name": cur["P"], "version": cur.get("V", ""),
                                         "source": cur.get("o", cur["P"]),
                                         "source_version": cur.get("V", "")})
                        cur = {}
                    elif len(line) > 2 and line[1] == ":":
                        cur[line[0]] = line[2:]
            if cur.get("P"):
                pkgs.append({"name": cur["P"], "version": cur.get("V", ""),
                             "source": cur.get("o", cur["P"]), "source_version": cur.get("V", "")})
        except OSError as e:
            log.warning("cannot read apk db: %s", e)
    elif pm == "pacman":
        rc, out, _ = run(["pacman", "-Q"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                pkgs.append({"name": parts[0], "version": parts[1], "source": parts[0],
                             "source_version": parts[1]})
    return pkgs


def pending_updates(pm):
    """Updates the package manager can install right now.
    Returns list of {name, current, candidate, security, origin}."""
    ups = []
    if pm == "apt":
        rc, out, err = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], timeout=600)
        for line in out.splitlines():
            m = re.match(r"^Inst (\S+) \[([^\]]+)\] \((\S+) ([^\[]*)", line)
            if m:
                ups.append({"name": m.group(1), "current": m.group(2), "candidate": m.group(3),
                            "origin": m.group(4).strip(),
                            "security": "security" in m.group(4).lower()})
    elif pm in ("dnf", "yum"):
        sec = {}
        args = ([pm, "-q", "updateinfo", "list", "--security", "--available"] if pm == "dnf"
                else ["yum", "-q", "updateinfo", "list", "security"])
        rc, out, _ = run(args, timeout=600)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and ("Sec" in parts[1] or "security" in parts[1].lower()):
                m = re.match(r"^(.+?)-(?:\d+:)?[^-]+-[^-]+\.[^.]+$", parts[2])
                if m:
                    sec[m.group(1)] = parts[0] + " " + parts[1]
        rc, out, _ = run([pm, "-q", "check-update"], timeout=600)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and "." in parts[0] and not line.startswith(" "):
                name = parts[0].rsplit(".", 1)[0]
                ups.append({"name": name, "current": "", "candidate": parts[1], "origin": parts[2],
                            "security": name in sec, "advisory": sec.get(name, "")})
    elif pm == "zypper":
        rc, out, _ = run(["zypper", "-q", "--non-interactive", "list-updates"], timeout=600)
        for line in out.splitlines():
            cols = [c.strip() for c in line.split("|")]
            if len(cols) >= 6 and cols[0] in ("v", "i"):
                ups.append({"name": cols[2], "current": cols[3], "candidate": cols[4],
                            "origin": cols[1], "security": False})
        rc, out, _ = run(["zypper", "-q", "--non-interactive", "list-patches", "--category", "security"],
                         timeout=600)
        n = sum(1 for line in out.splitlines() if line.count("|") >= 4 and "security" in line)
        if n:
            ups.append({"name": "(%d security patches)" % n, "current": "", "candidate": "",
                        "origin": "zypper patches", "security": True})
    elif pm == "apk":
        rc, out, _ = run(["apk", "version", "-l", "<"])
        for line in out.splitlines():
            m = re.match(r"^(.+)-([^-]+-r\d+)\s+<\s+(\S+)", line)
            if m:
                ups.append({"name": m.group(1), "current": m.group(2), "candidate": m.group(3),
                            "origin": "", "security": False})
    elif pm == "pacman":
        vulnerable = set()
        if which("arch-audit"):
            rc, out, _ = run(["arch-audit", "-u", "-f", "%n"])
            vulnerable = set(out.split())
        if which("checkupdates"):
            rc, out, _ = run(["checkupdates"], timeout=600)
            for line in out.splitlines():
                m = re.match(r"^(\S+) (\S+) -> (\S+)", line)
                if m:
                    ups.append({"name": m.group(1), "current": m.group(2), "candidate": m.group(3),
                                "origin": "", "security": m.group(1) in vulnerable})
    return ups


def owner_package(pm, path):
    """Which OS package owns a file (None if unmanaged)."""
    cands = [path]
    rp = os.path.realpath(path)
    if rp != path:
        cands.append(rp)
    for p in cands:
        if pm == "apt":
            rc, out, _ = run(["dpkg", "-S", p])
            if rc == 0 and ":" in out:
                return out.split(":", 1)[0].split(",")[0].strip()
        elif pm in ("dnf", "yum", "zypper"):
            rc, out, _ = run(["rpm", "-qf", "--qf", "%{NAME}\n", p])
            if rc == 0 and out.strip():
                return out.strip().splitlines()[0]
        elif pm == "apk":
            rc, out, _ = run(["apk", "info", "-q", "--who-owns", p])
            if rc == 0 and out.strip():
                return out.split()[0]
        elif pm == "pacman":
            rc, out, _ = run(["pacman", "-Qqo", p])
            if rc == 0 and out.strip():
                return out.strip()
    return None


# --------------------------------------------------------------------------
# runtimes (PHP, Java, Python, Node.js, Ruby, Go)
# --------------------------------------------------------------------------

def _java_tuple(v):
    m = re.match(r"^1\.(\d+)\.\d+_(\d+)", v) or re.match(r"^(\d+)u(\d+)", v)
    if m:
        return (int(m.group(1)), 0, int(m.group(2)))
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def _num_tuple(v):
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


RUNTIMES = [
    {"name": "php", "product": "php", "cycle_parts": 2, "bin_re": r"^php(\d+(\.\d+)?)?$",
     "names": ["php"], "globs": ["/usr/bin/php*", "/usr/local/bin/php*", "/opt/*/bin/php",
                                 "/opt/remi/*/root/usr/bin/php", "/usr/local/php*/bin/php"],
     "cmd": ["-r", "echo PHP_VERSION;"], "re": r"(\d+\.\d+\.\d+)"},
    {"name": "java", "product": "eclipse-temurin", "cycle_parts": 1, "bin_re": r"^java$",
     "names": ["java"], "globs": ["/usr/lib/jvm/*/bin/java", "/usr/lib/jvm/*/jre/bin/java",
                                  "/opt/*/bin/java", "/opt/java/*/bin/java", "/usr/java/*/bin/java"],
     "cmd": ["-version"], "re": r"version \"([^\"]+)\"", "tuple": _java_tuple},
    {"name": "python", "product": "python", "cycle_parts": 2, "bin_re": r"^python(\d(\.\d+)?)?$",
     "names": ["python3", "python"], "globs": ["/usr/bin/python3.*", "/usr/local/bin/python3.*",
                                                "/opt/*/bin/python3"],
     "cmd": ["-c", "import platform;print(platform.python_version())"], "re": r"(\d+\.\d+\.\d+)"},
    {"name": "node", "product": "nodejs", "cycle_parts": 1, "bin_re": r"^node(js)?$",
     "names": ["node", "nodejs"], "globs": ["/opt/*/bin/node", "/usr/local/bin/node"],
     "cmd": ["--version"], "re": r"v?(\d+\.\d+\.\d+)"},
    {"name": "ruby", "product": "ruby", "cycle_parts": 2, "bin_re": r"^ruby[\d.]*$",
     "names": ["ruby"], "globs": ["/opt/*/bin/ruby"],
     "cmd": ["-e", "print RUBY_VERSION"], "re": r"(\d+\.\d+\.\d+)"},
    {"name": "go", "product": "go", "cycle_parts": 2, "bin_re": r"^go$",
     "names": ["go"], "globs": ["/usr/local/go/bin/go", "/usr/lib/go-*/bin/go"],
     "cmd": ["version"], "re": r"go(\d+\.\d+(?:\.\d+)?)"},
]


class EolCache(object):
    def __init__(self, cache_dir, timeout):
        self.dir = cache_dir
        self.timeout = timeout
        self.mem = {}

    def releases(self, product):
        if product in self.mem:
            return self.mem[product]
        path = os.path.join(self.dir, "eol-%s.json" % product)
        data = None
        try:
            if time.time() - os.path.getmtime(path) < 86400:
                data = read_json(path)
        except OSError:
            pass
        if data is None:
            try:
                resp = http_json(EOL_URL % product, timeout=self.timeout)
                data = ((resp or {}).get("result") or {}).get("releases") or []
                write_json(path, data)
            except Exception as e:  # network trouble must not kill the scan
                log.warning("endoflife.date lookup for %s failed: %s", product, e)
                data = read_json(path, [])
        self.mem[product] = data
        return data


def inventory_runtimes(pm, eol):
    found = []
    seen = set()
    for spec in RUNTIMES:
        cands = []
        for n in spec["names"]:
            p = which(n)
            if p:
                cands.append(p)
        if spec["name"] == "java" and os.environ.get("JAVA_HOME"):
            cands.append(os.path.join(os.environ["JAVA_HOME"], "bin", "java"))
        for g in spec["globs"]:
            cands.extend(sorted(glob.glob(g)))
        for p in cands:
            if not re.match(spec["bin_re"], os.path.basename(p)):
                continue
            if not (os.path.isfile(p) and os.access(p, os.X_OK)):
                continue
            real = os.path.realpath(p)
            if real in seen:
                continue
            seen.add(real)
            rc, out, err = run([p] + spec["cmd"], timeout=30)
            m = re.search(spec["re"], out + "\n" + err)
            if not m:
                continue
            ver = m.group(1)
            rt = {"runtime": spec["name"], "version": ver, "path": p, "realpath": real,
                  "os_package": owner_package(pm, p) if pm else None}
            rt.update(eol_status(spec, ver, eol))
            found.append(rt)
    return found


def eol_status(spec, ver, eol):
    to_t = spec.get("tuple", _num_tuple)
    vt = to_t(ver)
    cycle = ".".join(str(x) for x in vt[:spec["cycle_parts"]])
    rels = eol.releases(spec["product"]) if eol else []
    rel = next((r for r in rels if str(r.get("name")) == cycle), None)
    if rel is None:
        return {"cycle": cycle, "status": "unknown", "latest": None, "eol_date": None}
    latest = (rel.get("latest") or {}).get("name")
    status = "ok"
    if latest and to_t(latest) > vt:
        status = "outdated"
    if rel.get("isEol"):
        status = "eol"
    return {"cycle": cycle, "status": status, "latest": latest, "eol_date": rel.get("eolFrom")}


# --------------------------------------------------------------------------
# filesystem scanner for application libraries
# --------------------------------------------------------------------------

class FsScanner(object):
    def __init__(self, cfg, pm):
        self.cfg = cfg
        self.pm = pm
        self.excludes = set(os.path.normpath(p) for p in cfg["exclude_paths"])
        self.max_depth = int(cfg["max_scan_depth"])
        self.max_archive = int(cfg["max_archive_mb"]) * 1024 * 1024
        self.packages = {}
        self.projects = {}          # dir -> {"type": ..., "lockfiles": [...]}
        self.composer_installed = []
        self.unidentified_jars = []
        self._owner_cache = {}

    def scan(self):
        roots = []
        for p in sorted(set(os.path.normpath(x) for x in self.cfg["scan_paths"])):
            if not os.path.isdir(p) or p in self.excludes:
                continue
            if any(p == r or p.startswith(r.rstrip("/") + "/") for r in roots):
                continue
            roots.append(p)
        for r in roots:
            log.debug("scanning %s", r)
            self._walk(r)
        # vendor/composer/installed.json only for projects without composer.lock
        for proj, pkgs in self.composer_installed:
            if proj not in self.projects or "composer.lock" not in self.projects[proj]["lockfiles"]:
                for p in pkgs:
                    self._add(p)
        return list(self.packages.values())

    def _add(self, p):
        key = (p["ecosystem"], p["name"], p["version"], p["location"])
        self.packages.setdefault(key, p)

    def _project(self, d, ptype, lockfile):
        pr = self.projects.setdefault(d, {"dir": d, "types": [], "lockfiles": []})
        if ptype not in pr["types"]:
            pr["types"].append(ptype)
        if lockfile and lockfile not in pr["lockfiles"]:
            pr["lockfiles"].append(lockfile)

    def _walk(self, root):
        try:
            root_dev = os.lstat(root).st_dev
        except OSError:
            return
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            depth = dirpath.count("/") - base_depth
            base = os.path.basename(dirpath)
            if base.endswith((".dist-info", ".egg-info")):
                dirnames[:] = []
                self._python_dist(dirpath, filenames)
                continue
            keep = []
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if d in SKIP_DIR_NAMES or full in self.excludes or depth >= self.max_depth:
                    continue
                if self.cfg["same_filesystem"]:
                    try:
                        if os.lstat(full).st_dev != root_dev:
                            continue
                    except OSError:
                        continue
                keep.append(d)
            dirnames[:] = keep
            fset = set(filenames)
            parent = os.path.basename(os.path.dirname(dirpath))
            in_nm = "/node_modules/" in dirpath + "/"
            if "package.json" in fset:
                gparent = os.path.basename(os.path.dirname(os.path.dirname(dirpath)))
                if parent == "node_modules" or (parent.startswith("@") and gparent == "node_modules"):
                    self._npm_pkg(dirpath)
                elif not in_nm and ("package-lock.json" in fset or "node_modules" in dirnames):
                    self._project(dirpath, "npm", "package-lock.json" if "package-lock.json" in fset else None)
                    if "package-lock.json" in fset:
                        self._project(dirpath, "npm", "package.json")
            if "composer.lock" in fset and not in_nm:
                self._composer_lock(dirpath)
            if "installed.json" in fset and base == "composer" and parent == "vendor":
                self._composer_installed(dirpath)
            if "Gemfile.lock" in fset and not in_nm:
                self._gemfile_lock(dirpath)
            for fn in filenames:
                if fn.lower().endswith((".jar", ".war", ".ear")):
                    full = os.path.join(dirpath, fn)
                    if not os.path.islink(full):
                        self._archive(full)

    # -- python --------------------------------------------------------
    def _python_dist(self, d, filenames):
        meta = "METADATA" if "METADATA" in filenames else ("PKG-INFO" if "PKG-INFO" in filenames else None)
        if not meta:
            return
        name = ver = None
        try:
            with open(os.path.join(d, meta), encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        break
                    if line.startswith("Name:"):
                        name = line[5:].strip()
                    elif line.startswith("Version:"):
                        ver = line[8:].strip()
        except OSError:
            return
        if not name or not ver:
            return
        site = os.path.dirname(d)
        p = {"ecosystem": "PyPI", "name": norm_name("PyPI", name), "version": ver,
             "location": site, "dist_dir": d}
        venv = self._find_venv(site)
        if venv:
            p.update(manager="pip-venv", python=os.path.join(venv, "bin", "python"), project=venv)
        elif under_os_prefix(site):
            p["manager"] = "os"
        elif site.startswith("/usr/local/"):
            m = re.search(r"/python(\d+\.\d+)/", site + "/")
            p.update(manager="pip-system", python=which("python" + m.group(1)) if m else which("python3"))
        else:
            p["manager"] = "pip-user"
        self._add(p)

    @staticmethod
    def _find_venv(path):
        cur = path
        for _ in range(5):
            if os.path.isfile(os.path.join(cur, "pyvenv.cfg")):
                return cur
            nxt = os.path.dirname(cur)
            if nxt == cur:
                break
            cur = nxt
        return None

    # -- npm -----------------------------------------------------------
    def _npm_pkg(self, d):
        data = read_json(os.path.join(d, "package.json"), {})
        if not isinstance(data, dict):
            return
        name, ver = data.get("name"), data.get("version")
        if not isinstance(name, str) or not isinstance(ver, str) or not name or not ver:
            return
        idx = d.find("/node_modules/")
        prefix = d[:idx] or "/"
        top_level = d.count("/node_modules/") == 1
        p = {"ecosystem": "npm", "name": name, "version": ver, "location": d, "top_level": top_level}
        is_global = prefix.endswith("/lib") and not os.path.isfile(os.path.join(prefix, "package.json"))
        if is_global:
            p["manager"] = "npm-global"
            p["project"] = prefix
            if under_os_prefix(d):
                pkg_root = d if top_level else d[:d.index("/", idx + len("/node_modules/"))]
                if pkg_root not in self._owner_cache:
                    self._owner_cache[pkg_root] = owner_package(self.pm, os.path.join(pkg_root, "package.json")) if self.pm else None
                if self._owner_cache[pkg_root]:
                    p["manager"] = "os"
        elif under_os_prefix(d):
            p["manager"] = "os"
        else:
            p["manager"] = "npm-project"
            p["project"] = prefix
        self._add(p)

    # -- composer ------------------------------------------------------
    def _composer_lock(self, d):
        data = read_json(os.path.join(d, "composer.lock"), {})
        if not isinstance(data, dict):
            return
        self._project(d, "composer", "composer.lock")
        if os.path.isfile(os.path.join(d, "composer.json")):
            self._project(d, "composer", "composer.json")
        for key in ("packages", "packages-dev"):
            for pk in data.get(key) or []:
                p = self._composer_entry(pk, d, key == "packages-dev")
                if p:
                    self._add(p)

    def _composer_installed(self, d):
        data = read_json(os.path.join(d, "installed.json"))
        pkgs = data.get("packages", []) if isinstance(data, dict) else (data or [])
        proj = os.path.dirname(os.path.dirname(d))
        out = [p for p in (self._composer_entry(pk, proj, False) for pk in pkgs) if p]
        self.composer_installed.append((proj, out))

    @staticmethod
    def _composer_entry(pk, proj, dev):
        if not isinstance(pk, dict):
            return None
        name, ver = pk.get("name"), str(pk.get("version", ""))
        if not name or not ver or ver.startswith("dev-"):
            return None
        return {"ecosystem": "Packagist", "name": name, "version": ver.lstrip("vV"),
                "location": proj, "project": proj, "dev": dev,
                "manager": "os" if under_os_prefix(proj) else "composer"}

    # -- ruby ----------------------------------------------------------
    def _gemfile_lock(self, d):
        section = None
        managed = "os" if under_os_prefix(d) else "bundler"
        self._project(d, "bundler", "Gemfile.lock")
        try:
            with open(os.path.join(d, "Gemfile.lock"), encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line and not line.startswith(" "):
                        section = line.strip()
                        continue
                    if section != "GEM":
                        continue
                    m = re.match(r"^    ([^ (]+) \(([^)]+)\)\s*$", line)
                    if m:
                        ver = m.group(2).split("-")[0]
                        self._add({"ecosystem": "RubyGems", "name": m.group(1), "version": ver,
                                   "location": d, "project": d, "manager": managed})
        except OSError:
            pass

    # -- java archives -------------------------------------------------
    def _archive(self, path, depth=0, fileobj=None, label=None):
        label = label or path
        found = 0
        try:
            if fileobj is None:
                if os.path.getsize(path) > self.max_archive:
                    return 0
                zf = zipfile.ZipFile(path)
            else:
                zf = zipfile.ZipFile(fileobj)
        except Exception:
            return 0
        top = label.split("!/")[0]
        try:
            with zf:
                for info in zf.infolist():
                    n = info.filename
                    if POM_RE.search(n):
                        props = {}
                        for line in zf.read(info).decode("utf-8", "replace").splitlines():
                            k, sep, v = line.partition("=")
                            if sep and not k.startswith("#"):
                                props[k.strip()] = v.strip()
                        g, a, v = props.get("groupId"), props.get("artifactId"), props.get("version")
                        if g and a and v and "$" not in v:
                            found += 1
                            self._add({"ecosystem": "Maven", "name": "%s:%s" % (g, a), "version": v,
                                       "location": label, "archive": top,
                                       "manager": "os" if under_os_prefix(top) else "jar"})
                    elif (depth < 2 and n.lower().endswith((".jar", ".war"))
                          and info.file_size < self.max_archive):
                        found += self._archive(None, depth + 1, io.BytesIO(zf.read(info)),
                                               label + "!/" + n)
        except Exception as e:
            log.debug("cannot read archive %s: %s", label, e)
        if depth == 0 and not found:
            self.unidentified_jars.append(path)
        return found


# --------------------------------------------------------------------------
# OSV lookup
# --------------------------------------------------------------------------

class Osv(object):
    def __init__(self, cache_dir, timeout, workers):
        self.dir = os.path.join(cache_dir, "osv")
        os.makedirs(self.dir, exist_ok=True)
        self.timeout = timeout
        self.workers = workers

    def _cache_path(self, vid):
        return os.path.join(self.dir, re.sub(r"[^A-Za-z0-9_.-]", "_", vid) + ".json")

    def _cached(self, vid, modified):
        v = read_json(self._cache_path(vid))
        if v and (not modified or v.get("modified") == modified):
            return v
        return None

    def _store(self, v):
        try:
            write_json(self._cache_path(v["id"]), v)
        except (OSError, KeyError):
            pass

    def lookup(self, queries):
        """queries: iterable of (ecosystem, name, version).
        Returns {query: [full vuln dicts]}."""
        queries = list(dict.fromkeys(q for q in queries if q[0] and q[1] and q[2]))
        ids = {q: [] for q in queries}
        for chunk in chunks(queries, 1000):
            pending = [(q, None) for q in chunk]
            while pending:
                payload = {"queries": []}
                for (eco, name, ver), tok in pending:
                    item = {"package": {"ecosystem": eco, "name": name}, "version": ver}
                    if tok:
                        item["page_token"] = tok
                    payload["queries"].append(item)
                resp = http_json(OSV_BATCH_URL, payload, timeout=max(self.timeout, 60)) or {}
                nxt = []
                for (q, _), r in zip(pending, resp.get("results", [])):
                    ids[q].extend((v["id"], v.get("modified")) for v in r.get("vulns") or [])
                    if r.get("next_page_token"):
                        nxt.append((q, r["next_page_token"]))
                pending = nxt

        details = {}
        missing = {}
        for q, lst in ids.items():
            for vid, mod in lst:
                if vid in details:
                    continue
                v = self._cached(vid, mod)
                if v:
                    details[vid] = v
                else:
                    missing.setdefault(q, []).append(vid)

        # Packages with many uncached vulns: one /v1/query returns them all.
        bulk = [q for q, lst in missing.items() if len(lst) > 2]
        single = sorted(set(vid for q, lst in missing.items() if len(lst) <= 2 for vid in lst))

        def fetch_query(q):
            out, tok = [], None
            while True:
                body = {"package": {"ecosystem": q[0], "name": q[1]}, "version": q[2]}
                if tok:
                    body["page_token"] = tok
                r = http_json(OSV_QUERY_URL, body, timeout=max(self.timeout, 60)) or {}
                out.extend(r.get("vulns") or [])
                tok = r.get("next_page_token")
                if not tok:
                    return out

        def fetch_one(vid):
            return http_json(OSV_VULN_URL + urllib.parse.quote(vid, safe=""), timeout=self.timeout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as ex:
            for vulns in ex.map(fetch_query, bulk):
                for v in vulns:
                    details[v["id"]] = v
                    self._store(v)
            todo = [vid for vid in single if vid not in details]
            for v in ex.map(fetch_one, todo):
                if v:
                    details[v["id"]] = v
                    self._store(v)

        return {q: [details[vid] for vid, _ in lst if vid in details] for q, lst in ids.items()}


def eco_match(affected_eco, eco):
    if ":" in eco or ":" in affected_eco:
        return affected_eco == eco
    return affected_eco.split(":")[0] == eco.split(":")[0]


def fix_for(vuln, eco, name, installed):
    """Smallest 'fixed' version greater than the installed one (None = unfixed)."""
    cands = []
    for aff in vuln.get("affected") or []:
        pk = aff.get("package") or {}
        if norm_name(eco.split(":")[0], pk.get("name")) != norm_name(eco.split(":")[0], name):
            continue
        if not eco_match(pk.get("ecosystem", ""), eco):
            continue
        for r in aff.get("ranges") or []:
            if r.get("type") == "GIT":
                continue
            for ev in r.get("events") or []:
                f = ev.get("fixed")
                if f and vcmp(eco, f, installed) > 0:
                    cands.append(f)
    if not cands:
        return None
    best = cands[0]
    for c in cands[1:]:
        if vcmp(eco, c, best) < 0:
            best = c
    return best


# --------------------------------------------------------------------------
# collect / assess / plan / apply
# --------------------------------------------------------------------------

def collect(cfg, args, state_dir, refresh=True):
    osr = read_os_release()
    pm = detect_pkg_manager(osr)
    inv = {"os": {"id": osr.get("ID"), "name": osr.get("PRETTY_NAME"), "version": osr.get("VERSION_ID")},
           "package_manager": pm, "osv_ecosystem": osv_os_ecosystem(osr, cfg),
           "kernel": os.uname().release, "os_packages": [], "runtimes": [], "libraries": [],
           "projects": [], "unidentified_jars": [], "os_updates": [], "errors": []}
    if refresh and pm and cfg["refresh_package_index"] and is_root():
        log.info("refreshing package index (%s)", pm)
        refresh_index(pm)
    if cfg["scan_os_packages"] and pm:
        log.info("collecting OS packages via %s", pm)
        inv["os_packages"] = inventory_os(pm)
        inv["os_updates"] = pending_updates(pm)
    if cfg["scan_runtimes"]:
        log.info("detecting language runtimes")
        inv["runtimes"] = inventory_runtimes(pm, EolCache(os.path.join(state_dir, "cache"), cfg["http_timeout"]))
    if cfg["scan_libraries"]:
        log.info("scanning filesystem for libraries: %s", ", ".join(cfg["scan_paths"]))
        sc = FsScanner(cfg, pm)
        inv["libraries"] = sc.scan()
        inv["projects"] = list(sc.projects.values())
        inv["unidentified_jars"] = sc.unidentified_jars
    return inv


def assess(inv, cfg, state_dir):
    osv = Osv(os.path.join(state_dir, "cache"), cfg["http_timeout"], cfg["workers"])
    eco_os = inv["osv_ecosystem"]
    queries = []
    src_map = {}
    if eco_os:
        for p in inv["os_packages"]:
            q = (eco_os, p["source"], p["source_version"])
            queries.append(q)
            src_map.setdefault(q, []).append(p["name"])
    libs = [l for l in inv["libraries"]
            if l["manager"] != "os" or cfg["report_os_managed_libraries"]]
    for l in libs:
        queries.append((l["ecosystem"], l["name"], l["version"]))
    for rt in inv["runtimes"]:
        if rt["runtime"] == "go":
            queries.append(("Go", "stdlib", rt["version"]))

    log.info("querying OSV.dev for %d unique package versions", len(set(queries)))
    try:
        res = osv.lookup(queries)
    except Exception as e:
        inv["errors"].append("OSV lookup failed: %s" % e)
        log.error("OSV lookup failed: %s", e)
        res = {}

    ignore = set(cfg["ignore_vulns"])
    excl = set(cfg["exclude_packages"])
    min_rank = sev_rank(cfg["min_severity"])
    findings = []

    def mk(v, eco, name, version, extra):
        aliases = v.get("aliases") or []
        if v["id"] in ignore or ignore.intersection(aliases):
            return None
        sev, score = vuln_severity(v)
        if sev != "UNKNOWN" and sev_rank(sev) < min_rank:
            return None
        f = {"ecosystem": eco, "name": name, "version": version, "id": v["id"],
             "aliases": aliases, "cves": sorted(a for a in [v["id"]] + aliases if a.startswith("CVE-")),
             "summary": ((v.get("summary") or v.get("details") or "").strip().splitlines() or [""])[0][:200],
             "severity": sev, "score": score, "fixed_in": fix_for(v, eco, name, version),
             "url": "https://osv.dev/vulnerability/" + v["id"]}
        f.update(extra)
        return f

    if eco_os:
        for q, bins in src_map.items():
            for v in res.get(q, []):
                if q[1] in excl:
                    continue
                f = mk(v, q[0], q[1], q[2], {"layer": "os", "manager": "os", "binaries": sorted(set(bins)),
                                              "location": ""})
                if f and not (cfg["ignore_unfixed_os"] and not f["fixed_in"]):
                    findings.append(f)
    for l in libs:
        if l["name"] in excl:
            continue
        for v in res.get((l["ecosystem"], l["name"], l["version"]), []):
            extra = {k: l.get(k) for k in ("manager", "location", "project", "python", "top_level", "archive", "dev")
                     if l.get(k) is not None}
            extra["layer"] = "library"
            f = mk(v, l["ecosystem"], l["name"], l["version"], extra)
            if f:
                findings.append(f)
    for rt in inv["runtimes"]:
        if rt["runtime"] == "go":
            for v in res.get(("Go", "stdlib", rt["version"]), []):
                f = mk(v, "Go", "stdlib", rt["version"], {"layer": "runtime", "manager": "runtime",
                                                          "location": rt["path"]})
                if f:
                    findings.append(f)
    findings.sort(key=lambda f: (-sev_rank(f["severity"]), -(f["score"] or 0), f["name"]))
    return findings


def _apt_env():
    env = dict(os.environ)
    env.update(DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l", APT_LISTCHANGES_FRONTEND="none")
    return env


def plan(inv, findings, cfg, os_mode):
    pm = inv["package_manager"]
    pcfg = cfg["patch"]
    excl = set(cfg["exclude_packages"])
    actions = []

    # ---- OS layer ----------------------------------------------------
    ups = inv["os_updates"]
    vuln_bins = set()
    for f in findings:
        if f["layer"] == "os":
            vuln_bins.update(f.get("binaries") or [f["name"]])
    if pm and os_mode != "none":
        title = "OS updates (%s, mode=%s)" % (pm, os_mode)
        cmd, names = None, []
        if pm == "apt":
            if os_mode == "all":
                sel = ups
            elif os_mode == "security":
                sel = [u for u in ups if u["security"]]
            else:
                sel = [u for u in ups if u["security"] or u["name"] in vuln_bins]
            names = sorted(set(u["name"] for u in sel) - excl)
            if names:
                cmd = ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef",
                       "-o", "Dpkg::Options::=--force-confold", "install", "--only-upgrade"] + names
        elif pm in ("dnf", "yum"):
            sel = ups if os_mode == "all" else [u for u in ups if u["security"]]
            names = sorted(set(u["name"] for u in sel) - excl)
            if names:
                cmd = [pm, "-y", "upgrade"] + ([] if os_mode == "all" else ["--security"])
                cmd += ["--exclude=%s" % e for e in sorted(excl)]
        elif pm == "zypper":
            sel = ups if os_mode == "all" else [u for u in ups if u["security"]]
            names = [u["name"] for u in sel]
            if names:
                cmd = (["zypper", "--non-interactive", "update"] if os_mode == "all" else
                       ["zypper", "--non-interactive", "patch", "--category", "security"])
        elif pm == "apk":
            if os_mode == "all":
                sel = ups
            else:
                sel = [u for u in ups if u["name"] in vuln_bins]
            names = sorted(set(u["name"] for u in sel) - excl)
            if names:
                cmd = ["apk", "upgrade", "--no-cache"] + ([] if os_mode == "all" else names)
        elif pm == "pacman":
            sel = ups if os_mode == "all" else [u for u in ups if u["security"]]
            names = [u["name"] for u in sel]
            if names:  # Arch does not support partial upgrades
                cmd = ["pacman", "-Syu", "--noconfirm"] + (["--ignore", ",".join(sorted(excl))] if excl else [])
        if cmd:
            actions.append({"layer": "os", "title": title, "cmd": cmd, "packages": names,
                            "enabled": True, "needs_root": True,
                            "env": "apt" if pm == "apt" else None})
        elif ups and os_mode != "all":
            actions.append({"layer": "os", "manual": True, "title": "OS updates",
                            "detail": "%d update(s) pending but none classified as %s; use --os-mode all "
                                      "to install them" % (len(ups), os_mode)})

    # ---- libraries ---------------------------------------------------
    by_pkg = {}
    for f in findings:
        if f["layer"] != "library":
            continue
        key = (f["ecosystem"], f["name"], f["version"], f.get("location"))
        by_pkg.setdefault(key, []).append(f)

    groups = {}
    manual = []
    os_libs = []
    for (eco, name, ver, loc), fs in by_pkg.items():
        f0 = fs[0]
        mgr = f0.get("manager")
        fixes = [f["fixed_in"] for f in fs if f["fixed_in"]]
        target = vmax(eco, fixes)
        unfixed = [f["id"] for f in fs if not f["fixed_in"]]
        ids = ", ".join(sorted(set(f["cves"][0] if f["cves"] else f["id"] for f in fs))[:6])
        if mgr == "os":
            os_libs.append("%s %s %s" % (eco, name, ver))
            continue
        if not target:
            manual.append({"layer": "library", "manual": True,
                           "title": "%s %s %s at %s" % (eco, name, ver, loc),
                           "detail": "no fixed version published yet (%s) - mitigate or replace" % ", ".join(unfixed[:5])})
            continue
        if mgr == "pip-venv":
            groups.setdefault(("pypi", f0["python"]), []).append((name, target))
        elif mgr == "pip-system" and pcfg["pip_allow_system"] and f0.get("python"):
            groups.setdefault(("pypi-system", f0["python"]), []).append((name, target))
        elif mgr == "npm-global" and f0.get("top_level"):
            groups.setdefault(("npm-global", f0.get("project")), []).append((name, target))
        elif mgr == "npm-project":
            groups.setdefault(("npm-project", f0["project"]), []).append((name, target))
        elif mgr == "composer":
            groups.setdefault(("composer", f0["project"]), []).append((name, target))
        elif mgr == "bundler":
            groups.setdefault(("bundler", f0["project"]), []).append((name, target))
        else:
            where = f0.get("archive") or loc
            hint = {"jar": "rebuild/redeploy the application with %s:%s (or replace the jar)" % (name, target),
                    "pip-user": "as the owning user: pip install --user --upgrade '%s==%s'" % (name, target),
                    "pip-system": "pip install --upgrade '%s==%s' (set patch.pip_allow_system to automate)" % (name, target),
                    "npm-global": "transitive dependency: update its parent package (npm update -g)"}.get(
                        mgr, "upgrade to %s" % target)
            manual.append({"layer": "library", "manual": True, "title": "%s %s %s in %s" % (eco, name, ver, where),
                           "detail": "%s [%s]" % (hint, ids)})

    if os_libs:
        os_libs = sorted(set(os_libs))
        manual.append({"layer": "library", "manual": True, "packages": os_libs,
                       "title": "%d vulnerable libraries shipped inside OS packages" % len(os_libs),
                       "detail": "fixed through OS updates, not pip/npm/gem (distros often backport fixes, so "
                                 "check the distro security tracker): %s%s" % (
                                     ", ".join(os_libs[:8]), " ..." if len(os_libs) > 8 else "")})

    for (kind, where), items in sorted(groups.items()):
        items = sorted(set(items))
        names = [n for n, _ in items]
        if kind in ("pypi", "pypi-system"):
            cmd = [where, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check"]
            m = re.search(r"python(\d+\.\d+)", os.path.basename(where))
            if kind == "pypi-system" and m and glob.glob("/usr/lib/python%s/EXTERNALLY-MANAGED" % m.group(1)):
                cmd.append("--break-system-packages")
            cmd += ["%s==%s" % (n, t) for n, t in items]
            proj = os.path.dirname(os.path.dirname(where)) if kind == "pypi" else None
            actions.append({"layer": "library", "title": "pip upgrade in %s" % (proj or where), "cmd": cmd,
                            "packages": names, "enabled": bool(pcfg["pypi"]), "toggle": "patch.pypi",
                            "user": path_owner(proj) if proj else None, "needs_root": kind == "pypi-system",
                            "backup_dir": proj, "backup_files": []})
        elif kind == "npm-global":
            cmd = ["npm", "install", "-g"] + ["%s@%s" % (n, t) for n, t in items]
            actions.append({"layer": "library", "title": "npm global upgrade (%s)" % where, "cmd": cmd,
                            "packages": names, "enabled": bool(pcfg["npm"]), "toggle": "patch.npm",
                            "needs_root": where.startswith("/usr"), "requires": "npm"})
        elif kind == "npm-project":
            has_lock = os.path.isfile(os.path.join(where, "package-lock.json"))
            if not has_lock:
                manual.append({"layer": "library", "manual": True, "title": "npm project %s" % where,
                               "detail": "no package-lock.json; upgrade %s manually" %
                                         ", ".join("%s@%s" % i for i in items)})
                continue
            actions.append({"layer": "library", "title": "npm audit fix in %s" % where,
                            "cmd": ["npm", "audit", "fix", "--no-fund"], "cwd": where,
                            "packages": names, "enabled": bool(pcfg["npm"]), "toggle": "patch.npm",
                            "user": path_owner(where), "requires": "npm", "backup_dir": where,
                            "backup_files": ["package.json", "package-lock.json"]})
        elif kind == "composer":
            actions.append({"layer": "library", "title": "composer update in %s" % where,
                            "cmd": ["composer", "update", "--no-interaction", "--with-dependencies"] + names,
                            "cwd": where, "packages": names, "enabled": bool(pcfg["composer"]),
                            "toggle": "patch.composer", "user": path_owner(where), "requires": "composer",
                            "backup_dir": where, "backup_files": ["composer.json", "composer.lock"]})
        elif kind == "bundler":
            actions.append({"layer": "library", "title": "bundle update in %s" % where,
                            "cmd": ["bundle", "update", "--conservative"] + names, "cwd": where,
                            "packages": names, "enabled": bool(pcfg["rubygems"]), "toggle": "patch.rubygems",
                            "user": path_owner(where), "requires": "bundle", "backup_dir": where,
                            "backup_files": ["Gemfile", "Gemfile.lock"]})

    # ---- runtimes ----------------------------------------------------
    for rt in inv["runtimes"]:
        if rt["status"] not in ("eol", "outdated"):
            continue
        if rt["status"] == "eol":
            detail = "%s %s branch is END-OF-LIFE (since %s) - no more security fixes; migrate to a supported " \
                     "version" % (rt["runtime"], rt["cycle"], rt.get("eol_date"))
        else:
            detail = "upstream latest in %s branch is %s" % (rt["cycle"], rt["latest"])
            if rt.get("os_package"):
                detail += " (installed from OS package %s - distro may backport fixes; covered by OS updates)" \
                          % rt["os_package"]
        manual.append({"layer": "runtime", "manual": True,
                       "title": "%s %s (%s)" % (rt["runtime"], rt["version"], rt["path"]), "detail": detail})

    for f in findings:
        if f["layer"] == "runtime" and f["fixed_in"]:
            manual.append({"layer": "runtime", "manual": True, "title": "Go toolchain %s (%s)" % (f["version"], f["location"]),
                           "detail": "rebuild Go binaries with go >= %s [%s]" % (f["fixed_in"], f["id"])})
            break

    return actions + manual


def apply_plan(actions, inv, state_dir, cfg):
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    bdir = os.path.join(state_dir, "backups", ts)
    os.makedirs(bdir, exist_ok=True)
    applied = False
    for a in actions:
        if a.get("manual"):
            continue
        if not a.get("enabled"):
            a["result"] = "skipped (disabled; set %s=true)" % a.get("toggle", "")
            continue
        if a.get("needs_root") and not is_root():
            a["result"] = "skipped (needs root)"
            continue
        if a.get("requires") and not which(a["requires"]):
            a["result"] = "skipped (%s not installed)" % a["requires"]
            continue
        if a["layer"] == "os":
            with open(os.path.join(bdir, "os-packages-before.txt"), "w") as f:
                for p in inv["os_packages"]:
                    f.write("%s\t%s\n" % (p["name"], p["version"]))
        if a.get("backup_dir"):
            dst = os.path.join(bdir, a["backup_dir"].strip("/").replace("/", "__"))
            os.makedirs(dst, exist_ok=True)
            for fn in a.get("backup_files", []):
                src = os.path.join(a["backup_dir"], fn)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
        env = _apt_env() if a.get("env") == "apt" else None
        cmd = as_user(a.get("user"), a["cmd"])
        log.info("APPLY: %s\n    $ %s", a["title"], " ".join(cmd))
        rc, out, err = run(cmd, cwd=a.get("cwd"), timeout=3600, env=env)
        a["rc"] = rc
        a["result"] = "ok" if rc == 0 else "failed (rc=%d)" % rc
        a["output_tail"] = (out + "\n" + err).strip()[-2000:]
        if rc != 0:
            log.error("%s failed (rc=%d): %s", a["title"], rc, err.strip()[-500:])
        applied = True
    if not os.listdir(bdir):
        os.rmdir(bdir)
    return applied


def restart_status(cfg, applied):
    st = {"reboot_required": os.path.exists("/var/run/reboot-required"), "services": [], "actions": []}
    if which("needs-restarting"):
        rc, _, _ = run(["needs-restarting", "-r"])
        st["reboot_required"] = st["reboot_required"] or rc == 1
    if which("needrestart"):
        rc, out, _ = run(["needrestart", "-b", "-r", "l"])
        for line in out.splitlines():
            if line.startswith("NEEDRESTART-SVC:"):
                st["services"].append(line.split(":", 1)[1].strip())
            elif line.startswith("NEEDRESTART-KSTA:") and line.split(":", 1)[1].strip() in ("2", "3"):
                st["reboot_required"] = True
    if applied and is_root():
        if cfg["patch"]["restart_services"] and st["services"] and which("needrestart"):
            rc, _, err = run(["needrestart", "-r", "a"], env=_apt_env())
            st["actions"].append("needrestart -r a (rc=%d)" % rc)
        if cfg["patch"]["auto_reboot"] and st["reboot_required"]:
            delay = int(cfg["patch"]["reboot_delay_minutes"])
            run(["shutdown", "-r", "+%d" % delay, "vulnagent: reboot to finish security updates"])
            st["actions"].append("reboot scheduled in %d min" % delay)
    return st


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def build_report(inv, findings, actions, applied, restart, prev):
    by_sev = {s: 0 for s in reversed(SEVERITIES)}
    for f in findings:
        by_sev[f["severity"]] += 1
    lib_counts = {}
    for l in inv["libraries"]:
        lib_counts[l["ecosystem"]] = lib_counts.get(l["ecosystem"], 0) + 1
    keyf = lambda f: "%s|%s|%s|%s" % (f["id"], f["ecosystem"], f["name"], f.get("location", ""))
    prev_keys = set(keyf(f) for f in (prev or {}).get("findings", []))
    new = [f for f in findings if keyf(f) not in prev_keys] if prev else []
    vulnerable = set((f["ecosystem"], f["name"], f["version"], f.get("location")) for f in findings)
    return {
        "agent": "vulnagent " + VERSION,
        "host": socket.getfqdn(),
        "generated": now_iso(),
        "os": inv["os"], "kernel": inv["kernel"], "package_manager": inv["package_manager"],
        "osv_ecosystem": inv["osv_ecosystem"],
        "summary": {
            "os_packages": len(inv["os_packages"]),
            "libraries": lib_counts,
            "runtimes": len(inv["runtimes"]),
            "vulnerabilities": len(findings),
            "by_severity": by_sev,
            "vulnerable_packages": len(vulnerable),
            "fixable": sum(1 for f in findings if f["fixed_in"]),
            "new_since_last_run": len(new),
            "os_updates_pending": len(inv["os_updates"]),
            "os_security_updates_pending": sum(1 for u in inv["os_updates"] if u["security"]),
            "eol_runtimes": sum(1 for r in inv["runtimes"] if r["status"] == "eol"),
            "applied": applied,
        },
        "runtimes": inv["runtimes"],
        "findings": findings,
        "new_findings": [keyf(f) for f in new],
        "os_updates": inv["os_updates"],
        "plan": actions,
        "restart": restart,
        "projects": inv["projects"],
        "unidentified_jars": inv["unidentified_jars"],
        "inventory": {"os_packages": inv["os_packages"], "libraries": inv["libraries"]},
        "errors": inv["errors"],
    }


_COL = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m", "LOW": "\033[36m",
        "UNKNOWN": "\033[2m", "eol": "\033[1;31m", "outdated": "\033[33m", "ok": "\033[32m"}


def text_report(rep, limit=40, color=False):
    def c(key, s):
        return "%s%s\033[0m" % (_COL[key], s) if color and key in _COL else s

    s = rep["summary"]
    out = []
    out.append("=" * 78)
    out.append("vulnagent report  host=%s  %s" % (rep["host"], rep["generated"]))
    out.append("OS: %s  kernel %s  pkg-mgr=%s  osv-ecosystem=%s" % (
        rep["os"].get("name"), rep["kernel"], rep["package_manager"], rep["osv_ecosystem"] or "n/a"))
    out.append("Inventory: %d OS packages | libraries: %s | %d runtimes" % (
        s["os_packages"], ", ".join("%s=%d" % kv for kv in sorted(s["libraries"].items())) or "none",
        s["runtimes"]))
    out.append("=" * 78)
    if rep["runtimes"]:
        out.append("\nRuntimes:")
        for r in rep["runtimes"]:
            st = r["status"].upper()
            extra = ""
            if r["status"] == "outdated":
                extra = " (latest %s)" % r["latest"]
            elif r["status"] == "eol":
                extra = " (EOL since %s)" % r["eol_date"]
            out.append("  %-7s %-14s %-9s%s  %s%s" % (r["runtime"], r["version"], c(r["status"], st), extra,
                                                     r["path"], " [pkg %s]" % r["os_package"] if r["os_package"] else ""))
    groups = {}
    for f in rep["findings"]:
        k = (f["ecosystem"], f["name"], f["version"], f.get("location") or ",".join(f.get("binaries", [])[:3]))
        groups.setdefault(k, []).append(f)
    out.append("\nVulnerable packages: %d   vulnerabilities: %d   (%s)" % (
        len(groups), s["vulnerabilities"],
        ", ".join("%s %d" % (k, v) for k, v in s["by_severity"].items() if v) or "none"))
    if s["new_since_last_run"]:
        out.append("  %d new since last run" % s["new_since_last_run"])
    for i, ((eco, name, ver, loc), fs) in enumerate(sorted(groups.items(),
                                                        key=lambda kv: (-max(sev_rank(f["severity"]) for f in kv[1]),
                                                                        kv[0][1]))):
        if i >= limit:
            out.append("  ... %d more (see JSON/HTML report or use --limit)" % (len(groups) - limit))
            break
        worst = max(fs, key=lambda f: (sev_rank(f["severity"]), f["score"] or 0))
        fixes = [f["fixed_in"] for f in fs if f["fixed_in"]]
        target = vmax(eco, fixes)
        ids = sorted(set(f["cves"][0] if f["cves"] else f["id"] for f in fs))
        out.append("  %s %s %s %s  fix: %s  [%s]" % (
            c(worst["severity"], "%-8s" % worst["severity"]), eco, name, ver, target or "none",
            fs[0].get("manager")))
        out.append("           %s%s" % (", ".join(ids[:5]), " (+%d)" % (len(ids) - 5) if len(ids) > 5 else ""))
        if loc:
            out.append("           at %s" % loc)
    out.append("\nOS updates pending: %d (security: %d)" % (s["os_updates_pending"], s["os_security_updates_pending"]))
    out.append("\nRemediation plan:")
    for a in rep["plan"]:
        if a.get("manual"):
            out.append("  [manual] %s\n           %s" % (a["title"], a["detail"]))
        else:
            tag = "auto" if a.get("enabled") else "off "
            res = (" -> " + a["result"]) if a.get("result") else ""
            cmd = " ".join(a["cmd"])
            if len(cmd) > 160:
                cmd = cmd[:157] + "..."
            out.append("  [%s]   %s (%d pkg)%s\n           $ %s" % (tag, a["title"], len(a.get("packages", [])), res, cmd))
    if not rep["plan"]:
        out.append("  nothing to do")
    r = rep["restart"]
    if r and (r.get("reboot_required") or r.get("services")):
        out.append("\nRestart: reboot_required=%s services=%s %s" % (
            r["reboot_required"], ", ".join(r["services"][:10]) or "-", "; ".join(r.get("actions", []))))
    if rep["unidentified_jars"]:
        out.append("\n%d jar/war file(s) had no Maven metadata and could not be checked" % len(rep["unidentified_jars"]))
    for e in rep["errors"]:
        out.append("ERROR: " + e)
    return "\n".join(out)


def html_report(rep):
    e = html.escape
    s = rep["summary"]
    sevcol = {"CRITICAL": "#b00020", "HIGH": "#e65100", "MEDIUM": "#f9a825", "LOW": "#0277bd", "UNKNOWN": "#777"}
    rows = []
    for f in rep["findings"]:
        rows.append("<tr><td><span class=sev style='background:%s'>%s</span></td><td>%s</td><td>%s</td><td>%s</td>"
                    "<td>%s</td><td><a href='%s'>%s</a><br><small>%s</small></td><td>%s</td><td class=loc>%s</td></tr>" % (
                        sevcol.get(f["severity"], "#777"), e(f["severity"]), e(f["ecosystem"]), e(f["name"]),
                        e(f["version"]), e(f["fixed_in"] or "-"), e(f["url"]), e(f["id"]), e(", ".join(f["cves"][:3])),
                        e(f["summary"]), e(f.get("location") or ", ".join(f.get("binaries", [])[:5]))))
    rts = "".join("<tr><td>%s</td><td>%s</td><td class='st-%s'>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        e(r["runtime"]), e(r["version"]), e(r["status"]), e(r["status"].upper()), e(r["latest"] or "-"),
        e(r["path"]), e(r["os_package"] or "-")) for r in rep["runtimes"])
    plan = "".join("<li><b>%s</b> %s<br><code>%s</code></li>" % (
        "[manual]" if a.get("manual") else ("[auto]" if a.get("enabled") else "[off]"), e(a["title"]),
        e(a.get("detail") or " ".join(a.get("cmd", [])) + ((" &rarr; " + a["result"]) if a.get("result") else "")))
        for a in rep["plan"])
    cards = "".join("<div class=card><div class=n style='color:%s'>%d</div>%s</div>" % (sevcol[k], v, k)
                    for k, v in s["by_severity"].items())
    return """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>vulnagent - %(host)s</title><style>
:root{--bg:#fff;--fg:#1d1d1f;--mut:#666;--line:#e3e3e3;--card:#f6f6f7}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececec;--mut:#9a9a9a;--line:#2c2c30;--card:#1e1e22}}
body{font:14px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px 16px;max-width:1300px;margin:auto}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}.mut{color:var(--mut)}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}.card{background:var(--card);border-radius:8px;padding:10px 16px;min-width:90px}
.n{font-size:24px;font-weight:700}table{border-collapse:collapse;width:100%%;font-size:13px}
td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.sev{color:#fff;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:700}.loc{word-break:break-all;color:var(--mut)}
.st-eol{color:#b00020;font-weight:700}.st-outdated{color:#e65100}.st-ok{color:#2e7d32}code{font-size:12px;word-break:break-all}
a{color:inherit}.wrap{overflow-x:auto}li{margin-bottom:8px}</style></head><body>
<h1>Vulnerability report &ndash; %(host)s</h1>
<div class=mut>%(os)s &middot; kernel %(kernel)s &middot; %(gen)s &middot; %(agent)s</div>
<div class=cards>%(cards)s<div class=card><div class=n>%(pk)d</div>vulnerable pkgs</div>
<div class=card><div class=n>%(upd)d</div>OS updates (%(sec)d sec)</div></div>
<h2>Runtimes</h2><div class=wrap><table><tr><th>Runtime</th><th>Version</th><th>Status</th><th>Latest</th><th>Path</th><th>OS package</th></tr>%(rts)s</table></div>
<h2>Vulnerabilities (%(nv)d)</h2><div class=wrap><table><tr><th>Severity</th><th>Ecosystem</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>ID</th><th>Summary</th><th>Location</th></tr>%(rows)s</table></div>
<h2>Remediation plan</h2><ul>%(plan)s</ul></body></html>""" % {
        "host": e(rep["host"]), "os": e(rep["os"].get("name") or ""), "kernel": e(rep["kernel"]),
        "gen": e(rep["generated"]), "agent": e(rep["agent"]), "cards": cards, "pk": s["vulnerable_packages"],
        "upd": s["os_updates_pending"], "sec": s["os_security_updates_pending"], "rts": rts,
        "nv": len(rep["findings"]), "rows": "".join(rows), "plan": plan or "<li>nothing to do</li>"}


def save_report(rep, state_dir, keep):
    rdir = os.path.join(state_dir, "reports")
    os.makedirs(rdir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(rdir, "report-%s.json" % ts)
    write_json(path, rep)
    write_json(os.path.join(rdir, "latest.json"), rep)
    with open(os.path.join(rdir, "latest.html"), "w", encoding="utf-8") as f:
        f.write(html_report(rep))
    old = sorted(glob.glob(os.path.join(rdir, "report-*.json")))
    for p in old[:-keep] if keep > 0 else []:
        try:
            os.remove(p)
        except OSError:
            pass
    return path


def notify(rep, cfg):
    n = cfg["notify"]
    s = rep["summary"]
    if n.get("webhook_url") and (s["vulnerabilities"] or s["eol_runtimes"] or not n.get("only_on_findings")):
        sev = ", ".join("%s: %d" % (k, v) for k, v in s["by_severity"].items() if v) or "none"
        lines = ["*vulnagent* `%s` (%s)" % (rep["host"], rep["os"].get("name")),
                 "Vulnerabilities: %d (%s), %d new since last run" % (s["vulnerabilities"], sev, s["new_since_last_run"]),
                 "OS updates pending: %d (security %d)%s" % (s["os_updates_pending"], s["os_security_updates_pending"],
                                                              " - patches applied" if s["applied"] else ""),
                 ]
        if s["eol_runtimes"]:
            lines.append("EOL runtimes: " + ", ".join("%s %s" % (r["runtime"], r["version"])
                                                       for r in rep["runtimes"] if r["status"] == "eol"))
        top = [f for f in rep["findings"] if f["severity"] in ("CRITICAL", "HIGH")][:8]
        for f in top:
            lines.append("- %s %s %s %s -> %s (%s)" % (f["severity"], f["ecosystem"], f["name"], f["version"],
                                                       f["fixed_in"] or "no fix", f["cves"][0] if f["cves"] else f["id"]))
        if rep["restart"].get("reboot_required"):
            lines.append("Reboot required")
        text = "\n".join(lines)
        try:
            http_json(n["webhook_url"], {"text": text, "content": text[:1900]}, timeout=cfg["http_timeout"], retries=2)
        except Exception as e:
            log.warning("webhook failed: %s", e)
    if n.get("report_upload_url"):
        hdr = {"Authorization": "Bearer " + n["report_upload_token"]} if n.get("report_upload_token") else {}
        slim = dict(rep)
        slim.pop("inventory", None)
        try:
            http_json(n["report_upload_url"], slim, timeout=cfg["http_timeout"], retries=2, headers=hdr)
        except Exception as e:
            log.warning("report upload failed: %s", e)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def load_config(path, args):
    cfg = DEFAULT_CONFIG
    if path and os.path.isfile(path):
        user = read_json(path)
        if user is None:
            raise SystemExit("cannot parse config %s (must be JSON)" % path)
        cfg = deep_merge(DEFAULT_CONFIG, user)
    elif path and args.config_given:
        raise SystemExit("config file %s not found" % path)
    cfg = json.loads(json.dumps(cfg))  # deep copy
    if getattr(args, "paths", None):
        cfg["scan_paths"] = args.paths
    if getattr(args, "no_libs", False):
        cfg["scan_libraries"] = False
    if getattr(args, "no_os", False):
        cfg["scan_os_packages"] = False
    if getattr(args, "os_ecosystem", None):
        cfg["os_ecosystem_override"] = args.os_ecosystem
    if getattr(args, "min_severity", None):
        cfg["min_severity"] = args.min_severity.upper()
    if getattr(args, "libs", False):
        for k in ("pypi", "npm", "composer", "rubygems"):
            cfg["patch"][k] = True
    if getattr(args, "os_mode", None):
        cfg["patch"]["os"] = args.os_mode
    if cfg["patch"]["os"] not in OS_MODES:
        raise SystemExit("patch.os must be one of %s" % ", ".join(OS_MODES))
    return cfg


def resolve_state_dir(cfg):
    for d in (cfg["state_dir"], os.path.join(os.path.expanduser("~"), ".cache", "vulnagent")):
        try:
            os.makedirs(os.path.join(d, "cache"), exist_ok=True)
            if os.access(d, os.W_OK):
                return d
        except OSError:
            continue
    raise SystemExit("no writable state directory")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vulnagent", description=__doc__.split("\n\n")[0].strip(),
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-c", "--config", default=None, help="config file (default /etc/vulnagent/config.json)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true", help="only warnings/errors on stderr")
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="command")

    def common(p):
        p.add_argument("--paths", nargs="+", help="override scan_paths")
        p.add_argument("--no-libs", action="store_true", help="skip filesystem library scan")
        p.add_argument("--no-os", action="store_true", help="skip OS packages")
        p.add_argument("--os-ecosystem", help="OSV ecosystem for OS packages, e.g. Debian:12")
        p.add_argument("--min-severity", choices=["low", "medium", "high", "critical"])
        p.add_argument("--json", action="store_true", help="print full JSON report to stdout")
        p.add_argument("--limit", type=int, default=40, help="max packages listed in text output")

    p_inv = sub.add_parser("inventory", help="list what is installed (no vulnerability lookup)")
    p_inv.add_argument("--paths", nargs="+")
    p_inv.add_argument("--no-libs", action="store_true")
    p_inv.add_argument("--no-os", action="store_true")
    p_inv.add_argument("--json", action="store_true")
    common(sub.add_parser("scan", help="inventory + vulnerability check + remediation plan (changes nothing)"))
    p_patch = sub.add_parser("patch", help="scan and patch (dry-run unless --apply)")
    common(p_patch)
    p_run = sub.add_parser("run", help="agent mode for the systemd timer: scan, patch if auto_apply, report, notify")
    common(p_run)
    for p in (p_patch, p_run):
        p.add_argument("--apply", action="store_true", help="really execute the plan")
        p.add_argument("--os-mode", choices=OS_MODES, help="override patch.os")
        p.add_argument("--libs", action="store_true", help="enable pip/npm/composer/bundler patching")

    args = ap.parse_args(argv)
    if not args.command:
        ap.print_help()
        return 2
    logging.basicConfig(level=logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S", stream=sys.stderr)
    args.config_given = args.config is not None
    cfg = load_config(args.config or "/etc/vulnagent/config.json", args)
    state_dir = resolve_state_dir(cfg)
    if not is_root():
        log.warning("not running as root: some files may be unreadable and nothing can be patched")

    if args.command == "inventory":
        inv = collect(cfg, args, state_dir, refresh=False)
        if args.json:
            print(json.dumps(inv, indent=2, default=str))
        else:
            print("OS: %s, package manager: %s, %d packages" % (inv["os"]["name"], inv["package_manager"],
                                                              len(inv["os_packages"])))
            for r in inv["runtimes"]:
                print("runtime  %-7s %-12s %-9s %s" % (r["runtime"], r["version"], r["status"], r["path"]))
            for l in sorted(inv["libraries"], key=lambda l: (l["ecosystem"], l["name"])):
                print("%-9s %-50s %-16s %-11s %s" % (l["ecosystem"], l["name"], l["version"], l["manager"], l["location"]))
            print("%d libraries, %d projects, %d OS updates pending" % (
                len(inv["libraries"]), len(inv["projects"]), len(inv["os_updates"])))
        return 0

    lock = open(os.path.join(state_dir, "vulnagent.lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log.error("another vulnagent run is in progress")
        return 3

    prev = read_json(os.path.join(state_dir, "reports", "latest.json"))
    inv = collect(cfg, args, state_dir)
    findings = assess(inv, cfg, state_dir)
    actions = plan(inv, findings, cfg, cfg["patch"]["os"])

    do_apply = args.command in ("patch", "run") and (getattr(args, "apply", False) or
                                                     (args.command == "run" and cfg["auto_apply"]))
    applied = False
    if do_apply:
        applied = apply_plan(actions, inv, state_dir, cfg)
        if applied:
            log.info("re-scanning after patching")
            inv2 = collect(cfg, args, state_dir, refresh=False)
            inv2["errors"] = inv["errors"] + inv2["errors"]
            findings = assess(inv2, cfg, state_dir)
            inv = inv2
    elif args.command == "patch":
        log.warning("dry-run: nothing was changed. Re-run with --apply to execute the plan.")

    restart = restart_status(cfg, applied)
    rep = build_report(inv, findings, actions, applied, restart, prev)
    path = save_report(rep, state_dir, int(cfg["keep_reports"]))
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
    else:
        print(text_report(rep, limit=args.limit, color=sys.stdout.isatty()))
        print("\nReports: %s  |  %s" % (path, os.path.join(state_dir, "reports", "latest.html")))
    if args.command == "run":
        notify(rep, cfg)
    if rep["errors"]:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
