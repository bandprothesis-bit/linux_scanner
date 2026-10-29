#!/usr/bin/env python3
"""
vulnagent-dojo - send the latest vulnagent report to DefectDojo.

Reads the JSON report vulnagent writes after every run
(<state_dir>/reports/latest.json), converts it to DefectDojo's
"Generic Findings Import" format and uploads it with the reimport API:

  * one DefectDojo product per machine (created automatically),
  * findings fixed since the last upload are closed automatically,
  * new findings are added, unchanged ones keep their history.

Only the Python 3.6+ standard library is required.

  vulnagent-dojo                      upload using /etc/vulnagent/defectdojo.json
  vulnagent-dojo --dry-run -o x.json  only write the converted findings file
"""

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
import uuid

VERSION = "1.0.0"
SCAN_TYPE = "Generic Findings Import"

DEFAULT_CONFIG = {
    "url": "",                       # https://defectdojo.example.com
    "api_token": "",                 # DefectDojo -> user menu -> API v2 Key (or env DD_API_TOKEN)
    "product_type": "Linux servers",
    "product_name": "{host}",        # {host} = FQDN, {short} = short hostname
    "engagement_name": "vulnagent",
    "test_title": "vulnagent",
    "close_old_findings": True,      # close findings that are no longer reported
    "minimum_severity": "Info",
    "include_os_managed_libraries": True,
    "include_runtimes": True,        # EOL / outdated PHP, Java, Python, ...
    "include_pending_advisories": True,  # RPM/SUSE: pending security errata as findings
    "agent_config": "/etc/vulnagent/config.json",
    "report": "",                    # default: <state_dir>/reports/latest.json
    "verify_tls": True,
    "ca_file": "",                   # internal CA bundle for a self-signed DefectDojo
    "timeout": 600,
}

SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "UNKNOWN": "Info"}
# Red Hat / Rocky / Alma / Oracle / SUSE advisory severities
ADVISORY_SEV = {"critical": "Critical", "important": "High", "moderate": "Medium", "low": "Low"}


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.isfile(path):
        user = read_json(path)
        if user is None:
            raise SystemExit("cannot parse %s (must be JSON)" % path)
        cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
    return cfg


def report_path(cfg):
    if cfg["report"]:
        return cfg["report"]
    agent = read_json(cfg["agent_config"]) or {}
    dirs = [agent.get("state_dir"), "/var/lib/vulnagent", os.path.expanduser("~/.cache/vulnagent")]
    for d in dirs:
        if d and os.path.isfile(os.path.join(d, "reports", "latest.json")):
            return os.path.join(d, "reports", "latest.json")
    raise SystemExit("no vulnagent report found (looked in %s). Run 'vulnagent scan' first."
                     % ", ".join(d for d in dirs if d))


def clip(s, n):
    s = s or ""
    return s if len(s) <= n else s[:n - 3] + "..."


# --------------------------------------------------------------------------
# report -> Generic Findings Import
# --------------------------------------------------------------------------
# DefectDojo identifies a finding by a hash of title + description (+ file_path),
# so both only contain values that stay the same while the problem exists.
# Things that change on their own (fixed version, score) go into other fields.

def vuln_finding(f):
    ident = f["cves"][0] if f.get("cves") else f["id"]
    where = f.get("location") or ""
    os_managed = f["layer"] == "library" and f.get("manager") == "os"
    desc = [f.get("summary") or ident, "",
            "**Package:** %s %s (%s)" % (f["name"], f["version"], f["ecosystem"])]
    if f.get("binaries"):
        desc.append("**Installed binary packages:** " + ", ".join(f["binaries"]))
    if where:
        desc.append("**Location:** " + where)
    if f.get("project"):
        desc.append("**Project:** " + f["project"])
    if f.get("archive"):
        desc.append("**Inside archive:** " + f["archive"])
    desc.append("**Advisory:** %s" % ", ".join([f["id"]] + [a for a in f.get("aliases", []) if a != f["id"]]))
    if os_managed:
        desc += ["", "This library was installed by an OS package. The distribution may have backported "
                     "the fix without changing the version, so verify before acting."]

    if f.get("fixed_in"):
        if f["layer"] == "os" or os_managed:
            mitigation = "Install OS updates (fixed in %s %s)." % (f["name"], f["fixed_in"])
        else:
            mitigation = "Upgrade %s to %s or later." % (f["name"], f["fixed_in"])
    else:
        mitigation = "No fixed version published yet. Mitigate or accept the risk."

    tags = ["vulnagent", f["layer"], re.sub(r"[^a-z0-9]+", "-", f["ecosystem"].lower()).strip("-")]
    if os_managed:
        tags.append("os-managed")
    out = {
        "title": clip("%s: %s %s" % (ident, f["name"], f["version"]), 500),
        "severity": SEV.get(f["severity"], "Info"),
        "description": "\n".join(desc),
        "mitigation": mitigation,
        "references": f.get("url") or "",
        "component_name": clip(f["name"], 200),
        "component_version": clip(f["version"], 100),
        "vuln_id_from_tool": f["id"],
        "unique_id_from_tool": clip("|".join([f["id"], f["ecosystem"], f["name"], f["version"], where]), 500),
        "vulnerability_ids": sorted(set([f["id"]] + f.get("aliases", []))),
        "static_finding": True,
        "dynamic_finding": False,
        "tags": tags,
    }
    if where:
        out["file_path"] = clip(where, 4000)
    if f.get("score"):
        out["cvssv3_score"] = float(f["score"])
    return out


def runtime_finding(r):
    if r["status"] == "eol":
        title = "%s %s is end-of-life" % (r["runtime"], r["cycle"] or r["version"])
        sev = "High"
        mitigation = "Upgrade to a supported %s release (EOL since %s)." % (r["runtime"], r.get("eol_date"))
    else:
        title = "%s %s is missing patch releases" % (r["runtime"], r["version"])
        sev = "Low" if r.get("os_package") else "Medium"
        mitigation = "Update %s to %s or later." % (r["runtime"], r.get("latest"))
    desc = ["**Runtime:** %s %s" % (r["runtime"], r["version"]), "**Path:** " + r["path"]]
    if r.get("os_package"):
        desc += ["**OS package:** " + r["os_package"], "",
                 "Installed by an OS package: the distribution may ship fixes without changing the version."]
    return {
        "title": title, "severity": sev, "description": "\n".join(desc), "mitigation": mitigation,
        "references": "https://endoflife.date/" + r["runtime"],
        "component_name": r["runtime"], "component_version": r["version"], "file_path": r["path"],
        "vuln_id_from_tool": "runtime-" + r["status"],
        "unique_id_from_tool": "runtime|%s|%s|%s" % (r["runtime"], r["version"], r["path"]),
        "static_finding": True, "dynamic_finding": False,
        "tags": ["vulnagent", "runtime", r["status"]],
    }


def advisory_findings(updates):
    """Pending security errata (dnf/yum/zypper) grouped per advisory."""
    groups = {}
    for u in updates:
        if not u.get("security"):
            continue
        adv = (u.get("advisory") or "").split()
        key = adv[0] if adv else u["name"]
        g = groups.setdefault(key, {"level": adv[1] if len(adv) > 1 else "", "pkgs": []})
        g["pkgs"].append(u)
    out = []
    for key, g in sorted(groups.items()):
        level = g["level"].split("/")[0].lower()
        names = sorted(set(u["name"] for u in g["pkgs"]))
        if key.startswith("("):  # zypper only reports a count
            title, sev = "Pending SUSE security patches", "High"
            desc = "zypper reports %s. Run 'zypper list-patches --category security' for details." % key.strip("()")
        else:
            title, sev = "%s: security update for %s" % (key, ", ".join(names[:3]) + (" ..." if len(names) > 3 else "")), \
                ADVISORY_SEV.get(level, "Medium")
            desc = "Security advisory %s (%s) is available but not installed.\n\n**Packages:** %s" % (
                key, g["level"] or "unrated", ", ".join(names))
        out.append({
            "title": clip(title, 500), "severity": sev, "description": desc,
            "mitigation": "Install the security updates (vulnagent patch --apply, or dnf upgrade --advisory=%s)." % key
            if not key.startswith("(") else "zypper patch --category security",
            "component_name": names[0] if len(names) == 1 else "",
            "vuln_id_from_tool": key, "unique_id_from_tool": "advisory|" + key,
            "vulnerability_ids": [key] if re.match(r"^[A-Z]+-\d{4}:\d+$", key) else [],
            "static_finding": True, "dynamic_finding": False,
            "tags": ["vulnagent", "os", "advisory"],
        })
    return out


def convert(rep, cfg):
    findings = []
    for f in rep.get("findings", []):
        if f["layer"] == "library" and f.get("manager") == "os" and not cfg["include_os_managed_libraries"]:
            continue
        findings.append(vuln_finding(f))
    if cfg["include_runtimes"]:
        findings += [runtime_finding(r) for r in rep.get("runtimes", []) if r.get("status") in ("eol", "outdated")]
    # Debian/Ubuntu/Alpine already have per-CVE OS findings from OSV; elsewhere
    # the distro's security errata are the OS findings.
    if cfg["include_pending_advisories"] and not rep.get("osv_ecosystem"):
        findings += advisory_findings(rep.get("os_updates", []))
    for x in findings:
        if not x.get("vulnerability_ids"):
            x.pop("vulnerability_ids", None)
        if not x.get("component_name"):
            x.pop("component_name", None)
    s = rep.get("summary", {})
    return {
        "name": "vulnagent",
        "type": SCAN_TYPE,
        "version": rep.get("agent", "").replace("vulnagent ", ""),
        "description": "%s - %s, kernel %s, %d OS packages, %d OS updates pending (%d security)" % (
            rep.get("host"), (rep.get("os") or {}).get("name"), rep.get("kernel"),
            s.get("os_packages", 0), s.get("os_updates_pending", 0), s.get("os_security_updates_pending", 0)),
        "findings": findings,
    }


# --------------------------------------------------------------------------
# upload
# --------------------------------------------------------------------------

def multipart(fields, filename, content):
    boundary = uuid.uuid4().hex
    parts = []
    for k, v in fields.items():
        parts.append(('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                      % (boundary, k, v)).encode("utf-8"))
    parts.append(('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
                  'Content-Type: application/json\r\n\r\n' % (boundary, filename)).encode("utf-8"))
    parts.append(content + b"\r\n")
    parts.append(("--%s--\r\n" % boundary).encode("utf-8"))
    return b"".join(parts), "multipart/form-data; boundary=" + boundary


def upload(cfg, rep, doc):
    url = cfg["url"].rstrip("/")
    if not url:
        raise SystemExit("DefectDojo url is not set (config 'url' or --url)")
    token = cfg["api_token"] or os.environ.get("DD_API_TOKEN", "")
    if not token:
        raise SystemExit("DefectDojo API token is not set (config 'api_token', --token or env DD_API_TOKEN)")
    host = rep.get("host") or socket.getfqdn()
    product = cfg["product_name"].format(host=host, short=host.split(".")[0])
    date = (rep.get("generated") or datetime.date.today().isoformat())[:10]
    close_old = cfg["close_old_findings"]
    if close_old and rep.get("errors"):
        # an incomplete scan must not close findings it simply did not check
        print("report has errors (%s): not closing old findings this time" % "; ".join(rep["errors"])[:300],
              file=sys.stderr)
        close_old = False
    fields = {
        "scan_type": SCAN_TYPE,
        "product_type_name": cfg["product_type"],
        "product_name": product,
        "engagement_name": cfg["engagement_name"],
        "test_title": cfg["test_title"],
        "auto_create_context": "true",
        "close_old_findings": "true" if close_old else "false",
        "deduplication_on_engagement": "true",
        "minimum_severity": cfg["minimum_severity"],
        "active": "true",
        "verified": "false",
        "scan_date": date,
        "version": doc["version"],
    }
    body, ctype = multipart(fields, "vulnagent-%s.json" % host, json.dumps(doc).encode("utf-8"))
    req = urllib.request.Request(url + "/api/v2/reimport-scan/", data=body, headers={
        "Authorization": "Token " + token, "Content-Type": ctype, "Accept": "application/json",
        "User-Agent": "vulnagent-dojo/" + VERSION})
    if cfg["ca_file"]:
        ctx = ssl.create_default_context(cafile=cfg["ca_file"])
    elif not cfg["verify_tls"]:
        ctx = ssl._create_unverified_context()
    else:
        ctx = None
    try:
        with urllib.request.urlopen(req, timeout=cfg["timeout"], context=ctx) as r:
            res = json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:2000]
        hint = {401: " (wrong API token?)", 403: " (token user may not import into this product type)",
                400: " (check product_type exists or that the user may create products)"}.get(e.code, "")
        raise SystemExit("DefectDojo returned HTTP %d%s:\n%s" % (e.code, hint, detail))
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        raise SystemExit("cannot reach DefectDojo at %s: %s" % (url, getattr(e, "reason", e)))
    return product, res


def stats_line(res):
    delta = ((res.get("statistics") or {}).get("delta") or {})
    parts = []
    for k in ("created", "closed", "reactivated", "untouched"):
        total = (delta.get(k) or {}).get("total", {}).get("total")
        if total is not None:
            parts.append("%s %d" % (k, total))
    return ", ".join(parts)


def main():
    ap = argparse.ArgumentParser(description="Upload the latest vulnagent report to DefectDojo.")
    ap.add_argument("-c", "--config", default="/etc/vulnagent/defectdojo.json")
    ap.add_argument("--report", help="vulnagent JSON report (default: latest)")
    ap.add_argument("--url", help="DefectDojo base URL")
    ap.add_argument("--token", help="DefectDojo API v2 token (prefer the config file or DD_API_TOKEN)")
    ap.add_argument("--product", help="product name (default: the host name)")
    ap.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate")
    ap.add_argument("--dry-run", action="store_true", help="convert only, do not upload")
    ap.add_argument("-o", "--output", help="also write the converted findings file here")
    ap.add_argument("-V", "--version", action="version", version="vulnagent-dojo " + VERSION)
    args = ap.parse_args()

    cfg = load_config(args.config)
    for key, val in (("report", args.report), ("url", args.url), ("api_token", args.token),
                     ("product_name", args.product)):
        if val:
            cfg[key] = val
    if args.insecure:
        cfg["verify_tls"] = False

    path = report_path(cfg)
    rep = read_json(path)
    if not rep or "findings" not in rep:
        raise SystemExit("%s is not a vulnagent report" % path)
    doc = convert(rep, cfg)
    by_sev = {}
    for f in doc["findings"]:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    summary = ", ".join("%s %d" % (s, by_sev[s]) for s in ("Critical", "High", "Medium", "Low", "Info")
                        if s in by_sev) or "none"
    print("report %s (%s, %s): %d findings - %s" % (path, rep.get("host"), rep.get("generated"),
                                                   len(doc["findings"]), summary))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        print("wrote %s" % args.output)
    if args.dry_run:
        return 0
    product, res = upload(cfg, rep, doc)
    print("uploaded to DefectDojo product '%s' (test %s)%s" % (
        product, res.get("test_id", res.get("test", "?")),
        ": " + stats_line(res) if stats_line(res) else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
