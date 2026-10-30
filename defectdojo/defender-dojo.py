#!/usr/bin/env python3
"""
defender-dojo - import Microsoft Defender for Endpoint vulnerabilities into DefectDojo.

For every customer in the config it:
  1. gets an app-only token from Microsoft Entra ID (client credentials),
  2. reads the device list (api/machines) and the vulnerabilities per device
     (api/vulnerabilities/machinesVulnerabilities),
  3. uploads each active device as its own DefectDojo product, under a product
     type named after the customer, with the reimport API: fixed findings are
     closed, new ones added, history kept.

Needs read-only API permissions Machine.Read.All and Vulnerability.Read.All
(WindowsDefenderATP) and a Defender licence that includes vulnerability
management. Only the Python 3.6+ standard library is required.

  defender-dojo --test                 check login and counts, upload nothing
  defender-dojo                        import all customers
  defender-dojo --customer Contoso     import one customer
  defender-dojo --dry-run -o /tmp/x    write the per-device files only
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "1.0.0"
SCAN_TYPE = "Generic Findings Import"
PAGE = 10000  # Defender's maximum $top

DEFAULT_CONFIG = {
    "defectdojo": {"url": "", "api_token": "", "verify_tls": True, "ca_file": "", "timeout": 600},
    # Microsoft endpoints (change only for government clouds)
    "login_url": "https://login.microsoftonline.com",
    "api_url": "https://api.securitycenter.microsoft.com",
    "scope": "https://api.securitycenter.microsoft.com/.default",
    # shared app registration (multi-tenant / partner access); a customer may override
    "client_id": "",
    "client_secret": "",
    # defaults every customer inherits
    "product_name": "{host} ({customer})",
    "engagement_name": "defender",
    "test_title": "defender",
    "skip_inactive_days": 30,
    "minimum_severity": "Info",
    "upload_workers": 4,
    "http_timeout": 120,
    "customers": [],
}
INHERITED = ("login_url", "api_url", "scope", "client_id", "client_secret", "product_name",
             "engagement_name", "test_title", "skip_inactive_days", "minimum_severity")
SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


def log(msg, *args):
    print(msg % args if args else msg, flush=True)


def load_config(path):
    try:
        with open(path, encoding="utf-8") as f:
            user = json.load(f)
    except OSError as e:
        raise SystemExit("cannot read %s: %s" % (path, e.strerror))
    except ValueError as e:
        raise SystemExit("cannot parse %s: %s" % (path, e))
    if os.name == "posix" and os.stat(path).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        log("warning: %s holds secrets but is readable by other users (chmod 600 it)", path)
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    for k, v in user.items():
        if k.startswith("_"):
            continue
        if k == "defectdojo":
            cfg["defectdojo"].update({a: b for a, b in v.items() if not a.startswith("_")})
        else:
            cfg[k] = v
    if not cfg["defectdojo"]["api_token"]:
        cfg["defectdojo"]["api_token"] = os.environ.get("DD_API_TOKEN", "")
    customers = []
    for c in cfg["customers"]:
        c = {k: v for k, v in c.items() if not k.startswith("_")}
        if not c.get("name") or not c.get("tenant_id"):
            raise SystemExit("every customer needs a 'name' and a 'tenant_id'")
        for k in INHERITED:
            c.setdefault(k, cfg[k])
        c.setdefault("product_type", c["name"])
        c.setdefault("enabled", True)
        if c["client_secret"].startswith("env:"):
            c["client_secret"] = os.environ.get(c["client_secret"][4:], "")
        customers.append(c)
    cfg["customers"] = customers
    return cfg


def request(url, data=None, headers=None, timeout=120, context=None, retries=4):
    """Returns (status, body bytes). Retries throttling and server errors."""
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers=dict(headers or {}, **{
            "User-Agent": "defender-dojo/" + VERSION}))
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            body = e.read()
            if e.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                try:
                    wait = int(e.headers.get("Retry-After") or 0)
                except ValueError:
                    wait = 0
                time.sleep(min(wait or 2 ** (attempt + 2), 120))
                continue
            return e.code, body
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            if attempt < retries - 1:
                time.sleep(2 ** (attempt + 1))
                continue
            raise RuntimeError("cannot reach %s: %s" % (urllib.parse.urlsplit(url).netloc,
                                                        getattr(e, "reason", e)))
    raise RuntimeError("giving up on %s" % urllib.parse.urlsplit(url).netloc)


def error_text(body):
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return body.decode("utf-8", "replace")[:300]
    if "error_description" in d:  # Entra ID
        return d["error_description"].splitlines()[0]
    err = d.get("error")
    if isinstance(err, dict):
        return "%s: %s" % (err.get("code"), err.get("message"))
    return json.dumps(d)[:300]


# --------------------------------------------------------------------------
# Microsoft Defender
# --------------------------------------------------------------------------

class Defender:
    def __init__(self, c, timeout):
        self.c = c
        self.timeout = timeout
        self.token = None

    def login(self):
        c = self.c
        if not c["client_id"] or not c["client_secret"]:
            raise RuntimeError("client_id / client_secret not set")
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": c["client_id"],
            "client_secret": c["client_secret"], "scope": c["scope"]}).encode()
        url = "%s/%s/oauth2/v2.0/token" % (c["login_url"].rstrip("/"), urllib.parse.quote(c["tenant_id"]))
        st, b = request(url, body, {"Content-Type": "application/x-www-form-urlencoded"}, self.timeout)
        if st != 200:
            raise RuntimeError("sign-in to tenant %s failed (HTTP %d): %s" % (c["tenant_id"], st, error_text(b)))
        self.token = json.loads(b.decode("utf-8"))["access_token"]

    def get_all(self, path):
        base = self.c["api_url"].rstrip("/") + path
        url, skip, items, relogged = base + "?$top=%d" % PAGE, 0, [], False
        while url:
            st, b = request(url, headers={"Authorization": "Bearer " + self.token,
                                          "Accept": "application/json"}, timeout=self.timeout)
            if st == 401 and not relogged:  # token expired during a long export
                self.login()
                relogged = True
                continue
            if st == 404:  # Defender's answer when there is nothing to list
                return items
            if st == 403:
                raise RuntimeError("%s: access denied. The app needs the application permissions "
                                   "Machine.Read.All and Vulnerability.Read.All (WindowsDefenderATP) with "
                                   "admin consent, and the licence must include vulnerability management. %s"
                                   % (path, error_text(b)))
            if st != 200:
                raise RuntimeError("%s: HTTP %d: %s" % (path, st, error_text(b)))
            d = json.loads(b.decode("utf-8"))
            page = d.get("value", [])
            items.extend(page)
            if d.get("@odata.nextLink"):
                url = d["@odata.nextLink"]
            elif len(page) >= PAGE:
                skip += PAGE
                url = base + "?$top=%d&$skip=%d" % (PAGE, skip)
            else:
                url = None
        return items


def parse_time(s):
    try:
        return datetime.datetime.strptime((s or "")[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def nice(s):
    return (s or "").replace("_", " ").strip()


def to_findings(vulns, machine):
    """One finding per CVE and product version on this device. Title and
    description hold only what stays the same while the problem exists (the
    fixing KB can be superseded), because DefectDojo matches findings on them."""
    seen = {}
    for v in vulns:
        cve = v.get("cveId") or v.get("id") or "unknown"
        key = (cve, v.get("productVendor"), v.get("productName"), v.get("productVersion"))
        if key in seen:
            continue
        vendor, name = nice(v.get("productVendor")), nice(v.get("productName"))
        product = name if vendor.lower() in name.lower() else ("%s %s" % (vendor.title(), name)).strip()
        version = v.get("productVersion") or ""
        kb = v.get("fixingKbId")
        f = {
            "title": ("%s: %s %s" % (cve, product, version)).strip()[:500],
            "severity": SEV.get((v.get("severity") or "").lower(), "Info"),
            "description": "Microsoft Defender reports %s in %s %s.\n\n**Vendor:** %s\n**Product:** %s\n**Version:** %s"
                           % (cve, product, version, v.get("productVendor") or "-", v.get("productName") or "-",
                              version or "-"),
            "mitigation": ("Install the update KB%s (Windows Update / WSUS / Intune)." % kb) if kb else
                          "Update %s to a version that fixes %s (see the Defender portal for the recommendation)."
                          % (product or "the product", cve),
            "references": "https://nvd.nist.gov/vuln/detail/%s" % cve if cve.startswith("CVE-") else "",
            "component_name": (v.get("productName") or "")[:200],
            "component_version": version[:100],
            "vuln_id_from_tool": cve,
            "unique_id_from_tool": "%s|%s|%s|%s|%s" % (machine["id"], cve, v.get("productVendor"),
                                                       v.get("productName"), version),
            "static_finding": False,
            "dynamic_finding": False,
            "tags": ["defender"] + ([re.sub(r"[^a-z0-9]+", "-", machine["osPlatform"].lower()).strip("-")]
                                    if machine.get("osPlatform") else []),
        }
        if cve.startswith("CVE-"):
            f["vulnerability_ids"] = [cve]
        if not f["references"]:
            del f["references"]
        if not f["component_name"]:
            del f["component_name"]
        seen[key] = f
    return list(seen.values())


def device_doc(machine, findings):
    return {
        "name": "Microsoft Defender for Endpoint",
        "type": SCAN_TYPE,
        "description": "%s - %s %s, last seen %s, Defender device id %s" % (
            machine.get("computerDnsName") or machine["id"], machine.get("osPlatform") or "",
            machine.get("version") or "", machine.get("lastSeen") or "?", machine["id"]),
        "findings": findings,
    }


# --------------------------------------------------------------------------
# DefectDojo
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


def dojo_context(dd):
    if dd.get("ca_file"):
        return ssl.create_default_context(cafile=dd["ca_file"])
    if not dd.get("verify_tls", True):
        return ssl._create_unverified_context()
    return None


def upload(dd, c, product, doc):
    fields = {
        "scan_type": SCAN_TYPE,
        "product_type_name": c["product_type"],
        "product_name": product,
        "engagement_name": c["engagement_name"],
        "test_title": c["test_title"],
        "auto_create_context": "true",
        "close_old_findings": "true",
        "deduplication_on_engagement": "true",
        "minimum_severity": c["minimum_severity"],
        "active": "true",
        "verified": "false",
        "scan_date": datetime.date.today().isoformat(),
        "version": "defender-dojo " + VERSION,
    }
    body, ctype = multipart(fields, "defender.json", json.dumps(doc).encode("utf-8"))
    st, b = request(dd["url"].rstrip("/") + "/api/v2/reimport-scan/", body, {
        "Authorization": "Token " + dd["api_token"], "Content-Type": ctype, "Accept": "application/json"},
        timeout=dd.get("timeout", 600), context=dojo_context(dd), retries=2)
    if st not in (200, 201):
        hint = {401: " (wrong DefectDojo API token?)",
                403: " (the token's user may not create products in this product type)"}.get(st, "")
        raise RuntimeError("DefectDojo HTTP %d%s: %s" % (st, hint, b.decode("utf-8", "replace")[:500]))
    res = json.loads(b.decode("utf-8") or "{}")
    delta = (res.get("statistics") or {}).get("delta") or {}
    return {k: ((delta.get(k) or {}).get("total") or {}).get("total", 0) for k in ("created", "closed", "reactivated")}


# --------------------------------------------------------------------------

def run_customer(cfg, c, mode, outdir):
    log("== %s (tenant %s)", c["name"], c["tenant_id"])
    d = Defender(c, cfg["http_timeout"])
    d.login()
    machines = d.get_all("/api/machines")
    vulns = d.get_all("/api/vulnerabilities/machinesVulnerabilities")
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cutoff = now - datetime.timedelta(days=int(c["skip_inactive_days"] or 36500))
    active = {}
    for m in machines:
        seen = parse_time(m.get("lastSeen"))
        if seen is None or seen >= cutoff:
            active[m["id"]] = m
    by_machine = {}
    for v in vulns:
        if v.get("machineId") in active:
            by_machine.setdefault(v["machineId"], []).append(v)
    log("   %d devices (%d active in the last %s days), %d vulnerability rows",
        len(machines), len(active), c["skip_inactive_days"], len(vulns))
    if mode == "test":
        return 0

    jobs = []
    names = {}
    # sorted by name, then device id, so a duplicate name always gets the same suffix
    for mid, m in sorted(active.items(), key=lambda kv: ((kv[1].get("computerDnsName") or kv[0]).lower(), kv[0])):
        host = (m.get("computerDnsName") or mid).lower()
        product = c["product_name"].format(host=host, short=host.split(".")[0], customer=c["name"])
        if product in names:  # two devices with the same name: keep them apart
            product = "%s [%s]" % (product, mid[:8])
        names[product] = mid
        jobs.append((product, device_doc(m, to_findings(by_machine.get(mid, []), m))))

    if mode == "dry-run":
        os.makedirs(outdir, exist_ok=True)
        for product, doc in jobs:
            fn = re.sub(r"[^A-Za-z0-9._-]+", "_", product) + ".json"
            with open(os.path.join(outdir, fn), "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=1)
        log("   wrote %d device files to %s", len(jobs), outdir)
        return 0

    failed = 0
    totals = {"created": 0, "closed": 0, "reactivated": 0}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(cfg["upload_workers"]))) as ex:
        futs = {ex.submit(upload, cfg["defectdojo"], c, p, doc): (p, doc) for p, doc in jobs}
        for fut in concurrent.futures.as_completed(futs):
            product, doc = futs[fut]
            try:
                st = fut.result()
                for k in totals:
                    totals[k] += st[k]
                log("   %-50s %4d findings  created %d, closed %d, reactivated %d",
                    product, len(doc["findings"]), st["created"], st["closed"], st["reactivated"])
            except Exception as e:
                failed += 1
                log("   %-50s FAILED: %s", product, e)
    log("   done: %d devices uploaded, %d failed; created %d, closed %d, reactivated %d",
        len(jobs) - failed, failed, totals["created"], totals["closed"], totals["reactivated"])
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description="Import Microsoft Defender vulnerabilities into DefectDojo.")
    ap.add_argument("-c", "--config", default="/etc/vulnagent/defender.json")
    ap.add_argument("--customer", action="append", help="only this customer (repeatable)")
    ap.add_argument("--test", action="store_true", help="sign in and count devices; upload nothing")
    ap.add_argument("--dry-run", action="store_true", help="write the per-device files instead of uploading")
    ap.add_argument("-o", "--output", default="defender-dryrun", help="folder for --dry-run")
    ap.add_argument("-V", "--version", action="version", version="defender-dojo " + VERSION)
    args = ap.parse_args()

    cfg = load_config(args.config)
    mode = "test" if args.test else ("dry-run" if args.dry_run else "upload")
    if mode == "upload" and (not cfg["defectdojo"]["url"] or not cfg["defectdojo"]["api_token"]):
        raise SystemExit("defectdojo.url and defectdojo.api_token must be set in %s" % args.config)
    wanted = set(n.lower() for n in args.customer or [])
    customers = [c for c in cfg["customers"] if c["enabled"] and (not wanted or c["name"].lower() in wanted)]
    if not customers:
        raise SystemExit("no matching enabled customers in %s" % args.config)

    rc = 0
    for c in customers:
        try:
            # a failed export stops this customer before anything is uploaded,
            # so DefectDojo never closes findings because of missing data
            rc |= run_customer(cfg, c, mode, os.path.join(args.output, re.sub(r"\W+", "_", c["name"])))
        except Exception as e:
            log("   %s: FAILED: %s", c["name"], e)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
