# vulnagent + DefectDojo

This add-on sends every machine's vulnagent results to one central [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) console. DefectDojo is an open-source (OWASP) vulnerability management web application.

After each daily run, `vulnagent-dojo` uploads the report:

- **One product per machine.** DefectDojo creates the product the first time that machine reports.
- **Fixed findings close automatically.** A vulnerability that is gone in the next report is closed.
- **New findings are added.** Unchanged ones keep their history, notes, assignments and risk acceptances.
- **Findings are tagged** by layer (`os`, `library`, `runtime`, `advisory`), by ecosystem (`debian-13`, `pypi`, `maven`, …) and with `os-managed`, so you can filter in DefectDojo.

What gets uploaded from each machine:

| vulnagent result | DefectDojo finding |
|---|---|
| Vulnerable OS package (Debian, Ubuntu, Alpine) | One finding per CVE and package, with the fixed version as the mitigation |
| Vulnerable library (PHP, Java, Python, Node, Ruby) | One finding per vulnerability and location, with the CVE, GHSA and CVSS score |
| Pending security errata (Rocky, RHEL, Alma, SUSE) | One finding per advisory (`RLSA-…`, `RHSA-…`), with the advisory's severity |
| End-of-life runtime | High |
| Runtime missing patch releases | Low if the OS package manages it, Medium otherwise |
| Certificate expired | High |
| Certificate expiring within 7 days | High |
| Certificate expiring within 30 days (`cert_warning_days` in `/etc/vulnagent/config.json`) | Medium |
| Every other certificate on the machine | Info: an inventory, with subject, issuer, DNS names, fingerprints, file and the server config that uses it |

Reporting is one-way. Patching is still controlled by each machine's `/etc/vulnagent/config.json`.

**Windows servers** report to the same DefectDojo with a PowerShell agent. A second script checks them against the Microsoft security baseline and reports each deviation as a finding, in the engagement *hardening*. See [windows/README.md](../windows/README.md).

Customers with **Microsoft Defender for Endpoint** can feed the same DefectDojo without installing anything on their devices. See [DEFENDER.md](DEFENDER.md).

## 1. DefectDojo server (one VM)

[server/](server/README.md) has a ready-to-run DefectDojo: pinned version, random secrets, HTTPS with its own CA, backups, and an API user for the agents. Copy the `server` folder to a Linux VM (Ubuntu Server 24.04 LTS or Debian 13; 4 vCPU, 8 GB RAM, 50 GB disk), then:

```bash
cd /opt/defectdojo && sudo ./setup.sh --install-docker --host <dns-name-or-ip>
```

After 5 to 10 minutes it prints the address (`https://<host>:8443`), the admin password, the API key for the agents (user `vulnagent`, global role Maintainer) and the CA certificate the agents must trust. Details, backups and upgrades: [server/README.md](server/README.md).

**Firewall:** the machines need to reach the VM on TCP 8443.

## 2. Each Linux machine

On a machine that already has the code, for example from `git clone` or `bootstrap.sh`:

```bash
cd ~/linux_scanner && git pull && git checkout defectdojo
```

```bash
sudo DD_API_TOKEN=<your-token> sh defectdojo/install.sh --url https://<vm-ip>:8443
```

This does four things:

- Installs vulnagent itself if it is missing.
- Installs `/usr/local/sbin/vulnagent-dojo`.
- Writes `/etc/vulnagent/defectdojo.json` (mode 0600, because it holds the token).
- Hooks the upload into the daily `vulnagent.service` with a systemd drop-in, or into the cron job if systemd is absent.

Test it right away: scan, upload that report, then do a full run the way the daily timer does:

```bash
sudo vulnagent scan
```

```bash
sudo vulnagent-dojo
```

```bash
sudo systemctl start vulnagent.service
```

The machine then appears in DefectDojo under **Products**.

You can also upload by hand without installing anything:

```bash
sudo python3 ~/linux_scanner/defectdojo/vulnagent-dojo.py --url https://<vm-ip>:8443 --token <your-token>
```

Without a config file, the certificate is checked against the machine's trusted CAs. On Debian and Ubuntu, add the server's CA once with `sudo cp defectdojo-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`.

### Many machines at once

```bash
./deploy-fleet.sh hosts.txt my-config.json my-defectdojo.json
```

Make `my-defectdojo.json` from `defectdojo.example.json`, with your URL and token.

## Configuration (`/etc/vulnagent/defectdojo.json`)

| Key | Default | Meaning |
|---|---|---|
| `url`, `api_token` | – | DefectDojo base URL and API v2 key. The token can also come from env `DD_API_TOKEN`. |
| `product_type` | `Linux servers` | Group of products. Created if missing. Use one per site or department, for example. |
| `product_name` | `{host}` | `{host}` is the FQDN and `{short}` the short hostname. |
| `close_old_findings` | `true` | Close findings no longer reported. Skipped automatically when the scan had errors, so an OSV timeout does not close everything. |
| `include_os_managed_libraries` | `true` | Libraries installed by OS packages, tagged `os-managed`. They may be false positives because of distro backports. Set to `false` to leave them out. |
| `include_runtimes` | `true` | Upload EOL or outdated runtime findings. |
| `include_pending_advisories` | `true` | On RPM and SUSE machines, upload pending security errata as findings. |
| `include_certificates` | `true` | Upload the certificate findings. |
| `include_valid_certificates` | `true` | Also upload valid certificates, as Info findings. Set to `false` to see only expired and expiring ones. |
| `minimum_severity` | `Info` | Findings below this severity are not imported. |
| `ca_file` / `verify_tls` | – / `true` | For a DefectDojo server with an internal or self-signed certificate. |

## Useful DefectDojo views

- **Dashboard:** open findings by severity across all machines.
- **Findings → Open findings:** filter by tag (`os`, `library`, `maven`, `os-managed`, `certificate`), severity or product. Tag `certificate` with severity High or Medium lists every certificate that needs renewing, across all Linux and Windows machines.
- **Products → (machine) → Findings:** everything open on one machine. The **Metrics** tab shows the trend.
- **Product type → SLA configuration:** fix deadlines per severity, with breach alerts.
- **Risk acceptance / false positive:** marks a finding so later uploads do not reopen it.
