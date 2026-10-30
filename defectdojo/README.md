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

Reporting is one-way. Patching is still controlled by each machine's `/etc/vulnagent/config.json`.

**Windows servers** report to the same DefectDojo with a PowerShell agent. See [windows/README.md](../windows/README.md).

Customers with **Microsoft Defender for Endpoint** can feed the same DefectDojo without installing anything on their devices. See [DEFENDER.md](DEFENDER.md).

## 1. DefectDojo server (one VM)

**Recommended VM:** Ubuntu Server 24.04 LTS (Debian 12/13 also works), 4 vCPU, 8 GB RAM, 50 GB disk. Give it a fixed IP address or a DNS name that the machines can reach.

Install Docker:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
```

Download and start DefectDojo:

```bash
git clone https://github.com/DefectDojo/django-DefectDojo.git ~/django-DefectDojo
```

```bash
cd ~/django-DefectDojo && sudo docker compose up -d
```

The first start downloads the images and initialises the database, which takes 3–5 minutes. When it finishes, get the generated admin password:

```bash
sudo docker compose logs initializer | grep "Admin password:"
```

Open `http://<vm-ip>:8080` and log in as `admin`. HTTPS is on port `8443` with a self-signed certificate. For production, put a real certificate in front of it (see DefectDojo's `readme-docs/DOCKER.md`).

The containers restart automatically after a reboot.

**API token:** for testing, log in as admin and open the user menu (top right) → **API v2 Key**.

For production, create a dedicated user for the machines instead:

1. Go to **Users → Add user**, name it `vulnagent`, and give it the global role **Maintainer**, which lets it create a product per machine.
2. Log in as that user and copy its **API v2 Key**.

**Firewall:** the machines need to reach the VM on TCP 8080 (or 8443).

## 2. Each Linux machine

On a machine that already has the code, for example from `git clone` or `bootstrap.sh`:

```bash
cd ~/linux_scanner && git pull && git checkout defectdojo
```

```bash
sudo DD_API_TOKEN=<your-token> sh defectdojo/install.sh --url http://<vm-ip>:8080
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
sudo python3 ~/linux_scanner/defectdojo/vulnagent-dojo.py --url http://<vm-ip>:8080 --token <your-token>
```

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
| `minimum_severity` | `Info` | Findings below this severity are not imported. |
| `ca_file` / `verify_tls` | – / `true` | For a DefectDojo server with an internal or self-signed certificate. |

## Useful DefectDojo views

- **Dashboard:** open findings by severity across all machines.
- **Findings → Open findings:** filter by tag (`os`, `library`, `maven`, `os-managed`), severity or product.
- **Products → (machine) → Findings:** everything open on one machine. The **Metrics** tab shows the trend.
- **Product type → SLA configuration:** fix deadlines per severity, with breach alerts.
- **Risk acceptance / false positive:** marks a finding so later uploads do not reopen it.
