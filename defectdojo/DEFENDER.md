# Microsoft Defender → DefectDojo

`defender-dojo` imports the vulnerabilities that **Microsoft Defender for Endpoint** finds on a customer's devices (Windows, macOS and Linux) into the same DefectDojo as the Linux agents. Nothing is installed on the customer's devices.

Every night it does this for each customer:

1. Signs in to the customer's Microsoft tenant with a read-only app registration.
2. Reads the device list and the vulnerabilities per device from the Defender API.
3. Uploads each device as its own DefectDojo product, `<device> (<customer>)`, under a product type named after the customer:
   - **New findings** are added.
   - **Fixed findings** are closed.
   - **History**, notes and risk acceptances are kept.

Each finding has:

- The CVE and Microsoft's severity.
- The affected product and version.
- The fix: the **KB update** to install, or the product to update.
- The tags `defender` and the device's OS, for example `windows11`.

Devices that Defender hasn't seen for 30 days are skipped. If the Defender export fails (sign-in, permissions, network), nothing is uploaded for that customer, so DefectDojo never closes findings because data was missing.

## What the customer needs

- **A licence that includes Defender Vulnerability Management**, one of:
  - Defender for Endpoint Plan 2 (included in Microsoft 365 E5)
  - Defender for Business
  - the Defender Vulnerability Management add-on

  Plan 1 alone is not enough.
- **An app registration with read-only API access.** Their admin creates it once (about 5 minutes):

1. In the **Microsoft Entra admin center**, go to **App registrations → New registration**. Name it `DefectDojo vulnerability export`, choose *Accounts in this organizational directory only*, and select **Register**.
2. Go to **API permissions → Add a permission → APIs my organization uses**, search for **WindowsDefenderATP**, and choose **Application permissions**. Tick these two, then select **Add permissions**:
   - `Machine.Read.All`
   - `Vulnerability.Read.All`
3. Select **Grant admin consent for <organisation>**. Both permissions must show a green "Granted" status.
4. Go to **Certificates & secrets → New client secret**. Pick an expiry, for example 12 or 24 months, and copy the secret **Value**. It is shown only once.
5. From **Overview**, copy the **Directory (tenant) ID** and the **Application (client) ID**.

The customer then sends you the tenant ID, client ID and secret value. Use a password manager share or another secure channel, not plain email.

These permissions only read device and vulnerability data. The app cannot change anything in Defender or on the devices.

> **Many customers?** Instead of one app per customer, you can register one *multi-tenant* app in your own tenant, and have each customer's admin consent to it. Then each customer entry needs only its `tenant_id`, and the shared `client_id` and `client_secret` go at the top of the config. See Microsoft's guide "Partner access through Microsoft Defender for Endpoint APIs".

## Install on the DefectDojo server (once)

The connector runs on the DefectDojo server itself, or on any Linux machine that can reach both DefectDojo and the internet (`login.microsoftonline.com` and `api.securitycenter.microsoft.com`, HTTPS).

```bash
git clone -b defectdojo https://github.com/bandprothesis-bit/linux_scanner.git ~/linux_scanner
```

```bash
sudo sh ~/linux_scanner/defectdojo/install-defender.sh
```

This does three things:

- Installs `/usr/local/sbin/defender-dojo`.
- Creates `/etc/vulnagent/defender.json` (mode 0600, because it holds secrets).
- Enables a daily timer at 05:15, after the Linux agents' uploads.

Edit the config:

```bash
sudo nano /etc/vulnagent/defender.json
```

- `defectdojo.url`: `http://127.0.0.1:8080` when the connector runs on the DefectDojo server itself.
- `defectdojo.api_token`: the DefectDojo API v2 key of a user with the global role Maintainer.

## Add a customer

Add an entry to `customers` in `/etc/vulnagent/defender.json`:

```json
{
  "name": "Contoso",
  "tenant_id": "<Directory (tenant) ID>",
  "client_id": "<Application (client) ID>",
  "client_secret": "<secret value>",
  "product_type": "Contoso"
}
```

Check the sign-in and permissions. This uploads nothing:

```bash
sudo /usr/local/sbin/defender-dojo --test --customer Contoso
```

It should print the device and vulnerability counts:

```
== Contoso (tenant 1a2b...)
   212 devices (187 active in the last 30 days), 9431 vulnerability rows
```

Import now instead of waiting for the night:

```bash
sudo /usr/local/sbin/defender-dojo --customer Contoso
```

In DefectDojo, go to **Product Types → Contoso**. There is one product per device, each with its findings.

To pause a customer, set `"enabled": false`. To preview what would be uploaded, run `--dry-run -o /tmp/preview`; it writes one JSON file per device.

## Daily operation

| Task | Command |
|---|---|
| Next scheduled run | `systemctl list-timers defender-dojo.timer --no-pager` |
| Run all customers now | `sudo systemctl start defender-dojo` |
| Log of the last run | `sudo journalctl -u defender-dojo -n 60 --no-pager` |
| Check one customer's sign-in | `sudo /usr/local/sbin/defender-dojo --test --customer <name>` |

**Client secrets expire.** Put a reminder in your calendar a few weeks before each customer's secret expires. The customer creates a new secret, and you replace `client_secret` in the config.

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `AADSTS7000215: Invalid client secret` | The secret value is wrong. Copy the secret **Value**, not the Secret ID. |
| `AADSTS7000222: ... client secret keys ... are expired` | The secret expired. The customer creates a new one. |
| `AADSTS700016: Application ... was not found in the directory` | Wrong tenant ID or client ID. With a multi-tenant app, it means admin consent was not given in that tenant. |
| `AADSTS90002: Tenant ... not found` | Wrong tenant ID. |
| `access denied` / HTTP 403 | One of these: the two **Application** permissions are missing, admin consent was not granted, or the licence lacks vulnerability management. |
| `0 devices` | No devices are onboarded to Defender, or none were seen in the last 30 days (`skip_inactive_days`). |
| `DefectDojo HTTP 401` | Wrong DefectDojo API token in `defectdojo.api_token`. |
| `cannot reach login.microsoftonline.com` | The server has no internet access or needs a proxy. Add `Environment=HTTPS_PROXY=http://proxy:port` with `sudo systemctl edit defender-dojo`. |

## Notes

- **Product names** look like `dc01.contoso.local (Contoso)`. DefectDojo needs product names to be unique across all customers, so keep `{customer}` in `product_name`. Two devices with the same name in one tenant get the Defender device ID added.
- **Retired devices** stop being uploaded after 30 days without contact. Their products stay in DefectDojo until you delete them.
- **API limits:** Defender allows 100 API calls per minute. A customer needs only a few calls per night, even with thousands of devices.
