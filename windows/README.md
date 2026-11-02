# vulnagent for Windows → DefectDojo

A PowerShell agent that reports Windows servers (and PCs) to the same DefectDojo as the Linux agents. It needs nothing beyond what Windows already has: Windows PowerShell 5.1 is built into Windows Server 2016 and later. On Windows Server 2012 R2, install WMF 5.1 first.

Every night, as a scheduled task running as SYSTEM, it does this:

| Check | Source | DefectDojo finding |
|---|---|---|
| **Missing security updates** | Windows Update, or the WSUS server the machine already uses | One finding per update, with the KB, CVEs and Microsoft's severity: Critical → Critical, Important → High, Moderate → Medium, unrated → High |
| **Windows version support** | endoflife.date, by build and edition | High when out of support. Low when support ends within 90 days. |
| **Runtimes and SQL Server**: .NET, Java (Oracle, Temurin), Python, Node.js, PowerShell 7, SQL Server | Installed programs, compared with endoflife.date | High when end-of-life. Medium when patch releases (or SQL Server CUs) are missing. |
| **Outdated applications** such as Chrome, 7-Zip and Notepad++ | `winget upgrade`, only where winget is installed | Low, with the version to update to |
| **Restart pending** after updates | Registry | Low |
| **Certificates** in the computer's Personal, Web Hosting and Remote Desktop stores | Certificate store, plus the IIS/HTTP.sys bindings and the Remote Desktop certificate setting to show where each one is used | High when expired or expiring within 7 days. Medium within 30 days. Every other certificate is listed as Info, as an inventory. |

Each run also writes a readable **HTML report** of everything it found: see [HTML report](#html-report).

A second script, **vulnagent-harden.ps1**, compares each machine with the **Microsoft security baseline** and reports every deviation to DefectDojo. It can also apply the recommended settings, with a backup and undo. See [Hardening](#hardening-microsoft-security-baseline).

Each machine becomes its own DefectDojo product under the product type **Windows servers**. Fixed findings close automatically, new ones are added, and notes and risk acceptances are kept, the same as on Linux.

Defender antivirus signature updates are ignored. Non-security updates are left out unless you turn on `include_non_security_updates`.

## Install on one server

You need the DefectDojo address and an API v2 key, the same ones the Linux machines use.

Open **PowerShell as administrator** on the server and run these three lines, with your key and address:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$env:DD_API_TOKEN = '<your-api-key>'
iwr https://raw.githubusercontent.com/bandprothesis-bit/linux_scanner/defectdojo/windows/install.ps1 -UseBasicParsing -OutFile $env:TEMP\vulnagent-install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\vulnagent-install.ps1 -Url http://<dojo-server>:8080
```

If the server has no internet access, copy the `windows` folder to it (for example over a file share), then run this in that folder:

```powershell
$env:DD_API_TOKEN = '<your-api-key>'; powershell -ExecutionPolicy Bypass -File .\install.ps1 -Url http://<dojo-server>:8080
```

The installer does four things:

1. Copies the agent and the hardening script to `C:\Program Files\vulnagent\`.
2. Writes `C:\ProgramData\vulnagent\defectdojo.json`. Only SYSTEM and Administrators can read that folder, because the file holds the key.
3. Creates the scheduled task **vulnagent**, which runs daily at 03:30 plus up to 45 minutes of random delay, and the task **vulnagent-hardening** at the same time. The hardening task only checks and reports; it changes nothing.
4. Runs the first scan and the first hardening check. The scan takes 2–10 minutes, mostly the Windows Update search. Then the server appears in DefectDojo under **Products**.

Installer options:

| Option | Meaning |
|---|---|
| `-ProductType "Site B servers"` | Group the machine under another product type. It is created if missing. |
| `-ProductName "{short}"` | Name the product by computer name instead of the full DNS name. |
| `-At 22:00` | Change the time of the daily run. |
| `-Insecure` | Accept a self-signed HTTPS certificate on DefectDojo. Better: import your internal CA into the server's *Trusted Root Certification Authorities*. |
| `-NoRun` | Don't run the first scan now. |
| `-NoHardening` | Don't install the hardening script and task (removes them if they were installed before). |
| `-Uninstall` (`-Purge`) | Remove the task and agent. Add `-Purge` to also delete the config and reports. |

Running the installer again updates the agent and keeps the config.

## Install on many servers

From an admin workstation, run this in the `windows` folder as a user who is administrator on the servers. WinRM must be on, which it is by default on domain-joined servers.

```powershell
.\deploy-fleet.ps1 -ComputerName (Get-Content .\servers.txt) -Url http://<dojo-server>:8080
```

`servers.txt` holds one server name per line. The script asks for the API key once, installs on each server, starts each first scan in the background, and prints a table of the results. Add `-Credential (Get-Credential)` to connect as a different account.

With **Group Policy** instead: put the `windows` folder on a share that the computer accounts can read, and add a computer startup script that runs `install.ps1 -Url ... -NoRun`, with the key in `$env:DD_API_TOKEN`. Keep in mind that the key is then readable from the share.

## Daily operation

| Task | Command (PowerShell as administrator) |
|---|---|
| Run a scan and upload now | `Start-ScheduledTask vulnagent` |
| Watch the result | `Get-Content C:\ProgramData\vulnagent\vulnagent.log -Tail 30` |
| Last run result | `Get-ScheduledTaskInfo vulnagent` (LastTaskResult 0 = OK, 2 = uploaded but part of the scan failed, 3 = failed) |
| Scan and upload, in this window | `powershell -ExecutionPolicy Bypass -File "C:\Program Files\vulnagent\vulnagent-win.ps1"` |
| Install missing security updates now, then scan and upload | `powershell -ExecutionPolicy Bypass -File "C:\Program Files\vulnagent\vulnagent-win.ps1" -InstallUpdates security` |
| Scan and upload, skip the patching set in the config | `... vulnagent-win.ps1 -NoPatch` |
| Scan without uploading | `... vulnagent-win.ps1 -DryRun -Output C:\Temp\findings.json` |
| Scan without uploading, and open the HTML report | `... vulnagent-win.ps1 -DryRun -Html $env:TEMP\vulnagent.html; start $env:TEMP\vulnagent.html` |
| HTML report of the last nightly run | `Copy-Item C:\ProgramData\vulnagent\reports\latest.html $env:TEMP; start $env:TEMP\latest.html` |
| Full local report | `C:\ProgramData\vulnagent\reports\latest.json` (includes the list of installed programs) |
| Hardening check and upload now | `Start-ScheduledTask vulnagent-hardening` |
| Hardening report without uploading | `... vulnagent-harden.ps1 -DryRun -Html $env:TEMP\hardening.html; start $env:TEMP\hardening.html` |
| Hardening: apply the safe settings | `... vulnagent-harden.ps1 -Apply safe` (see [Hardening](#hardening-microsoft-security-baseline)) |
| Hardening log | `Get-Content C:\ProgramData\vulnagent\hardening.log -Tail 30` |

## HTML report

Every run, including `-DryRun`, writes `C:\ProgramData\vulnagent\reports\latest.html`. It is one file with no external links, so it opens on servers without internet access, and it can be attached to an email or a ticket.

It contains:

- The machine, Windows version, last restart and when the scan ran, plus warnings when part of the scan failed or a restart is pending.
- Counts by severity, missing updates, certificates and Windows support status. Click a severity count to show only those findings.
- All findings, sorted by severity, with a search box (KB, CVE, name, thumbprint...). Click a finding to see its details: KB, CVEs, path, store, what uses it.
- Tables of the missing Windows updates, runtimes and SQL Server, applications with updates, and certificates.
- The updates installed in this run, when patching is on.

Printing it (or *Print → Save as PDF*) expands every finding.

The `C:\ProgramData\vulnagent` folder is readable only by administrators, so a browser can't open the file there directly. Copy it out first (see [Daily operation](#daily-operation)), or write it somewhere else with `-Html <path>` when you run the scan by hand.

## Hardening (Microsoft security baseline)

`vulnagent-harden.ps1` checks the machine against the baselines of Microsoft's [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319):

| Machine | Compared with |
|---|---|
| Server (member or standalone) | Windows Server 2025 v2602, *Member Server* |
| Domain controller | Windows Server 2025 v2602, *Domain Controller* |
| Workstation | Windows 11 v25H2 |

The values are the newest baseline's, also on Windows Server 2016, 2019 and 2022. Settings that need a newer Windows than the machine has are skipped. On top of the baseline it checks Microsoft's guidance on TLS 1.0/1.1, PowerShell 2.0 and the Print Spooler.

About 120 to 150 checks apply per machine:

| Area | Examples |
|---|---|
| SMB | SMB 1.0 off, signing required, no insecure guest logons, anonymous access blocked |
| Network | LLMNR and NetBIOS name resolution off, hardened SYSVOL/NETLOGON paths, LDAP signing |
| Credentials | WDigest off, NTLMv2 only, LSA protection, Credential Guard, anonymous enumeration blocked |
| Accounts | UAC, password length and lockout, Guest disabled, no stored auto-logon password, LAPS |
| User rights | Debug, act as OS, backup/restore and similar rights; local admins denied network and RDP logon |
| Audit | 23–30 advanced audit subcategories, command line in 4688 events, PowerShell script block logging, event log sizes |
| Defender | Real-time, behaviour and cloud protection, PUA blocking, attack surface reduction rules, network protection |
| Firewall | All three profiles on, inbound blocked by default, logging |
| Remote access | RDP with NLA and high encryption, WinRM without Basic auth or unencrypted traffic |
| System | AutoRun off, AlwaysInstallElevated off, Point and Print restricted, Print Spooler on DCs, PowerShell 2.0 removed, Secure Boot, BitLocker |
| TLS | SSL 3.0, TLS 1.0 and TLS 1.1 off; strong crypto for .NET |

List the checks that apply to a machine with `vulnagent-harden.ps1 -List`.

### In DefectDojo

Each failed check becomes one finding in the machine's product, in the engagement **hardening**, with the check's severity. The description says why it matters, the expected value and the baseline setting. The mitigation shows the current value and how to fix it. Fixed checks close at the next run.

Filter by the tag `hardening` to see all of them across the fleet. The tags `fix-safe`, `fix-review` and `fix-manual` say how each one can be fixed.

### The HTML report

Every run writes `C:\ProgramData\vulnagent\reports\hardening.html`, and `-Html <path>` writes a copy where a browser can open it. It shows the compliance score and the failed checks by severity. Click a check to see the expected and current value of each setting. Passed checks are hidden until you tick *show passed checks*.

### Applying the settings

Each check is marked:

| Mark | Meaning | Applied by |
|---|---|---|
| **safe** | Doesn't break a normal, current environment | `-Apply safe` |
| **review** | Can break old clients, devices or applications. The finding says what. Test it on one machine first. | `-Apply all` |
| **manual** | Needs hardware, Active Directory or a decision: Credential Guard, Secure Boot, BitLocker, LAPS, the auto-logon password | never automatic |

```powershell
# see what would change, without changing anything
powershell -ExecutionPolicy Bypass -File "C:\Program Files\vulnagent\vulnagent-harden.ps1" -Apply safe -DryRun

# apply the safe settings, then check again and upload
powershell -ExecutionPolicy Bypass -File "C:\Program Files\vulnagent\vulnagent-harden.ps1" -Apply safe

# apply selected "review" checks after testing them: by ID, ID pattern or area
... vulnagent-harden.ps1 -Apply all -Only SMB-03, SMB-04, LSA-03
... vulnagent-harden.ps1 -Apply all -Only Firewall -Exclude FW-01

# put back what the last -Apply changed (repeat to go back further)
... vulnagent-harden.ps1 -Undo last
```

Before each change the old value is saved in `C:\ProgramData\vulnagent\hardening\backup-<date>-<time>.json`, and `-Undo` puts it back. `-Undo <file>` undoes a specific run. One limitation: password and lockout policy values that did not exist before (for example the lockout duration while lockout was off) cannot be removed again, so they keep the new value.

Some settings need a restart: the output then says `RESTART NEEDED`. The script never restarts the machine.

**In a domain, use Group Policy for the fleet.** The script changes the local settings. A Group Policy that sets the same setting overwrites the local value at the next refresh, so the check fails again. For many machines, import the Microsoft baseline GPOs from the toolkit (`Baseline-ADImport.ps1`) and link them, and use `vulnagent-harden.ps1` to see where they are missing or overridden. Use `-Apply` for standalone servers and for single exceptions.

### Accepted deviations

When a check is deliberately not followed on a machine, for example because another antivirus replaces Defender, list it in that machine's config:

```json
"hardening_exclude": ["DEF-*", "SMB-03"]
```

These checks then show as *Exception* in the report. They are not sent to DefectDojo, and `-Apply` doesn't change them. For exceptions on many machines, use DefectDojo's risk acceptance on the findings instead.

## Configuration (`C:\ProgramData\vulnagent\defectdojo.json`)

| Key | Default | Meaning |
|---|---|---|
| `url`, `api_token` | – | DefectDojo address and API v2 key. |
| `product_type` | `Windows servers` | DefectDojo product type. Created if missing. |
| `product_name` | `{host}` | `{host}` is the full DNS name, `{short}` the computer name. |
| `windows_update_source` | `default` | `default` uses the machine's own setting: WSUS if configured, otherwise Windows Update. `windows_update` asks Microsoft directly, bypassing WSUS. `microsoft_update` also covers SQL Server and Office, but only on machines where "updates for other Microsoft products" is enabled. |
| `include_non_security_updates` | `false` | Also report non-security updates, as Info. |
| `include_runtimes` | `true` | The end-of-life and patch checks for .NET, Java, Python, Node.js, PowerShell and SQL Server. |
| `include_winget` | `true` | Outdated applications, where winget is installed. |
| `eol_warning_days` | `90` | Warn this many days before Windows support ends. |
| `include_certificates` | `true` | The certificate check. |
| `include_valid_certificates` | `true` | Also list valid certificates, as Info. Set to `false` to see only expired and expiring ones. |
| `certificate_stores` | `["My", "WebHosting", "Remote Desktop"]` | Stores under `Cert:\LocalMachine` to check. Add `"Root"` and `"CA"` to include trusted root and intermediate CAs. Those also contain old Microsoft roots that Windows keeps on purpose, which then show as expired. |
| `cert_warning_days` | `30` | Report certificates expiring within this many days as Medium. |
| `install_updates` | `none` | `security` or `all`: install updates before each scan (see below). |
| `reboot_after_updates` | `false` | Restart 10 minutes after the scan when installed updates need it. |
| `winget_upgrade` | `false` | Also run `winget upgrade --all`. This accepts the apps' licence terms. |
| `close_old_findings` | `true` | Close findings that are no longer found. Skipped automatically when part of the scan failed. |
| `minimum_severity` | `Info` | Don't import findings below this. |
| `verify_tls` | `true` | `false` accepts any certificate (same as `-Insecure`). |
| `hardening_engagement`, `hardening_test_title` | `hardening` | Where the hardening findings go in each product. |
| `hardening_exclude` | `[]` | Hardening checks that are accepted deviations on this machine: IDs, patterns such as `"DEF-*"`, or areas such as `"Firewall"`. |
| `hardening_include_passed` | `false` | Also send passed hardening checks, as Info, for a complete compliance record in DefectDojo. |

## Patching

### Now, by hand

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Program Files\vulnagent\vulnagent-win.ps1" -InstallUpdates security
```

This installs the missing security updates (`-InstallUpdates all` installs every update), then scans and uploads, so DefectDojo shows what is still missing. **It never restarts the server**, even if `reboot_after_updates` is on in the config. When a restart is needed, the output says `RESTART NEEDED`, and a "Restart pending" finding stays open until you restart.

Run it in a local administrator PowerShell, or through Remote Desktop. Windows doesn't allow installing updates from a remote PowerShell session (`Invoke-Command`, `Enter-PSSession`); that fails with `0x80070005`.

### Every night

Off by default. To turn it on for a server, set `"install_updates": "security"` in its config (and optionally `"reboot_after_updates": true`). The nightly run then installs the missing security updates, scans, and reports what is still missing.

It skips three kinds of update, which you install by hand:

- Feature upgrades, such as a new Windows version.
- Updates with a licence agreement.
- Updates that need user input.

On servers that WSUS or another patch tool already manages, leave it at `none` and use the DefectDojo findings to see what that tool missed.

## Troubleshooting

| Message in the log | Cause and fix |
|---|---|
| `Windows Update: 0x8024402C` / `0x80072EE2` / `0x80072EFD` | The server can't reach its update server. Check DNS, the proxy, or the WSUS address in Group Policy. |
| `Windows Update: 0x80244019` | The WSUS address is wrong. |
| `Windows Update: 0x80248014` | `microsoft_update` is set, but Microsoft Update isn't enabled on this machine. Use `default`. |
| `cannot download end-of-life data` | No internet access to `endoflife.date`. The last download is reused for 30 days. For servers that are always offline, set `include_runtimes` to `false`. |
| `DefectDojo returned HTTP 401` | Wrong API key in the config. |
| `cannot reach DefectDojo` | Firewall: the server needs TCP 8080 (or 8443) to the DefectDojo server. |
| `winget upgrade failed` | winget can't open its source as SYSTEM, which is common on Windows Server 2019. Set `include_winget` to `false`. |
| `hardening.log`: `X still fails after the change (a Group Policy may set it back)` | A domain GPO sets this setting to another value. Change it in the GPO, or add the check to `hardening_exclude`. |
| `hardening.log`: `the audit policy could not be read` | `auditpol.exe` failed. Run the script as administrator or SYSTEM. |
| Defender checks missing from the hardening report | Defender is not the active antivirus (passive mode, or another antivirus). Check `DEF-01`. |

**WSUS note:** with WSUS, "missing" means approved in WSUS and not yet installed. Updates that nobody has approved in WSUS don't appear. To compare against everything Microsoft has released, set `windows_update_source` to `windows_update`. The server then needs internet access to Windows Update.
