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

1. Copies the agent to `C:\Program Files\vulnagent\vulnagent-win.ps1`.
2. Writes `C:\ProgramData\vulnagent\defectdojo.json`. Only SYSTEM and Administrators can read that folder, because the file holds the key.
3. Creates the scheduled task **vulnagent**, which runs daily at 03:30 plus up to 45 minutes of random delay.
4. Runs the first scan. It takes 2–10 minutes, mostly the Windows Update search. Then the server appears in DefectDojo under **Products**.

Installer options:

| Option | Meaning |
|---|---|
| `-ProductType "Site B servers"` | Group the machine under another product type. It is created if missing. |
| `-ProductName "{short}"` | Name the product by computer name instead of the full DNS name. |
| `-At 22:00` | Change the time of the daily run. |
| `-Insecure` | Accept a self-signed HTTPS certificate on DefectDojo. Better: import your internal CA into the server's *Trusted Root Certification Authorities*. |
| `-NoRun` | Don't run the first scan now. |
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
| Full local report | `C:\ProgramData\vulnagent\reports\latest.json` (includes the list of installed programs) |

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
| `install_updates` | `none` | `security` or `all`: install updates before each scan (see below). |
| `reboot_after_updates` | `false` | Restart 10 minutes after the scan when installed updates need it. |
| `winget_upgrade` | `false` | Also run `winget upgrade --all`. This accepts the apps' licence terms. |
| `close_old_findings` | `true` | Close findings that are no longer found. Skipped automatically when part of the scan failed. |
| `minimum_severity` | `Info` | Don't import findings below this. |
| `verify_tls` | `true` | `false` accepts any certificate (same as `-Insecure`). |

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

**WSUS note:** with WSUS, "missing" means approved in WSUS and not yet installed. Updates that nobody has approved in WSUS don't appear. To compare against everything Microsoft has released, set `windows_update_source` to `windows_update`. The server then needs internet access to Windows Update.
