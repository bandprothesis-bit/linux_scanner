# vulnagent-local for Windows: reports on each machine, no server

The same scan and hardening check as [vulnagent for Windows](../windows/README.md), without DefectDojo. Nothing is uploaded and there is no API key: each machine keeps its own reports in `C:\vulnagent-local\reports`.

Use it on machines that can't reach DefectDojo, where there is no DefectDojo, or when you only want a report per machine.

| Script | What it does every night (scheduled task as SYSTEM) |
|---|---|
| `vulnagent-local-scan.ps1` | Missing Windows security updates, Windows version support, end-of-life or unpatched .NET, Java, Python, Node.js, PowerShell 7 and SQL Server, applications winget can upgrade, a pending restart, and expired or expiring certificates. |
| `vulnagent-local-harden.ps1` | About 130 settings compared with the Microsoft security baseline (Windows Server 2025 Member Server or Domain Controller, Windows 11), plus about 155 to 185 CIS Level 1 checks on Server 2022 and 2025 (and Server 2019 outside a domain), with the matching CIS Benchmark numbers (Stand-alone benchmarks for servers outside a domain, the Defender Antivirus benchmark) and, on Server 2019 and 2022, the DISA STIG IDs. Where IIS or SQL Server is installed, also 24 IIS and 18 SQL Server checks with their DISA STIG IDs. Changes nothing unless you run it with `-Apply`. |

The checks, severities and hardening options are exactly those of the DefectDojo version: see [what is checked](../windows/README.md), [hardening](../windows/README.md#hardening-microsoft-security-baseline), [CIS and STIG references](../windows/README.md#cis-benchmark-numbers-and-disa-stig-ids) and [IIS and SQL Server checks](../windows/README.md#iis-and-sql-server-checks) there.

Needs only Windows PowerShell 5.1 (built into Windows Server 2016 and later; install WMF 5.1 on 2012 R2). The scan connects only to Windows Update or WSUS, `endoflife.date` and winget's sources. The hardening check makes no network connections, except to the local SQL Server instances.

## Install on one machine

Open **PowerShell as administrator** and run:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
iwr https://raw.githubusercontent.com/bandprothesis-bit/linux_scanner/defectdojo/windows-local/install-local.ps1 -UseBasicParsing -OutFile $env:TEMP\vulnagent-local-install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\vulnagent-local-install.ps1
```

Without internet access, copy the `windows-local` folder to the machine and run, in that folder:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-local.ps1
```

The installer copies the two scripts to `C:\Program Files\vulnagent-local`, keeps the config, reports, logs and hardening backups in `C:\vulnagent-local` (readable only by SYSTEM and Administrators), creates the tasks `vulnagent-local-scan` and `vulnagent-local-hardening` (daily at 03:30 plus up to 45 minutes), and runs the first scan and hardening check, so the reports are there when it finishes.

| Option | Meaning |
|---|---|
| `-At 22:00` | Another time for the nightly run. |
| `-KeepDays 180` | Keep the dated reports this many days (default 90; `0` keeps all). |
| `-ReportReaders 'CONTOSO\Server Admins'` | Users or groups that may open the reports without *Run as administrator* (see below). Saved in the config, so a reinstall keeps them; `-ReportReaders none` removes them again. |
| `-NoHardening` | Only the scan, no hardening check. |
| `-NoRun` | Don't run the first scan now. |
| `-Uninstall` | Remove the tasks and scripts; the reports are kept. Add `-Purge` to delete them too. |

Running the installer again updates the scripts and keeps the config. It also moves the data of an earlier install from `C:\ProgramData\vulnagent-local` to `C:\vulnagent-local`.

## Run without installing

For a one-off check, or to try it first, run the two scripts straight from the extracted folder. Nothing is installed (no scheduled tasks, nothing in `C:\Program Files`). The reports go to the same `C:\vulnagent-local\reports` as after an install; the scripts create the folder the first time, readable only by SYSTEM and Administrators.

In **PowerShell as administrator**, in the `windows-local` folder (only `vulnagent-local-scan.ps1` and `vulnagent-local-harden.ps1` are needed):

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force              # allow scripts in this window only
.\vulnagent-local-scan.ps1 -Html $env:TEMP\scan.html          # 5 to 15 minutes (Windows Update search)
.\vulnagent-local-harden.ps1 -Html $env:TEMP\hardening.html   # only reads, changes nothing
ii $env:TEMP\scan.html; ii $env:TEMP\hardening.html
```

`-Html` writes an extra copy that a normal browser can open, since the reports folder is for administrators only.

| | Installed | Run without installing |
|---|---|---|
| When it runs | Every night, as SYSTEM | Only when you start it, as your administrator account |
| Reports | `C:\vulnagent-local\reports`, with history and changes since the last run | The same. A later install keeps them, so the history carries on. |
| Who can read them | Administrators, plus the `-ReportReaders` group | Administrators only: use the `-Html` copy |
| Removing it | `install-local.ps1 -Uninstall` | Delete the extracted folder, and `C:\vulnagent-local` if you don't need the reports |

- **Everything else works the same** with the script in your folder instead of `C:\Program Files\vulnagent-local`: `-Apply`, `-Undo`, `-List` and `-InstallUpdates` (see [Run by hand](#run-by-hand)). The hardening backups are saved in `C:\vulnagent-local\hardening`, so `-Undo last` works too.
- **Settings:** without a `config.json` the scripts use the defaults (see [Configuration](#configuration-cvulnagent-localconfigjson)). To change a setting, create `C:\vulnagent-local\config.json` with only the settings you want to change, or give your own file with `-ConfigPath`.
- **From a file share or USB stick:** the scripts don't have to be copied to the machine. Run them by their full path, for example `& \\fileserver\tools\windows-local\vulnagent-local-scan.ps1`. The reports are still written on the machine itself.
- **Before deleting `C:\vulnagent-local`:** it also holds the hardening backups. If you applied settings and may want to reverse them, run `-Undo` first.

## Install on many machines

From an admin workstation, in the `windows-local` folder, as a user who is administrator on the targets (WinRM must be on; it is by default on domain-joined servers):

```powershell
.\deploy-fleet-local.ps1 -ComputerName (Get-Content .\servers.txt)
.\deploy-fleet-local.ps1 -ComputerName srv01, srv02 -ReportReaders 'CONTOSO\Server Admins' -Credential (Get-Credential)
```

It installs on each machine and starts the first scan in the background. The reports stay on each machine.

## The reports

Everything is in `C:\vulnagent-local\reports`:

| File | Content |
|---|---|
| `index.html` | **Start here.** The latest scan and hardening result, and a table of every earlier run with its counts by severity and what was new or fixed. |
| `scan.html`, `hardening.html` | The latest reports. Click a finding or check for details; the severity cards filter the list. |
| `scan.json`, `hardening.json` | All data of the latest run, for scripts. |
| `scan-findings.json`, `hardening-findings.json` | The findings only, in DefectDojo's *Generic Findings Import* format, so you can still import a report into DefectDojo by hand. |
| `history\<date>-<time>-scan.html` (and `-hardening`) | A copy of each run's report, deleted after `keep_reports_days`. |

**What changed since the last run:** every report starts with a box that lists the new findings and the fixed ones (for hardening: checks that fail now but passed before, and checks that pass now). When part of a run failed, for example the Windows Update search, findings it couldn't check are listed as *gone*, not *fixed*. The ERROR lines in the report say what failed.

Logs: `C:\vulnagent-local\scan.log` and `hardening.log`.

### Opening the reports

The reports list the machine's weaknesses, so the folder is readable only by SYSTEM and Administrators. Because of UAC, a browser that wasn't started as administrator can't open it. Three ways around that:

- **Give a group read access**, once: `install-local.ps1 -ReportReaders 'CONTOSO\Server Admins'`. Members can then open `C:\vulnagent-local\reports\index.html` directly (type or paste the full path; browsing through `C:\vulnagent-local` itself is still blocked).
- **Copy a report** from an administrator PowerShell, then open the copy:

  ```powershell
  Copy-Item C:\vulnagent-local\reports\scan.html, C:\vulnagent-local\reports\hardening.html $env:TEMP; ii $env:TEMP\scan.html
  ```

- **Run a check yourself** with `-Html`, which writes an extra copy wherever you want:

  ```powershell
  & "C:\Program Files\vulnagent-local\vulnagent-local-scan.ps1" -Html $env:TEMP\scan.html
  ```

## Run by hand

In an administrator PowerShell:

```powershell
Start-ScheduledTask vulnagent-local-scan           # scan now, as SYSTEM, like at night
Start-ScheduledTask vulnagent-local-hardening      # hardening check now

$s = "C:\Program Files\vulnagent-local"
& "$s\vulnagent-local-scan.ps1" -InstallUpdates security    # install missing security updates, then scan (never restarts)
& "$s\vulnagent-local-harden.ps1" -List                     # the checks that apply to this machine
& "$s\vulnagent-local-harden.ps1" -Apply safe -DryRun       # what -Apply safe would change
& "$s\vulnagent-local-harden.ps1" -Apply safe               # change the "safe" settings, with a backup
& "$s\vulnagent-local-harden.ps1" -Apply all -Only SMB-03, LSA-03   # selected "review" checks, after testing
& "$s\vulnagent-local-harden.ps1" -Apply cis -Only 'CIS firewall' # selected CIS Level 1 checks, after testing
& "$s\vulnagent-local-harden.ps1" -Undo last                # put back what the last -Apply changed
```

Before each change, the old value is saved in `C:\vulnagent-local\hardening\backup-<date>-<time>.json`. In a domain, a Group Policy that sets the same setting wins over local changes: use the Microsoft baseline GPOs for the fleet. More in [Applying the settings](../windows/README.md#applying-the-settings).

Exit codes, for both scripts: `0` done, `2` part of the run failed (the report may be incomplete), `3` failed (no report written).

## Configuration (`C:\vulnagent-local\config.json`)

| Key | Default | Meaning |
|---|---|---|
| `report_readers` | `[]` | Users or groups that may read `reports`. Set it with `install-local.ps1 -ReportReaders`, which also sets the folder permissions. |
| `keep_reports_days` | `90` | Days to keep the dated reports in `reports\history`. `0` keeps all. |
| `windows_update_source` | `default` | `default` (WSUS if configured, otherwise Windows Update), `windows_update` or `microsoft_update`. |
| `include_non_security_updates` | `false` | Also list non-security updates, as Info. |
| `include_runtimes` | `true` | The end-of-life and patch checks for .NET, Java, Python, Node.js, PowerShell and SQL Server. Set to `false` on machines without internet access. |
| `include_winget` | `true` | Outdated applications, where winget is installed. |
| `eol_warning_days` | `90` | Warn this many days before Windows support ends. |
| `include_certificates` | `true` | The certificate check. |
| `include_valid_certificates` | `true` | Also list valid certificates, as Info. |
| `certificate_stores` | `["My", "WebHosting", "Remote Desktop"]` | Stores under `Cert:\LocalMachine` to check. |
| `cert_warning_days` | `30` | Certificates expiring within this many days are Medium. |
| `install_updates` | `none` | `security` or `all`: install updates before each nightly scan. |
| `reboot_after_updates` | `false` | Restart 10 minutes after the scan when installed updates need it. |
| `winget_upgrade` | `false` | Also run `winget upgrade --all` at night. |
| `hardening_exclude` | `[]` | Accepted deviations: check IDs, patterns such as `"DEF-*"`, or areas such as `"Firewall"`. Shown as *Exception*, never changed by `-Apply`. |
| `hardening_include_passed` | `false` | Also list passed checks in `hardening-findings.json`, as Info. |
| `cis_checks` | `true` | Also check the CIS Level 1 settings outside the Microsoft baseline (`CIS-001` and up, see [CIS Level 1 checks](../windows/README.md#cis-level-1-checks)). |
| `iis_checks` | `true` | Check the IIS settings (`IIS-01` and up), where IIS is installed. |
| `sql_checks` | `true` | Check the SQL Server settings (`SQL-01` and up), where SQL Server is installed. The checks connect to the local instances as SYSTEM. |

## Troubleshooting

The Windows Update, end-of-life, winget and hardening messages are the same as in the [DefectDojo version](../windows/README.md#troubleshooting). Specific to this version:

| Problem | Cause and fix |
|---|---|
| The browser says the file can't be opened, or access denied | The reports folder is for administrators only. See [Opening the reports](#opening-the-reports). |
| `running scripts is disabled on this system`, or `is not digitally signed` | Run `Set-ExecutionPolicy -Scope Process Bypass -Force` in that window first. If a Group Policy sets the execution policy, this is ignored: sign the scripts or ask for an exception. |
| `ERROR report index` in the log | The scan and the hardening check wrote `index.html` at the same moment. The next run fixes it; the reports themselves are complete. |
| `index.html` shows fewer runs than expected | Older reports were deleted after `keep_reports_days`. |
