<#
.SYNOPSIS
    Install vulnagent-local for Windows: scans and hardening checks whose
    reports stay on the machine. No DefectDojo or other server is needed.

.DESCRIPTION
    Run from an elevated PowerShell on each Windows machine. It:
      * copies vulnagent-local-scan.ps1 and vulnagent-local-harden.ps1 to
        C:\Program Files\vulnagent-local (from this folder, or downloads them
        from GitHub when run on its own),
      * creates C:\vulnagent-local, readable only by SYSTEM and Administrators
        (the reports list the machine's weaknesses), and writes config.json
        there. Data from an earlier install in C:\ProgramData\vulnagent-local
        is moved there,
      * creates the "vulnagent-local-scan" scheduled task: daily as SYSTEM, at
        -At plus up to 45 minutes of random delay,
      * creates the "vulnagent-local-hardening" task at the same time: it
        checks the machine against the Microsoft security baseline without
        changing anything (leave it out with -NoHardening),
      * runs the first scan and hardening check, so the reports exist right
        away.

    Reports: C:\vulnagent-local\reports\index.html links to the
    latest scan and hardening reports and to every earlier run.

    Running it again updates the scripts and keeps the existing config.

.EXAMPLE
    .\install-local.ps1

.EXAMPLE
    .\install-local.ps1 -ReportReaders 'CONTOSO\Server Admins' -KeepDays 180

.EXAMPLE
    .\install-local.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$At = '03:30',
    [int]$KeepDays = -1,
    [string[]]$ReportReaders,
    [switch]$NoRun,
    [switch]$NoHardening,
    [switch]$Uninstall,
    [switch]$Purge,
    [string]$Source = 'https://raw.githubusercontent.com/bandprothesis-bit/linux_scanner/defectdojo/windows-local/vulnagent-local-scan.ps1'
)

$ErrorActionPreference = 'Stop'
$TaskName = 'vulnagent-local-scan'
$HardenTask = 'vulnagent-local-hardening'
$BinDir = Join-Path $env:ProgramFiles 'vulnagent-local'
$DataDir = Join-Path "$env:SystemDrive\" 'vulnagent-local'   # C:\vulnagent-local
$OldDataDir = Join-Path $env:ProgramData 'vulnagent-local'   # used by the first version
$ReportDir = Join-Path $DataDir 'reports'
$Agent = Join-Path $BinDir 'vulnagent-local-scan.ps1'
$Harden = Join-Path $BinDir 'vulnagent-local-harden.ps1'
$Conf = Join-Path $DataDir 'config.json'
$PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (right-click > Run as administrator).'
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $HardenTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $BinDir -Recurse -Force -ErrorAction SilentlyContinue
    if ($Purge) {
        Remove-Item $DataDir, $OldDataDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host 'vulnagent-local removed, including its config, reports and hardening backups.'
    } else {
        Write-Host "vulnagent-local removed ($DataDir kept, with the reports and hardening backups; add -Purge to delete it)."
    }
    return
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Warning 'PowerShell 5.1 is recommended: install WMF 5.1 on Windows Server 2012 R2.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072  # TLS 1.2

# 1. scripts, from this folder or from next to -Source
function Install-Script([string]$Name, [string]$Target, [string]$Marker) {
    $local = if ($PSScriptRoot) { Join-Path $PSScriptRoot $Name } else { '' }
    $src = $Source -replace 'vulnagent-local-scan\.ps1$', $Name
    if ($local -and (Test-Path $local)) {
        Copy-Item $local $Target -Force
    } elseif ($src -match '^https?://') {
        Write-Host "downloading $src"
        Invoke-WebRequest -Uri $src -OutFile $Target -UseBasicParsing
    } else {
        Copy-Item $src $Target -Force
    }
    Unblock-File $Target -ErrorAction SilentlyContinue
    if (-not (Select-String -Path $Target -Pattern $Marker -SimpleMatch -Quiet)) {
        Remove-Item $Target -Force
        throw "$src is not the $Name script"
    }
    Write-Host "installed $Target"
}
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Install-Script 'vulnagent-local-scan.ps1' $Agent 'vulnagent-local scan for Windows'
if (-not $NoHardening) { Install-Script 'vulnagent-local-harden.ps1' $Harden 'vulnagent-local hardening for Windows' }

# 2. config, then the data folder C:\vulnagent-local
if ((Test-Path $OldDataDir) -and -not (Test-Path $DataDir)) {
    Move-Item $OldDataDir $DataDir
    Write-Host "moved $OldDataDir to $DataDir"
}
$cfg = [ordered]@{
    _comment             = 'vulnagent-local for Windows: the reports stay on this machine. See README.md for all options.'
    include_runtimes     = $true
    include_winget       = $true
    include_certificates = $true
    install_updates      = 'none'
    reboot_after_updates = $false
    hardening_exclude    = @()
    keep_reports_days    = 90
    report_readers       = @()
}
if (Test-Path $Conf) {
    $old = Get-Content -Path $Conf -Raw | ConvertFrom-Json
    foreach ($p in $old.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
    Write-Host "keeping existing $Conf"
}
if ($KeepDays -ge 0) { $cfg.keep_reports_days = $KeepDays }
if ($ReportReaders) { $cfg.report_readers = @($ReportReaders | Where-Object { $_ -and $_ -ne 'none' }) }

# Any user may create folders in the root of C:, so the installer takes ownership of everything in
# C:\vulnagent-local and resets it to SYSTEM and Administrators only (SIDs work in every language).
# The reports folder can also be opened by report_readers, without "Run as administrator".
New-Item -ItemType Directory -Force -Path (Join-Path $ReportDir 'history') | Out-Null
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "could not restrict access to $DataDir (icacls exit $LASTEXITCODE)" }
& icacls.exe (Join-Path $DataDir '*') /reset /T /C /Q | Out-Null
& icacls.exe $DataDir /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
foreach ($r in @($cfg.report_readers)) {
    & icacls.exe $ReportDir /grant "${r}:(OI)(CI)RX" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not give $r read access to $ReportDir (icacls exit $LASTEXITCODE)" }
    Write-Host "$r can read $ReportDir"
}

[IO.File]::WriteAllText($Conf, (ConvertTo-Json -InputObject $cfg -Depth 4), (New-Object Text.UTF8Encoding $false))
Write-Host "wrote $Conf"

# 3. daily scheduled tasks as SYSTEM
$trigger = New-ScheduledTaskTrigger -Daily -At $At -RandomDelay (New-TimeSpan -Minutes 45)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$action = New-ScheduledTaskAction -Execute $PowerShellExe `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Agent`""
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'vulnagent-local: scan for missing updates and outdated software, report in C:\vulnagent-local\reports' -Force | Out-Null
Write-Host "scheduled task '$TaskName' runs daily at $At (+ up to 45 min)"

if ($NoHardening) {
    Unregister-ScheduledTask -TaskName $HardenTask -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $Harden -Force -ErrorAction SilentlyContinue
} else {
    # audit only: changes are made by hand with -Apply
    $action = New-ScheduledTaskAction -Execute $PowerShellExe `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Harden`""
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $HardenTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'vulnagent-local: compare with the Microsoft security baseline, report in C:\vulnagent-local\reports (changes nothing)' -Force | Out-Null
    Write-Host "scheduled task '$HardenTask' runs daily at $At (+ up to 45 min), audit only"
}

# 4. first scan and hardening check
if (-not $NoRun) {
    Write-Host ''
    Write-Host 'First scan (the Windows Update search can take several minutes)...'
    & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $Agent
    switch ($LASTEXITCODE) {
        0 { }
        2 { Write-Warning 'Part of the scan failed (see the ERROR lines above); the report may be incomplete.' }
        default { Write-Warning "The first scan failed (exit $LASTEXITCODE). Fix the error above, then run: Start-ScheduledTask $TaskName" }
    }
    if (-not $NoHardening) {
        Write-Host ''
        Write-Host 'First hardening check (changes nothing)...'
        & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $Harden
        if ($LASTEXITCODE -eq 3) { Write-Warning "The hardening check failed. Fix the error above, then run: Start-ScheduledTask $HardenTask" }
    }
}
Write-Host ''
Write-Host "Reports: $ReportDir\index.html"
Write-Host "Logs:    $DataDir\scan.log, $DataDir\hardening.log"
Write-Host "Run now: Start-ScheduledTask $TaskName"
if (-not $NoHardening) {
    Write-Host "Fix:     & '$Harden' -Apply safe -DryRun   (shows what would change), then without -DryRun"
}
