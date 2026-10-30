<#
.SYNOPSIS
    Install vulnagent for Windows and register the machine with DefectDojo.

.DESCRIPTION
    Run from an elevated PowerShell on each Windows machine. It:
      * copies vulnagent-win.ps1 to C:\Program Files\vulnagent (from this
        folder, or downloads it from GitHub when run on its own),
      * writes C:\ProgramData\vulnagent\defectdojo.json, readable only by
        SYSTEM and Administrators because it holds the API token,
      * creates the "vulnagent" scheduled task: daily as SYSTEM, at -At plus
        up to 45 minutes of random delay,
      * runs the first scan, so the machine shows up in DefectDojo right away.

    Running it again updates the agent and keeps the existing config; values
    you pass (-Url, -Token, ...) replace the ones in the config.

.EXAMPLE
    $env:DD_API_TOKEN = '<token>'; .\install.ps1 -Url http://dojo.example.local:8080

.EXAMPLE
    .\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Url,
    [string]$Token,
    [string]$ProductType,
    [string]$ProductName,
    [string]$At = '03:30',
    [switch]$Insecure,
    [switch]$NoRun,
    [switch]$Uninstall,
    [switch]$Purge,
    [string]$Source = 'https://raw.githubusercontent.com/bandprothesis-bit/linux_scanner/defectdojo/windows/vulnagent-win.ps1'
)

$ErrorActionPreference = 'Stop'
$TaskName = 'vulnagent'
$BinDir = Join-Path $env:ProgramFiles 'vulnagent'
$DataDir = Join-Path $env:ProgramData 'vulnagent'
$Agent = Join-Path $BinDir 'vulnagent-win.ps1'
$Conf = Join-Path $DataDir 'defectdojo.json'
$PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (right-click > Run as administrator).'
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $BinDir -Recurse -Force -ErrorAction SilentlyContinue
    if ($Purge) {
        Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host 'vulnagent removed, including its config and reports.'
    } else {
        Write-Host "vulnagent removed ($DataDir kept; add -Purge to delete it)."
    }
    return
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Warning 'PowerShell 5.1 is recommended: install WMF 5.1 on Windows Server 2012 R2.'
}
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072  # TLS 1.2

# 1. agent
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$local = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'vulnagent-win.ps1' } else { '' }
if ($local -and (Test-Path $local)) {
    Copy-Item $local $Agent -Force
} elseif ($Source -match '^https?://') {
    Write-Host "downloading $Source"
    Invoke-WebRequest -Uri $Source -OutFile $Agent -UseBasicParsing
} else {
    Copy-Item $Source $Agent -Force
}
Unblock-File $Agent -ErrorAction SilentlyContinue
if (-not (Select-String -Path $Agent -Pattern 'vulnagent for Windows' -SimpleMatch -Quiet)) {
    Remove-Item $Agent -Force
    throw "$Source is not the vulnagent agent script"
}
Write-Host "installed $Agent"

# 2. config, readable only by SYSTEM and Administrators (SIDs work in every language)
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "could not restrict access to $DataDir (icacls exit $LASTEXITCODE)" }

$cfg = [ordered]@{
    _comment             = 'vulnagent for Windows -> DefectDojo. See WINDOWS.md for all options.'
    url                  = ''
    api_token            = ''
    product_type         = 'Windows servers'
    product_name         = '{host}'
    include_runtimes     = $true
    include_winget       = $true
    install_updates      = 'none'
    reboot_after_updates = $false
}
if (Test-Path $Conf) {
    $old = Get-Content -Path $Conf -Raw | ConvertFrom-Json
    foreach ($p in $old.PSObject.Properties) { $cfg[$p.Name] = $p.Value }
    Write-Host "keeping existing $Conf"
}
if ($Url) { $cfg.url = $Url.TrimEnd('/') }
if ($Token) { $cfg.api_token = $Token } elseif ($env:DD_API_TOKEN) { $cfg.api_token = $env:DD_API_TOKEN }
if ($ProductType) { $cfg.product_type = $ProductType }
if ($ProductName) { $cfg.product_name = $ProductName }
if ($Insecure) { $cfg.verify_tls = $false }
if (-not $cfg.url) { throw 'Pass the DefectDojo address: -Url http://<dojo-server>:8080' }
if (-not $cfg.api_token) {
    if (-not [Environment]::UserInteractive) { throw 'Pass the API token with -Token or $env:DD_API_TOKEN' }
    $sec = Read-Host -AsSecureString 'DefectDojo API v2 key'
    $cfg.api_token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
[IO.File]::WriteAllText($Conf, (ConvertTo-Json -InputObject $cfg -Depth 4), (New-Object Text.UTF8Encoding $false))
Write-Host "wrote $Conf"

# 3. daily scheduled task as SYSTEM
$action = New-ScheduledTaskAction -Execute $PowerShellExe `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Agent`""
$trigger = New-ScheduledTaskTrigger -Daily -At $At -RandomDelay (New-TimeSpan -Minutes 45)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'vulnagent: scan for missing updates and outdated software, report to DefectDojo' -Force | Out-Null
Write-Host "scheduled task '$TaskName' runs daily at $At (+ up to 45 min)"

# 4. first scan
if (-not $NoRun) {
    Write-Host ''
    Write-Host 'First scan (the Windows Update search can take several minutes)...'
    & $PowerShellExe -NoProfile -ExecutionPolicy Bypass -File $Agent
    $rc = $LASTEXITCODE
    Write-Host ''
    switch ($rc) {
        0 { Write-Host 'Done: the machine is now in DefectDojo under Products.' }
        2 { Write-Warning 'Uploaded, but part of the scan failed (see the ERROR lines above).' }
        default { Write-Warning "The first scan failed (exit $rc). Fix the error above, then run: Start-ScheduledTask $TaskName" }
    }
}
Write-Host ''
Write-Host "Log:     $DataDir\vulnagent.log"
Write-Host "Run now: Start-ScheduledTask $TaskName"
