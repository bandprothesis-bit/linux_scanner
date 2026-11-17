<#
.SYNOPSIS
    Install vulnagent-local on many Windows machines at once over PowerShell remoting.

.DESCRIPTION
    Run from an admin workstation or jump host, in this folder, as a user who
    is administrator on the target machines (for example a domain admin).
    WinRM must be enabled on the targets; it is on by default on domain-joined
    Windows Servers.

    For each machine it copies vulnagent-local-scan.ps1,
    vulnagent-local-harden.ps1, vulnagent-local-ai.ps1 and install-local.ps1,
    runs the installer and starts the first scan, hardening check and AI agent
    scan in the background. The reports
    stay on each machine, in C:\vulnagent-local\reports.

.EXAMPLE
    .\deploy-fleet-local.ps1 -ComputerName (Get-Content .\servers.txt)

.EXAMPLE
    .\deploy-fleet-local.ps1 -ComputerName srv01, srv02 -ReportReaders 'CONTOSO\Server Admins' -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$ComputerName,
    [string]$At = '03:30',
    [int]$KeepDays = -1,
    [string[]]$ReportReaders,
    [pscredential]$Credential,
    [switch]$NoRun,
    [switch]$NoHardening,
    [switch]$NoAiScan
)

$ErrorActionPreference = 'Stop'
$files = @((Join-Path $PSScriptRoot 'vulnagent-local-scan.ps1'), (Join-Path $PSScriptRoot 'vulnagent-local-harden.ps1'),
           (Join-Path $PSScriptRoot 'vulnagent-local-ai.ps1'), (Join-Path $PSScriptRoot 'install-local.ps1'))
foreach ($f in $files) { if (-not (Test-Path $f)) { throw "missing ${f}: run this from the windows-local folder of the repository" } }

$remoteDir = 'C:\Windows\Temp\vulnagent-local-setup'
$results = @()

foreach ($c in ($ComputerName | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })) {
    $c = $c.Trim()
    Write-Host "== $c"
    $s = $null
    try {
        $sp = @{ ComputerName = $c }
        if ($Credential) { $sp.Credential = $Credential }
        $s = New-PSSession @sp
        Invoke-Command -Session $s -ScriptBlock { param($d) New-Item -ItemType Directory -Force -Path $d | Out-Null } -ArgumentList $remoteDir
        Copy-Item -ToSession $s -Path $files -Destination $remoteDir -Force
        $out = Invoke-Command -Session $s -ArgumentList $remoteDir, $At, $KeepDays, $ReportReaders, [bool]$NoRun, [bool]$NoHardening, [bool]$NoAiScan -ScriptBlock {
            param($dir, $at, $keep, $readers, $norun, $noharden, $noai)
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
            $a = @{ At = $at; KeepDays = $keep; NoRun = $true }
            if ($readers) { $a.ReportReaders = $readers }
            if ($noharden) { $a.NoHardening = $true }
            if ($noai) { $a.NoAiScan = $true }
            try {
                & (Join-Path $dir 'install-local.ps1') @a
            } finally {
                Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
            }
            # first scan in the background, as SYSTEM, like the nightly run
            if (-not $norun) {
                Start-ScheduledTask -TaskName 'vulnagent-local-scan'; 'first scan started'
                if (-not $noharden) { Start-ScheduledTask -TaskName 'vulnagent-local-hardening'; 'first hardening check started' }
                if (-not $noai) { Start-ScheduledTask -TaskName 'vulnagent-local-ai'; 'first AI agent scan started' }
            }
        }
        $out | ForEach-Object { Write-Host "   $_" }
        $results += [pscustomobject]@{ Computer = $c; Result = 'installed' }
    } catch {
        Write-Warning "${c}: $($_.Exception.Message)"
        $results += [pscustomobject]@{ Computer = $c; Result = "FAILED: $($_.Exception.Message)" }
    } finally {
        if ($s) { Remove-PSSession $s }
    }
}

$results | Format-Table -AutoSize -Wrap
Write-Host 'The reports are ready on each machine when its first scan finishes (usually 5-15 minutes):'
Write-Host '  C:\vulnagent-local\reports\index.html'
