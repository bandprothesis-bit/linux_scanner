<#
.SYNOPSIS
    Install vulnagent on many Windows machines at once over PowerShell remoting.

.DESCRIPTION
    Run from an admin workstation or jump host, in this folder, as a user who
    is administrator on the target machines (for example a domain admin).
    WinRM must be enabled on the targets; it is on by default on domain-joined
    Windows Servers.

    For each machine it copies vulnagent-win.ps1 and install.ps1, runs the
    installer and starts the first scan in the background. The API token is
    asked once (or taken from $env:DD_API_TOKEN) and sent over the encrypted
    WinRM session.

.EXAMPLE
    .\deploy-fleet.ps1 -ComputerName (Get-Content .\servers.txt) -Url http://dojo.example.local:8080

.EXAMPLE
    .\deploy-fleet.ps1 -ComputerName srv01, srv02 -Url http://dojo.example.local:8080 -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$ComputerName,
    [Parameter(Mandatory = $true)][string]$Url,
    [string]$ProductType,
    [string]$At = '03:30',
    [pscredential]$Credential,
    [switch]$Insecure,
    [switch]$NoRun
)

$ErrorActionPreference = 'Stop'
$files = @((Join-Path $PSScriptRoot 'vulnagent-win.ps1'), (Join-Path $PSScriptRoot 'install.ps1'))
foreach ($f in $files) { if (-not (Test-Path $f)) { throw "missing ${f}: run this from the windows folder of the repository" } }

$tok = $env:DD_API_TOKEN
if (-not $tok) {
    $sec = Read-Host -AsSecureString 'DefectDojo API v2 key'
    $tok = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
$remoteDir = 'C:\Windows\Temp\vulnagent-setup'
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
        $out = Invoke-Command -Session $s -ArgumentList $remoteDir, $Url, $tok, $ProductType, $At, [bool]$Insecure, [bool]$NoRun -ScriptBlock {
            param($dir, $url, $tok, $ptype, $at, $insecure, $norun)
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
            $env:DD_API_TOKEN = $tok
            $a = @{ Url = $url; At = $at; NoRun = $true }
            if ($ptype) { $a.ProductType = $ptype }
            if ($insecure) { $a.Insecure = $true }
            try {
                & (Join-Path $dir 'install.ps1') @a
            } finally {
                Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
            }
            # first scan in the background, as SYSTEM, like the nightly run
            if (-not $norun) { Start-ScheduledTask -TaskName 'vulnagent'; 'first scan started' }
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
Write-Host 'The machines appear in DefectDojo when their first scan finishes (usually 5-15 minutes).'
