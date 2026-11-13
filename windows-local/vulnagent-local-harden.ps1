<#
.SYNOPSIS
    vulnagent-local hardening for Windows: checks the machine against the
    Microsoft security baselines, applies the recommended settings when asked,
    and writes the reports on this machine. Nothing is sent to a server.

.DESCRIPTION
    The checks come from the Microsoft Security Compliance Toolkit baselines:

      * Windows Server 2025 (v2602), Member Server profile, for servers,
      * the Domain Controller profile of the same baseline for DCs,
      * Windows 11 v25H2 for workstations,

    plus Microsoft's TLS, PowerShell 2.0 and Print Spooler guidance. Settings
    that need a newer Windows than the machine runs are skipped.

    Each check also names the CIS Benchmark recommendations for the same
    setting (Server 2016 to 2025, the Stand-alone benchmarks for servers
    outside a domain, Windows 11 and the Defender Antivirus benchmark), and
    the DISA STIG IDs on Server 2019 and 2022, for audits against CIS or STIG.

    Without -Apply the script only reads. Each run:

      * checks about 130 settings: SMB, NTLM and LSA protection, UAC,
        password and lockout policy, user rights, audit policy, event log
        sizes, Defender and attack surface reduction rules, firewall, RDP,
        WinRM, TLS and more,
      * compares the result with the previous run: which checks fail now that
        passed before, and which were fixed,
      * writes the reports to C:\vulnagent-local\reports:
        hardening.html (open in a browser), hardening.json (all data),
        hardening-findings.json (one finding per failed check), a dated copy in
        reports\history and index.html, which lists all of them.

    On Server 2022 and 2025, and Server 2019 outside a domain, about 155 to
    185 more checks cover the CIS Benchmark Level 1 recommendations that are not
    in the Microsoft baseline (IDs CIS-001 and up; 30 of them for Defender on
    every Windows version). Turn them off with "cis_checks": false.

    On machines with IIS or SQL Server, more checks cover their settings
    (IDs IIS-01 and up, SQL-01 and up), with the DISA STIG IDs of the IIS 10.0
    Server and Site STIGs and the SQL Server 2022 Instance STIG. They run only
    where IIS or SQL Server is installed, and only report: the fix is a
    command or a step by hand (two IIS registry settings can be applied with
    -Apply all). The SQL Server checks connect to the local instances with the
    account that runs the script. Turn them off with "iis_checks": false or
    "sql_checks": false.

    Every check is marked:
      safe    can be applied without breaking a normal, current environment
      review  can break old clients or applications: test first
      cis     a CIS Level 1 setting outside the Microsoft baseline: test first
      manual  needs hardware, Active Directory or a decision (not automatic)

    -Apply safe changes the failed "safe" checks, -Apply all also the "review"
    ones, -Apply cis the failed "cis" ones. Before a change the old value is saved to
    C:\vulnagent-local\hardening\backup-<time>.json, and -Undo puts
    it back. In a domain, settings that a Group Policy sets win over local
    changes: apply the Microsoft baseline GPOs there instead.

    Needs Windows PowerShell 5.1 and an elevated prompt (or SYSTEM). Makes no
    network connections, except to the local SQL Server instances.

    Exit codes: 0 done, 2 some checks or changes failed, 3 failed (no report
    written).

.EXAMPLE
    vulnagent-local-harden.ps1 -Html $env:TEMP\hardening.html
    Check only, and also write the report where your browser can open it
    without administrator rights.

.EXAMPLE
    vulnagent-local-harden.ps1 -Apply safe -DryRun
    Show what -Apply safe would change, without changing anything.

.EXAMPLE
    vulnagent-local-harden.ps1 -Apply all -Only SMB-*, LSA-03
    Apply the failed SMB checks and LSA-03, including "review" ones.

.EXAMPLE
    vulnagent-local-harden.ps1 -Apply cis -Only 'CIS firewall', CIS-012 -DryRun
    Show what the CIS firewall checks and CIS-012 would change.

.EXAMPLE
    vulnagent-local-harden.ps1 -Undo last
    Put back the values that the last -Apply changed.

.EXAMPLE
    vulnagent-local-harden.ps1 -List
    List all checks that apply to this machine.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$DryRun,
    [string]$Output,
    [string]$Html,
    [ValidateSet('safe', 'all', 'cis')][string]$Apply,
    [string[]]$Only,
    [string[]]$Exclude,
    [string]$Undo,
    [switch]$List
)
$ErrorActionPreference = 'Stop'
$VERSION = '1.0.0'
$SCAN_TYPE = 'Generic Findings Import'
$DataDir = Join-Path "$env:SystemDrive\" 'vulnagent-local'   # C:\vulnagent-local
if (-not $ConfigPath) { $ConfigPath = Join-Path $DataDir 'config.json' }
$LogFile = Join-Path $DataDir 'hardening.log'
$BackupDir = Join-Path $DataDir 'hardening'

$DefaultConfig = [ordered]@{
    hardening_exclude        = @()                # accepted deviations: check IDs (wildcards allowed)
    hardening_include_passed = $false             # also list passed checks in hardening-findings.json, as Info
    cis_checks               = $true              # also check the CIS Level 1 settings outside the Microsoft baseline
    iis_checks               = $true              # check the IIS settings, where IIS is installed
    sql_checks               = $true              # check the SQL Server settings, where SQL Server is installed
    keep_reports_days        = 90                 # dated copies in reports\history; 0 keeps them all
}

$SeverityOrder = [ordered]@{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$StatusOrder = @{ fail = 0; error = 1; exception = 2; pass = 3 }

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

function Write-Log([string]$Message) {
    $line = '{0} {1}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $Message
    try {
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 2MB) {
            Move-Item $LogFile "$LogFile.1" -Force
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Write-TextFile([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding $false))
}

function Write-JsonFile([string]$Path, $Object) {
    Write-TextFile $Path (ConvertTo-Json -InputObject $Object -Depth 10)
}

function Get-Clip([string]$Text, [int]$Max) {
    if ($Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max - 3) + '...'
}

function Read-Config([string]$Path) {
    $cfg = [ordered]@{}
    foreach ($k in $DefaultConfig.Keys) { $cfg[$k] = $DefaultConfig[$k] }
    if (Test-Path $Path) {
        $j = Get-Content -Path $Path -Raw | ConvertFrom-Json
        foreach ($p in $j.PSObject.Properties) {
            if (-not $p.Name.StartsWith('_')) { $cfg[$p.Name] = $p.Value }
        }
    }
    $cfg
}

function Assert-Admin {
    $me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell (right-click > Run as administrator).'
    }
}

function Initialize-DataDir {
    if (-not (Test-Path $DataDir)) {
        # same access as install-local.ps1 sets: SYSTEM and Administrators only
        New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
        & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    }
    foreach ($d in (Join-Path $DataDir 'reports\history'), $BackupDir) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}

function Test-IdMatch([string]$Id, [string]$Area, $Patterns) {
    foreach ($p in @($Patterns)) {
        if ($p -and ($Id -like $p -or $Area -eq $p)) { return $true }
    }
    $false
}

# --------------------------------------------------------------------------
# machine
# --------------------------------------------------------------------------

function Get-HostInfo {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $name = if ($cs.DNSHostName) { $cs.DNSHostName } else { $env:COMPUTERNAME }
    $fqdn = if ($cs.PartOfDomain) { '{0}.{1}' -f $name, $cs.Domain } else { $name }
    $release = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
    $role = [int]$cs.DomainRole    # 0/1 workstation, 2/3 server, 4/5 domain controller
    [pscustomobject]@{
        host    = $fqdn.ToLower()
        short   = $name.ToLower()
        os      = "$($os.Caption)".Trim()
        version = "$($os.Version)"
        ubr     = "$($cv.UBR)"
        release = "$release"
        build   = [int]$os.BuildNumber
        server  = ($os.ProductType -ne 1)
        dc      = ($role -ge 4)
        domain  = [bool]$cs.PartOfDomain
        role    = @('standalone workstation', 'domain member workstation', 'standalone server',
                    'domain member server', 'domain controller', 'domain controller')[$role]
        iis     = $(try { Get-IisInfo } catch { $null })
        sql     = @(try { Get-SqlInstances } catch { })
    }
}

function Get-BaselineName($H) {
    if ($H.dc) { return 'Microsoft security baseline Windows Server 2025 v2602 (Domain Controller)' }
    if ($H.server) { return 'Microsoft security baseline Windows Server 2025 v2602 (Member Server)' }
    'Microsoft security baseline Windows 11 v25H2'
}

# CIS Benchmark recommendations and DISA STIG IDs that cover the same setting as each check.
# Read from the CIS benchmark PDFs: Server 2019 Stand-alone v4.0.0, Server 2022 v5.1.0 and
# Stand-alone v2.0.0, Server 2025 v2.1.1 and Stand-alone v2.0.0, Defender Antivirus v1.0.0, and
# the CIS STIG benchmarks for Server 2019 (v3.0.0) and 2022 (v2.0.0) for the STIG IDs. Server 2016,
# Server 2019 in a domain and Windows 11 come from the Wazuh CIS policies (github.com/wazuh/wazuh,
# ruleset/sca/windows). The value a check wants is the Microsoft one; $CisNotes says where CIS
# asks for another value.
# Cells: CIS level L1 unless marked /L2, /NG (next generation, needs VBS) or /BL (BitLocker);
# STIG IDs carry their category: /I, /II, /III. !dc and !ms: only on domain controllers / only on
# the other servers. '=' is the same as the column to the left. Columns, in this order:
# ws2016 ws2019 ws2019sa ws2022 ws2022sa ws2025 ws2025sa win11 defender stig2019 stig2022.
$CisBenchmarks = [ordered]@{
    ws2016   = 'CIS Microsoft Windows Server 2016 Benchmark v2.0.0'
    ws2019   = 'CIS Microsoft Windows Server 2019 Benchmark v2.0.0'
    ws2019sa = 'CIS Microsoft Windows Server 2019 Stand-alone Benchmark v4.0.0'
    ws2022   = 'CIS Microsoft Windows Server 2022 Benchmark v5.1.0'
    ws2022sa = 'CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0'
    ws2025   = 'CIS Microsoft Windows Server 2025 Benchmark v2.1.1'
    ws2025sa = 'CIS Microsoft Windows Server 2025 Stand-alone Benchmark v2.0.0'
    win11    = 'CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0'
    defender = 'CIS Microsoft Defender Antivirus Benchmark v1.0.0'
    stig2019 = 'DISA STIG Windows Server 2019 V3R2 (CIS Windows Server 2019 STIG Benchmark v3.0.0)'
    stig2022 = 'DISA STIG Windows Server 2022 V2R2 (CIS Windows Server 2022 STIG Benchmark v2.0.0)'
}
$CisTable = @'
# check ws2016 ws2019 ws2019sa ws2022 ws2022sa ws2025 ws2025sa win11 defender stig2019 stig2022
SMB-01  18.4.4 = 18.4.3 = 18.4.2 18.4.3 18.4.2 18.4.4 - WN19-00-000390/II WN22-00-000390/II
SMB-02  18.4.3 = 18.4.2 = 18.4.1 18.4.2 18.4.1 18.4.3 - WN19-00-000400/II WN22-00-000400/II
SMB-03  - 2.3.9.2 = = = = = = - WN19-SO-000190/II WN22-SO-000190/II
SMB-04  2.3.8.1,2.3.9.2 2.3.8.1 = = = = = = - WN19-SO-000160/II WN22-SO-000160/II
SMB-05  2.3.8.3 = 2.3.8.2 = = = = 2.3.8.3 - WN19-SO-000180/II WN22-SO-000180/II
SMB-06  18.6.8.1 = = = = 18.6.8.4 = 18.6.8.1 - WN19-CC-000070/II WN22-CC-000070/II
SMB-07  2.3.10.10 = 2.3.10.9 2.3.10.10 2.3.10.9 2.3.10.10 2.3.10.9 = - WN19-SO-000250/I WN22-SO-000250/II
SMB-08  - - - 18.6.7.1 = 18.6.7.6,18.6.8.6 = - - - -
SMB-09  - - - - - 18.6.7.4,18.6.7.7 = - - - -
SMB-10  - - - - - 18.6.7.1,18.6.7.2,18.6.7.3,18.6.8.1,18.6.8.2,18.6.8.3 = - - - -
SMB-11  - - - - - 18.6.7.5,18.6.8.5 = - - - -
NET-01  18.6.4.2 = 18.6.4.4 = - 18.6.4.4 - 18.6.4.3 - - -
NET-02  18.6.4.1 = 18.6.4.2 = - 18.6.4.2 - 18.6.4.2 - - -
NET-03  18.4.7 18.4.6 18.4.7 18.4.6 18.4.5 18.4.6 18.4.5 18.4.7 - - -
NET-04  18.5.6 = = = = = = 18.5.7 - WN19-CC-000060/III WN22-CC-000060/II
NET-05  18.5.2,18.5.3 = = = = = = = - WN19-CC-000030/III,WN19-CC-000040/III WN22-CC-000030/II,WN22-CC-000040/II
NET-06  18.5.4 = = = = = = 18.5.5 - WN19-CC-000050/III WN22-CC-000050/II
NET-07  18.6.14.1 - 18.6.14.1 = = = = = - WN19-CC-000080/II WN22-CC-000080/II
NET-08  2.3.11.8 = = = = = = = - WN19-SO-000320/II WN22-SO-000320/II
NET-09  18.9.35.2/L2!ms = 18.9.38.2/L2 18.9.38.2/L2!ms 18.9.38.2/L2 18.9.38.2/L2!ms 18.9.38.2/L2 18.9.36.2 - WN19-MS-000040/II!ms WN22-MS-000040/II!ms
LSA-01  18.4.8 18.4.7 18.4.8 - - - - 18.4.8 - WN19-CC-000020/II WN22-CC-000020/II
LSA-02  2.3.11.5 = = = = - - 2.3.11.5 - WN19-SO-000300/I WN22-SO-000300/I
LSA-03  2.3.11.7 = = = = 2.3.11.6 = 2.3.11.7 - WN19-SO-000310/I WN22-SO-000310/II
LSA-04  2.3.11.9,2.3.11.10 = = = = = = = - WN19-SO-000330/II,WN19-SO-000340/II WN22-SO-000330/II,WN22-SO-000340/II
LSA-05  2.3.10.2!ms,2.3.10.3!ms = 2.3.10.2,2.3.10.3 2.3.10.2!ms,2.3.10.3!ms 2.3.10.2,2.3.10.3 2.3.10.2!ms,2.3.10.3!ms 2.3.10.2,2.3.10.3 = - WN19-SO-000220/I,WN19-SO-000230/I WN22-SO-000220/I,WN22-SO-000230/I
LSA-06  2.3.10.11!ms = 2.3.10.10 2.3.10.11!ms 2.3.10.10 2.3.10.11!ms 2.3.10.10 = - WN19-MS-000060/II!ms WN22-MS-000060/II!ms
LSA-07  2.3.11.2 = = = = = = = - WN19-SO-000270/II WN22-SO-000270/II
LSA-08  2.3.1.3 = 2.3.1.2 = = = = 2.3.1.3 - WN19-SO-000020/I WN22-SO-000020/II
LSA-09  18.4.6 18.9.25.1/NG 18.4.6 18.9.27.2/NG 18.9.27.1/NG 18.9.27.2/NG 18.9.27.1/NG 18.9.26.2 - - -
LSA-10  18.9.4.2 = = = = = = = - WN19-CC-000100/II WN22-CC-000100/II
LSA-11  18.9.4.1 = = = = = = = - - -
LSA-12  - - 2.3.11.11,2.3.11.12 2.3.11.11,2.3.11.13 2.3.11.11,2.3.11.12 2.3.11.11,2.3.11.13 2.3.11.11,2.3.11.12 = - - -
LSA-13  18.9.5.5/NG!ms = 18.9.5.5/NG 18.9.5.5/NG!ms 18.9.5.5/NG 18.9.5.5/NG!ms 18.9.5.5/NG 18.9.5.5 - - WN22-MS-000140/II!ms
UAC-01  2.3.17.6 = = = = = = = - WN19-SO-000440/II WN22-SO-000440/II
UAC-02  2.3.17.2 = = = = = = = - WN19-SO-000400/II WN22-SO-000400/II
UAC-03  2.3.17.3 = = = = = = = - WN19-SO-000410/II WN22-SO-000410/II
UAC-04  2.3.17.1 = = = = = = = - WN19-SO-000380/II WN22-SO-000380/II
UAC-05  2.3.17.4,2.3.17.5,2.3.17.8 = = = = = = = - WN19-SO-000420/II,WN19-SO-000430/II,WN19-SO-000450/II WN22-SO-000420/II,WN22-SO-000430/II,WN22-SO-000450/II
UAC-06  18.4.1!ms = 18.4.1 18.4.1!ms - 18.4.1!ms - 18.4.1 - WN19-MS-000020/II!ms WN22-MS-000020/II!ms
ACC-01  1.1.4 = = = = = = = - WN19-AC-000070/II WN22-AC-000070/II
ACC-02  1.1.5 = = = = = = = - WN19-AC-000080/II WN22-AC-000080/II
ACC-03  1.1.1 - 1.1.1 = = = = = - WN19-AC-000040/II WN22-AC-000040/II
ACC-04  1.1.6 = = 1.1.7 = = = = - WN19-AC-000090/I WN22-AC-000090/I
ACC-05  1.2.2 = = = = = = = - WN19-AC-000020/II WN22-AC-000020/II
ACC-06  1.2.1,1.2.4 = = = = = = = - WN19-AC-000010/II,WN19-AC-000030/II WN22-AC-000010/II,WN22-AC-000030/II
ACC-07  1.2.3 = = 1.2.3!ms 1.2.3 1.2.3!ms 1.2.3 = - - -
ACC-08  2.3.1.2!ms = 2.3.1.1 2.3.1.1!ms 2.3.1.1 2.3.1.1!ms 2.3.1.1 2.3.1.2 - WN19-SO-000010/II WN22-SO-000010/II
ACC-09  2.3.10.1 = = = = = = = - WN19-SO-000210/I WN22-SO-000210/II
ACC-10  2.3.7.3 = = = = = = 2.3.7.4 - WN19-SO-000120/II WN22-SO-000120/II
ACC-11  18.10.82.1 = 18.10.83.1 18.10.83.2 = = = 18.10.81.2 - WN19-CC-000450/II WN22-CC-000450/II
ACC-12  - - - - - - - - - - -
ACC-13  18.3.3!ms = - 18.9.26.1!ms - 18.9.26.1!ms - 18.9.25.1 - - -
ACC-14  2.3.7.9 = = = 2.3.7.7 2.3.7.9 2.3.7.7 2.3.7.9 - WN19-SO-000150/II WN22-SO-000150/II
URA-01  2.2.4 = 2.2.3 2.2.4 2.2.3 2.2.4 2.2.3 = - WN19-UR-000020/I WN22-UR-000020/I
URA-02  2.2.14 = 2.2.10 2.2.14 2.2.10 2.2.14 2.2.10 2.2.11 - WN19-UR-000060/I WN22-UR-000060/II
URA-03  2.2.1 = = = = = = = - WN19-UR-000010/II WN22-UR-000010/II
URA-04  2.2.19 = 2.2.14 2.2.19 2.2.14 2.2.19 2.2.14 2.2.15 - WN19-UR-000090/I WN22-UR-000100/I
URA-05  2.2.34 = 2.2.25 2.2.34 2.2.25 2.2.34 2.2.25 2.2.26 - WN19-UR-000150/II WN22-UR-000150/II
URA-06  2.2.48 = 2.2.36 2.2.48 2.2.36 2.2.48 2.2.36 2.2.39 - WN19-UR-000220/II WN22-UR-000220/II
URA-07  2.2.38!ms = 2.2.27 2.2.37!dc,2.2.38!ms 2.2.27 2.2.37!dc,2.2.38!ms 2.2.27 2.2.30 - WN19-UR-000170/II!dc,WN19-UR-000170/II!ms WN22-UR-000170/II!dc,WN22-UR-000170/II!ms
URA-08  2.2.10 = 2.2.7 2.2.11 2.2.7 2.2.11 2.2.7 = - WN19-UR-000040/II WN22-UR-000040/II
URA-09  2.2.45 = 2.2.34 2.2.45 2.2.34 2.2.45 2.2.34 2.2.37 - WN19-UR-000210/II WN22-UR-000210/II
URA-10  2.2.40 = 2.2.29 2.2.40 2.2.29 2.2.40 2.2.29 2.2.32 - WN19-UR-000180/II WN22-UR-000180/II
URA-11  2.2.35 = 2.2.26 2.2.35 2.2.26 2.2.35 2.2.26 2.2.27 - WN19-UR-000160/II WN22-UR-000160/II
URA-12  2.2.16 = 2.2.12 2.2.16 2.2.12 2.2.16 2.2.12 2.2.13 - WN19-UR-000080/II WN22-UR-000080/II
URA-13  2.2.27!dc,2.2.28!ms = 2.2.20 2.2.27!dc,2.2.28!ms 2.2.20 2.2.27!dc,2.2.28!ms 2.2.20 2.2.21 - WN19-DC-000420/II!dc,WN19-MS-000130/II!ms WN22-DC-000420/II!dc,WN22-MS-000130/II!ms
URA-14  2.2.20!dc,2.2.21!ms = 2.2.15 2.2.20!dc,2.2.21!ms 2.2.15 2.2.20!dc,2.2.21!ms 2.2.15 2.2.16 - WN19-DC-000370/II!dc,WN19-MS-000080/II!ms WN22-DC-000370/II!dc,WN22-MS-000080/II!ms
URA-15  2.2.25!dc,2.2.26!ms = 2.2.19 2.2.25!dc,2.2.26!ms 2.2.19 2.2.25!dc,2.2.26!ms 2.2.19 2.2.20 - WN19-MS-000120/II!ms WN22-DC-000410/II!dc,WN22-MS-000120/II!ms
URA-16  2.2.2!dc,2.2.3!ms = 2.2.2 2.2.2!dc,2.2.3!ms 2.2.2 2.2.2!dc,2.2.3!ms 2.2.2 = - WN19-DC-000340/II!dc,WN19-MS-000070/II!ms WN22-DC-000340/II!dc,WN22-MS-000070/II!ms
URA-17  2.2.7 = 2.2.5 2.2.7!dc,2.2.8!ms 2.2.5 2.2.7!dc,2.2.8!ms 2.2.5 = - - WN22-UR-000030/II
AUD-01  17.1.1 = = = = = = = - WN19-AU-000070/II WN22-AU-000070/II
AUD-02  17.2.5 = 17.2.2 17.2.5 17.2.2 17.2.5 17.2.2 = - WN19-AU-000100/II WN22-AU-000100/II
AUD-03  17.2.6 = 17.2.3 17.2.6 17.2.3 17.2.6 17.2.3 = - WN19-AU-000110/II WN22-AU-000110/II
AUD-04  17.3.1 = = = = = = = - WN19-AU-000130/II WN22-AU-000130/II
AUD-05  17.3.2 = = = = = = = - WN19-AU-000140/II WN22-AU-000140/II
AUD-06  17.5.1 = = = = = = = - WN19-AU-000160/II WN22-AU-000160/II
AUD-07  17.5.2 = = = = = = = - WN19-AU-000170/II WN22-AU-000170/II
AUD-08  17.5.4 = = = = = = = - WN19-AU-000190/II WN22-AU-000190/II
AUD-09  17.5.5 = = = = = = = - - -
AUD-10  17.5.6 = = = = = = = - WN19-AU-000210/II WN22-AU-000210/II
AUD-11  17.6.1 = = = = = = = - - -
AUD-12  17.6.2 = = = = = = = - - -
AUD-13  17.6.3 = = = = = = = - WN19-AU-000220/II WN22-AU-000220/II
AUD-14  17.6.4 = = = = = = = - WN19-AU-000240/II WN22-AU-000240/II
AUD-15  17.7.1 = = = = = = = - WN19-AU-000260/II WN22-AU-000260/II
AUD-16  17.7.2 = = = = = = = - WN19-AU-000280/II WN22-AU-000280/II
AUD-17  17.7.4 = = = = = = = - - -
AUD-18  17.7.5 = = = = = = = - - -
AUD-19  17.8.1 = = = = = = = - - WN22-AU-000300/II
AUD-20  17.9.2 = = = = = = = - WN19-AU-000340/II WN22-AU-000340/II
AUD-21  17.9.3 = = = = = = = - WN19-AU-000360/II WN22-AU-000360/II
AUD-22  17.9.4 = = = = = = = - WN19-AU-000370/II WN22-AU-000370/II
AUD-23  17.9.5 = = = = = = = - WN19-AU-000380/II WN22-AU-000380/II
AUD-24  17.7.3 = = = = = = = - WN19-AU-000290/II WN22-AU-000290/II
AUD-40  2.3.2.1 2.3.1.5 2.3.2.1 = = = = = - WN19-SO-000050/II WN22-SO-000050/II
AUD-41  18.9.3.1 = = = = = = = - WN19-CC-000090/II WN22-CC-000090/II
AUD-42  18.10.87.1 = 18.10.88.1/L2 = = = = 18.10.86.1/L2 - WN19-CC-000460/II WN22-CC-000460/II
AUD-43  18.10.26.1.2,18.10.26.2.2,18.10.26.3.2,18.10.26.4.2 = = = = = = 18.10.25.1.2,18.10.25.2.2,18.10.25.3.2,18.10.25.4.2 - WN19-CC-000270/II,WN19-CC-000280/II,WN19-CC-000290/II WN22-CC-000270/II,WN22-CC-000280/II,WN22-CC-000290/II
DEF-01  18.10.43.17 = - - - - - 18.10.42.17 - - -
DEF-02  18.10.43.10.2 = - - - - - 18.10.42.10.2 1.10.5 - -
DEF-03  18.10.43.10.3 = - - - - - 18.10.42.10.3 1.10.6 - -
DEF-04  18.10.43.10.1 = - - - - - 18.10.42.10.1 1.10.4 - -
DEF-05  18.10.43.10.4 = - - - - - 18.10.42.10.4 1.10.8 - -
DEF-06  18.10.43.5.2/L2 = - - - - - 18.10.42.5.2/L2 1.5.3 - -
DEF-07  - - - - - - - - 1.5.2 - -
DEF-08  - - - - - - - - 1.5.4 - -
DEF-09  - - - - - - - - 1.7.2 - -
DEF-10  18.10.43.16 = - - - - - 18.10.42.16 1.16 - -
DEF-11  18.10.43.13.1 = - - - - - 18.10.42.13.2 1.13.5 - -
DEF-12  18.10.43.6.3.1 = - - - - - 18.10.42.6.3.1 1.6.3.1 - -
DEF-21  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.5 - -
DEF-22  - - - - - - - - 1.6.1.2 - -
DEF-23  - - - - - - - - 1.6.1.17 - -
DEF-24  - - - - - - - - 1.6.1.13 - -
DEF-25  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.8 - -
DEF-26  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.9 - -
DEF-27  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.15 - -
DEF-28  - - - - - - - - - - -
DEF-29  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.6 - -
DEF-30  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.4 - -
DEF-31  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.10 - -
DEF-32  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.11 - -
DEF-33  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.16 - -
DEF-34  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.12 - -
DEF-35  18.10.43.6.1.2 = - - - - - 18.10.42.6.1.2 1.6.1.3 - -
DEF-36  - - - - - - - - - - -
FW-01   9.1.1,9.1.2 = = = - 9.1.1,9.1.2 - 9.1.1,9.1.2 - WNFWA-000001/II,WNFWA-000004/I =
FW-02   9.2.1,9.2.2 = = = = = = = - WNFWA-000002/II,WNFWA-000012/I =
FW-03   9.3.1,9.3.2 = = = = = = = - WNFWA-000003/II,WNFWA-000020/I =
FW-04   9.1.7,9.1.8,9.2.7,9.2.8,9.3.9,9.3.10 = 9.1.6,9.1.7,9.2.6,9.2.7,9.3.8,9.3.9 = 9.2.6,9.2.7,9.3.6,9.3.7 9.1.6,9.1.7,9.2.6,9.2.7,9.3.8,9.3.9 9.2.6,9.2.7,9.3.6,9.3.7 9.1.6,9.1.7,9.2.6,9.2.7,9.3.8,9.3.9 - WNFWA-000010/III,WNFWA-000011/II,WNFWA-000018/III,WNFWA-000019/III,WNFWA-000028/III,WNFWA-000029/III =
RDP-01  18.10.57.3.9.4 = = = = = = 18.10.56.3.9.4 - - -
RDP-02  18.10.57.3.9.2,18.10.57.3.9.5 = = = = = = 18.10.56.3.9.2,18.10.56.3.9.5 - WN19-CC-000370/II,WN19-CC-000380/II WN22-CC-000370/II,WN22-CC-000380/II
RDP-03  18.10.57.2.2 = = = = = = 18.10.56.2.3 - WN19-CC-000340/II WN22-CC-000340/II
RDP-04  18.10.57.3.9.1 = = = = = = 18.10.56.3.9.1 - WN19-CC-000360/II WN22-CC-000360/II
RDP-05  18.10.57.3.3.2 = = 18.10.57.3.3.3 = = = 18.10.56.3.3.3 - WN19-CC-000350/II WN22-CC-000350/II
RDP-06  18.9.34.2 = 18.9.37.2 = = = = 18.9.35.2 - - -
WRM-01  18.10.89.2.1,18.10.89.2.3 = 18.10.90.2.1,18.10.90.2.3 = = = = 18.10.88.2.1,18.10.88.2.3 - WN19-CC-000500/I,WN19-CC-000510/II WN22-CC-000500/I,WN22-CC-000510/II
WRM-02  18.10.89.1.1,18.10.89.1.2,18.10.89.1.3 = 18.10.90.1.1,18.10.90.1.2,18.10.90.1.3 = = = = 18.10.88.1.1,18.10.88.1.2,18.10.88.1.3 - WN19-CC-000470/I,WN19-CC-000480/II,WN19-CC-000490/II WN22-CC-000470/I,WN22-CC-000480/II,WN22-CC-000490/II
WRM-03  18.10.89.2.4 = 18.10.90.2.4 = = = = 18.10.88.2.4 - WN19-CC-000520/II WN22-CC-000520/II
SYS-01  18.10.7.1,18.10.7.2,18.10.7.3 = 18.10.8.1,18.10.8.2,18.10.8.3 = = = = 18.10.7.1,18.10.7.2,18.10.7.3 - WN19-CC-000210/I,WN19-CC-000220/I,WN19-CC-000230/I WN22-CC-000210/I,WN22-CC-000220/I,WN22-CC-000230/I
SYS-02  18.10.81.1,18.10.81.2 = 18.10.82.1,18.10.82.2 = = = = 18.10.80.1,18.10.80.2 - WN19-CC-000420/II,WN19-CC-000430/I WN22-CC-000420/II,WN22-CC-000430/I
SYS-03  18.4.5 = = = 18.4.4 18.4.5 18.4.4 18.4.6 - - -
SYS-04  18.9.13.1 = = = = = = = - WN19-CC-000130/II WN22-CC-000130/II
SYS-05  2.3.15.2 = = = = = = = - WN19-SO-000370/III WN22-SO-000370/II
SYS-06  - 18.9.24.1 = = = = = 18.9.24.1/BL - - -
SYS-07  18.10.76.2.1 = 18.10.77.2.1 = = = = 18.10.75.2.1 - WN19-CC-000300/II WN22-CC-000300/II
SYS-08  - - 18.10.29.2 = = = = - - - -
SYS-09  - - - - - - - - - - -
SYS-10  18.10.59.3 = = = = = = 18.10.58.5 - WN19-CC-000410/II WN22-CC-000410/II
SYS-11  18.9.27.4!ms = 18.9.29.4 18.9.29.4!ms - 18.9.29.4!ms - 18.9.28.4 - WN19-MS-000030/II!ms WN22-MS-000030/II!ms
SYS-12  18.7.8 = 18.7.9 = = 18.7.10 = 18.7.8 - - -
SYS-13  18.4.2 = 18.7.8 = = = = 18.4.2 - - -
SYS-14  18.9.19.2,18.9.19.3 = - - - - - 18.9.19.2,18.9.19.3 - WN19-CC-000140/II WN22-CC-000140/II
SYS-15  5.1!dc = - 5.1!dc - 5.1!dc - - - - -
SYS-16  5.2/L2!ms = - 5.2/L2!ms - 5.2/L2!ms - - - - -
SYS-17  - - - - - - - - - - -
SYS-18  - - - - - - - - - - -
SYS-19  - - - - - - - - - - -
TLS-01  - - - - - - - - - - -
TLS-02  - - - - - - - - - - -
TLS-03  - - - - - - - - - - -
TLS-04  - - - - - - - - - - -
AUD-25  17.1.2!dc = - 17.1.2!dc - 17.1.2!dc - - - - -
AUD-26  17.1.3!dc = - 17.1.3!dc - 17.1.3!dc - - - - -
AUD-27  17.2.2!dc = - 17.2.2!dc - 17.2.2!dc - - - WN19-DC-000230/II!dc WN22-DC-000230/II!dc
AUD-28  17.2.4!dc = - 17.2.4!dc - 17.2.4!dc - - - WN19-AU-000090/II WN22-AU-000090/II
AUD-29  17.4.1!dc = - 17.4.1!dc - 17.4.1!dc - - - WN19-DC-000240/II!dc WN22-DC-000240/II!dc
AUD-30  17.4.2!dc = - 17.4.2!dc - 17.4.2!dc - - - - WN22-DC-000260/II!dc
CIS-001 - - 1.1.2 = = = = - - WN19-AC-000050/II WN22-AC-000050/II
CIS-002 - - 1.1.3 = = = = - - WN19-AC-000060/II WN22-AC-000060/II
CIS-003 - - - 1.1.6!ms 1.1.6 1.1.6!ms 1.1.6 - - - -
CIS-004 - - - 2.2.5!dc - 2.2.5!dc - - - WN19-DC-000350/II!dc WN22-DC-000350/II!dc
CIS-005 - - 2.2.4 2.2.6 2.2.4 2.2.6 2.2.4 - - - -
CIS-006 - - - 2.2.9!dc - 2.2.9!dc - - - WN19-DC-000360/II!dc WN22-DC-000360/II!dc
CIS-007 - - 2.2.6 2.2.10!ms 2.2.6 2.2.10!ms 2.2.6 - - WN19-DC-000360/II!dc WN22-DC-000360/II!dc
CIS-008 - - 2.2.8 2.2.12 2.2.8 2.2.12 2.2.8 - - - -
CIS-009 - - 2.2.9 2.2.13 2.2.9 2.2.13 2.2.9 - - WN19-UR-000050/II WN22-UR-000050/II
CIS-010 - - 2.2.11 2.2.15 2.2.11 2.2.15 2.2.11 - - WN19-UR-000070/II WN22-UR-000070/II
CIS-011 - - - 2.2.17!dc - 2.2.17!dc - - - WN19-UR-000090/II!ms,WN19-UR-000090/II!dc WN22-UR-000090/II
CIS-012 - - 2.2.13 2.2.18!ms 2.2.13 2.2.18!ms 2.2.13 - - WN19-UR-000090/II!ms,WN19-UR-000090/II!dc WN22-UR-000090/II
CIS-013 - - 2.2.16 2.2.22 2.2.16 2.2.22 2.2.16 - - WN19-DC-000380/II!dc,WN19-MS-000090/II!ms WN22-DC-000380/II,WN22-MS-000090/II!ms
CIS-014 - - 2.2.17 2.2.23 2.2.17 2.2.23 2.2.17 - - WN19-DC-000390/II!dc,WN19-MS-000100/II!ms WN22-DC-000390/II!dc,WN22-MS-000100/II!ms
CIS-015 - - 2.2.18 2.2.24 2.2.18 2.2.24 2.2.18 - - WN19-DC-000400/II!dc,WN19-MS-000110/II!ms WN22-DC-000400/II!dc,WN22-MS-000110/II!ms
CIS-016 - - 2.2.21 2.2.29 2.2.21 2.2.29 2.2.21 - - WN19-UR-000110/II WN22-UR-000110/II
CIS-017 - - - - - 2.2.30 2.2.22 - - WN19-UR-000120/II WN22-UR-000120/II
CIS-018 - - - - - 2.2.31!dc,2.2.32!ms 2.2.23 - - WN19-UR-000130/II!dc,WN19-UR-000130/II!ms WN22-UR-000130/II!dc,WN22-UR-000130/II!ms
CIS-019 - - 2.2.24 2.2.33 2.2.24 2.2.33 2.2.24 - - WN19-UR-000140/II WN22-UR-000140/II
CIS-020 - - 2.2.28 2.2.39 2.2.28 2.2.39 2.2.28 - - - -
CIS-021 - - 2.2.30 2.2.41 2.2.30 2.2.41 2.2.30 - - WN19-UR-000190/II WN22-UR-000190/II
CIS-022 - - 2.2.31 2.2.42 2.2.31 2.2.42 2.2.31 - - WN19-UR-000200/II WN22-UR-000200/II
CIS-023 - - 2.2.32 2.2.43 2.2.32 2.2.43 2.2.32 - - - -
CIS-024 - - 2.2.33 2.2.44 2.2.33 2.2.44 2.2.33 - - - -
CIS-025 - - 2.2.35 2.2.46 2.2.35 2.2.46 2.2.35 - - - -
CIS-026 - - - 2.2.47!dc - 2.2.47!dc - - - - -
CIS-027 - - 2.3.1.3 = = = = - - WN19-SO-000030/II WN22-SO-000030/II
CIS-028 - - 2.3.1.4 = = = = - - WN19-SO-000040/II WN22-SO-000040/II
CIS-029 - - 2.3.2.2 = = = = - - - -
CIS-030 - - 2.3.4.1 = = = = - - - -
CIS-031 - - - 2.3.5.1!dc - 2.3.5.1!dc - - - - -
CIS-032 - - - 2.3.5.2!dc - 2.3.5.2!dc - - - - -
CIS-033 - - - 2.3.5.3!dc - 2.3.5.3!dc - - - - -
CIS-034 - - - - - 2.3.5.4!dc - - - - -
CIS-035 - - - 2.3.5.5!dc - 2.3.5.5!dc - - - WN19-DC-000330/II!dc WN22-DC-000330/II!dc
CIS-036 - - 2.3.6.1 = - 2.3.6.1 - - - WN19-SO-000060/II WN22-SO-000060/II
CIS-037 - - 2.3.6.2 = - 2.3.6.2 - - - WN19-SO-000070/II WN22-SO-000070/II
CIS-038 - - 2.3.6.3 = - 2.3.6.3 - - - WN19-SO-000080/II WN22-SO-000080/II
CIS-039 - - 2.3.6.4 = - 2.3.6.4 - - - WN19-SO-000090/II WN22-SO-000090/II
CIS-040 - - 2.3.6.5 = - 2.3.6.5 - - - WN19-SO-000100/II WN22-SO-000100/II
CIS-041 - - 2.3.6.6 = - 2.3.6.6 - - - WN19-SO-000110/II WN22-SO-000110/II
CIS-042 - - 2.3.7.2 = = = = - - - -
CIS-043 - - 2.3.7.4 = = = = - - WN19-SO-000130/II WN22-SO-000130/II
CIS-044 - - 2.3.7.5 = = = = - - WN19-SO-000140/III WN22-SO-000140/II
CIS-045 - - 2.3.7.7 = 2.3.7.6 2.3.7.7 2.3.7.6 - - - -
CIS-046 - - 2.3.7.8 2.3.7.8!ms - 2.3.7.8!ms - - - - -
CIS-047 - - 2.3.9.1 = = = = - - - -
CIS-048 - - 2.3.9.3 = = = = - - - -
CIS-049 - - 2.3.9.4 2.3.9.4!ms 2.3.9.4 2.3.9.4!ms 2.3.9.4 - - - -
CIS-050 - - 2.3.10.5 = = = = - - WN19-SO-000240/II WN22-SO-000240/II
CIS-051 - - - 2.3.10.6!dc - 2.3.10.6!dc - - - - -
CIS-052 - - 2.3.10.6 2.3.10.7!ms 2.3.10.6 2.3.10.7!ms 2.3.10.6 - - - -
CIS-053 - - 2.3.10.7 2.3.10.8 2.3.10.7 2.3.10.8 2.3.10.7 - - - -
CIS-054 - - 2.3.10.8 2.3.10.9 2.3.10.8 2.3.10.9 2.3.10.8 - - - -
CIS-055 - - 2.3.10.11 2.3.10.12 2.3.10.11 2.3.10.12 2.3.10.11 - - - -
CIS-056 - - 2.3.10.12 2.3.10.13 2.3.10.12 2.3.10.13 2.3.10.12 - - - -
CIS-057 - - 2.3.11.1 = = = = - - WN19-SO-000260/II WN22-SO-000260/II
CIS-058 - - 2.3.11.3 = = = = - - WN19-SO-000280/II WN22-SO-000280/II
CIS-059 - - 2.3.11.4 = = = = - - WN19-SO-000290/II WN22-SO-000290/II
CIS-060 - - - - - 2.3.11.7 = - - - -
CIS-061 - - - 2.3.11.12!dc - 2.3.11.12!dc - - - - -
CIS-062 - - 2.3.13.1 = = = = - - - -
CIS-063 - - 2.3.15.1 = = = = - - - -
CIS-064 - - 2.3.17.7 = = = = - - - -
CIS-065 - - 9.1.3 = - 9.1.3 - - - - -
CIS-066 - - 9.1.4 = - 9.1.4 - - - - -
CIS-067 - - 9.1.5 = - 9.1.5 - - - WNFWA-000009/III =
CIS-068 - - 9.2.3 = = = = - - - -
CIS-069 - - 9.2.4 = = = = - - - -
CIS-070 - - 9.2.5 = = = = - - WNFWA-000017/III =
CIS-071 - - 9.3.3 = = = = - - - -
CIS-072 - - 9.3.4 = - 9.3.4 - - - WNFWA-000024/II =
CIS-073 - - 9.3.5 = - 9.3.5 - - - WNFWA-000025/II =
CIS-074 - - 9.3.6 = 9.3.4 9.3.6 9.3.4 - - - -
CIS-075 - - 9.3.7 = 9.3.5 9.3.7 9.3.5 - - WNFWA-000027/III =
CIS-076 - - 17.2.1 = = = = - - - -
CIS-077 - - - 17.2.3!dc - 17.2.3!dc - - - - -
CIS-078 - - 17.5.3 = = = = - - WN19-AU-000180/II WN22-AU-000180/II
CIS-079 - - 17.9.1 = = = = - - WN19-AU-000320/II WN22-AU-000320/II
CIS-080 - - 18.1.1.1 = = = = - - - WN22-CC-000010/II
CIS-081 - - 18.1.1.2 = = = = - - WN19-CC-000010/II -
CIS-082 - - 18.1.2.2 = = = = - - - -
CIS-083 - - 18.4.4 = 18.4.3 18.4.4 18.4.3 - - - -
CIS-084 - - 18.5.1 = = = = - - - -
CIS-085 - - 18.5.8 = = = = - - - -
CIS-086 - - 18.5.11 = = = = - - - -
CIS-087 - - 18.6.4.1 = = = = - - - -
CIS-088 - - - 18.6.8.2 = 18.6.8.7 = - - - -
CIS-089 - - 18.6.11.2 = = = = - - - -
CIS-090 - - 18.6.11.3 = = = = - - - -
CIS-091 - - 18.6.11.4 = - 18.6.11.4 - - - - -
CIS-092 - - 18.6.21.1 = = = = - - - -
CIS-093 - - 18.7.1 = = = = - - - -
CIS-094 - - 18.7.2 = = = = - - - -
CIS-095 - - 18.7.3 = = = = - - - -
CIS-096 - - 18.7.4 = = = = - - - -
CIS-097 - - 18.7.5 = = = = - - - -
CIS-098 - - 18.7.6 = = = = - - - -
CIS-099 - - 18.7.7 = = = = - - - -
CIS-100 - - 18.7.10 = = 18.7.11 = - - - -
CIS-101 - - 18.7.11 = = 18.7.12 = - - - -
CIS-102 - - 18.7.12 = = 18.7.13 = - - - -
CIS-103 - - 18.9.7.2 = = = = - - - -
CIS-104 - - 18.9.17.1 = = = = - - - -
CIS-105 - - 18.9.19.2 = - 18.9.19.2 - - - - -
CIS-106 - - 18.9.19.3 = - 18.9.19.3 - - - - -
CIS-107 - - 18.9.19.4 = 18.9.19.2 18.9.19.4 18.9.19.2 - - - -
CIS-108 - - 18.9.19.5 = - 18.9.19.5 - - - - -
CIS-109 - - 18.9.20.1.1 = = = = - - WN19-CC-000150/II WN22-CC-000150/II
CIS-110 - - 18.9.20.1.5 = = = = - - - -
CIS-111 - - - 18.9.26.2!ms - 18.9.26.2!ms - - - - -
CIS-112 - - - 18.9.26.3!ms - 18.9.26.3!ms - - - - -
CIS-113 - - - - - 18.9.26.4!ms - - - - -
CIS-114 - - - 18.9.26.5!ms - 18.9.26.5!ms - - - - -
CIS-115 - - - 18.9.26.6!ms - 18.9.26.6!ms - - - - WN22-00-000020/II
CIS-116 - - - 18.9.26.7!ms - 18.9.26.7!ms - - - - -
CIS-117 - - - 18.9.26.8!ms - 18.9.26.8!ms - - - - -
CIS-118 - - - 18.9.27.1!dc - 18.9.27.1!dc - - - - -
CIS-119 - - 18.9.29.1 = = = = - - - -
CIS-120 - - 18.9.29.2 = = = = - - WN19-CC-000170/II WN22-CC-000170/II
CIS-121 - - 18.9.29.3 = - 18.9.29.3 - - - - -
CIS-122 - - 18.9.29.5 = 18.9.29.3 18.9.29.5 18.9.29.3 - - - -
CIS-123 - - 18.9.29.6 = 18.9.29.4 18.9.29.6 18.9.29.4 - - - -
CIS-124 - - - - - 18.9.31.1.1 - - - - -
CIS-125 - - 18.9.35.6.3 = = = = - - WN19-CC-000180/II WN22-CC-000180/II
CIS-126 - - 18.9.35.6.4 = = = = - - WN19-CC-000190/II WN22-CC-000190/II
CIS-127 - - 18.9.37.1 = = = = - - - -
CIS-128 - - 18.9.38.1 18.9.38.1!ms 18.9.38.1 18.9.38.1!ms 18.9.38.1 - - - -
CIS-129 - - - - - 18.9.41.1!dc - - - - -
CIS-130 - - - - - 18.9.41.2!ms 18.9.41.1 - - - -
CIS-131 - - - 18.9.41.1!dc - 18.9.41.3!dc - - - - -
CIS-132 - - 18.9.53.1.1 = = = = - - - -
CIS-133 - - 18.9.53.1.2 18.9.53.1.2!ms - 18.9.53.1.2!ms - - - - -
CIS-134 - - - - - 18.10.4.2 = - - - -
CIS-135 - - 18.10.6.1 = = = = - - - -
CIS-136 - - 18.10.9.1.1 = = = = - - - -
CIS-137 - - 18.10.13.1 = = = = - - - -
CIS-138 - - 18.10.14.1 = = = = - - - -
CIS-139 - - 18.10.15.1 = = = = - - - -
CIS-140 - - 18.10.15.2 = = = = - - WN19-CC-000240/II WN22-CC-000240/II
CIS-141 - - 18.10.16.1 = = = = - - WN19-CC-000250/II WN22-CC-000250/II
CIS-142 - - 18.10.16.3 = = = = - - - -
CIS-143 - - 18.10.18.2 = = = = - - - -
CIS-144 - - 18.10.18.3 = = = = - - - -
CIS-145 - - 18.10.18.4 = = = = - - - -
CIS-146 - - 18.10.18.5 = 18.10.18.6 18.10.18.5 = - - - -
CIS-147 - - 18.10.18.6 = 18.10.18.5 18.10.18.6 = - - - -
CIS-148 - - 18.10.26.1.1 = = = = - - - -
CIS-149 - - 18.10.26.2.1 = = = = - - - -
CIS-150 - - 18.10.26.3.1 = = = = - - - -
CIS-151 - - 18.10.26.4.1 = = = = - - - -
CIS-152 - - 18.10.29.3 = = = = - - WN19-CC-000310/II WN22-CC-000310/II
CIS-153 - - 18.10.29.4 = = = = - - WN19-CC-000320/III WN22-CC-000320/III
CIS-154 - - 18.10.29.5 = = = = - - WN19-CC-000330/II WN22-CC-000330/II
CIS-155 - - 18.10.41.1 = = = = - - - -
CIS-156 - - 18.10.57.3.9.3 = = = = - - - -
CIS-157 - - 18.10.57.3.10.1 = = = = - - - -
CIS-158 - - 18.10.57.3.11.1 = = = = - - - -
CIS-159 - - 18.10.57.3.11.2 = = = = - - - -
CIS-160 - - 18.10.58.1 = = = = - - WN19-CC-000390/II WN22-CC-000390/II
CIS-161 - - 18.10.81.2 = = = = - - - -
CIS-162 - - - 18.10.83.1 = = = - - - -
CIS-163 - - 18.10.93.2.1 = = = = - - - -
CIS-164 - - 18.10.94.1.1 = = = = - - - -
CIS-165 - - 18.10.94.2.1 = = = = - - - -
CIS-166 - - 18.10.94.2.2 = = = = - - - -
CIS-167 - - 18.10.94.4.1 = = = = - - - -
CIS-168 - - 18.10.94.4.2 = = = = - - - -
CIS-169 - - 18.11.1 = = = = - - - -
CIS-170 - - - 18.11.2 = = = - - - -
CIS-171 - - 2.2.22 2.2.30 2.2.22 - - - - WN19-UR-000120/II WN22-UR-000120/II
CIS-172 - - 2.2.23 2.2.31!dc,2.2.32!ms 2.2.23 - - - - WN19-UR-000130/II!dc,WN19-UR-000130/II!ms WN22-UR-000130/II!dc,WN22-UR-000130/II!ms
CIS-173 - - - 2.3.5.4!dc - - - - - WN19-DC-000320/II!dc WN22-DC-000320/II!dc
CIS-174 - - - 18.9.26.4!ms - - - - - - -
CIS-175 - - 18.10.58.2 = = - - - - WN19-CC-000400/II WN22-CC-000400/II
CIS-176 - - - - - - - - 1.4.1 - -
CIS-177 - - - - - - - - 1.5.1 - -
CIS-178 - - - - - - - - 1.6.1.1 - -
CIS-179 - - - - - - - - 1.6.1.7 - -
CIS-180 - - - - - - - - 1.6.1.14 - -
CIS-181 - - - - - - - - 1.7.1 - -
CIS-182 - - - - - - - - 1.10.1 - -
CIS-183 - - - - - - - - 1.10.2 - -
CIS-184 - - - - - - - - 1.10.3 - -
CIS-185 - - - - - - - - 1.10.7 - -
CIS-186 - - - - - - - - 1.11.1.1.2 - -
CIS-187 - - - - - - - - 1.11.1.2.2 - -
CIS-188 - - - - - - - - 1.12.2 - -
CIS-189 - - - - - - - - 1.13.1 - -
CIS-190 - - - - - - - - 1.13.2 - -
CIS-191 - - - - - - - - 1.13.3 - -
CIS-192 - - - - - - - - 1.13.4 - -
CIS-193 - - - - - - - - 1.13.6 - -
CIS-194 - - - - - - - - 1.13.7 - -
CIS-195 - - - - - - - - 1.13.8 - -
CIS-196 - - - - - - - - 1.13.9 - -
CIS-197 - - - - - - - - 1.13.10 - -
CIS-198 - - - - - - - - 1.13.11 - -
CIS-199 - - - - - - - - 1.14.1 - -
CIS-200 - - - - - - - - 1.15.1 - -
CIS-201 - - - - - - - - 1.15.2 - -
CIS-202 - - - - - - - - 1.15.3 - -
CIS-203 - - - - - - - - 1.15.4 - -
CIS-204 - - - - - - - - 1.17 - -
CIS-205 - - - - - - - - 1.18 - -
'@

# where CIS asks for another value than the check, which wants Microsoft's
$CisNotes = @{
    'ACC-05' = 'CIS allows up to 5 attempts; this check wants 3 or fewer, the Microsoft value.'
    'ACC-14' = 'CIS also accepts 2 (force logoff) and 3 (disconnect the Remote Desktop session); this check wants 1 (lock the workstation), the Microsoft value.'
    'LSA-09' = 'CIS wants 1 (LSA protection with UEFI lock); this check also accepts 2 (without the UEFI lock), as Microsoft does.'
    'SMB-08' = 'CIS wants SMB 3.1.1 (785) as the lowest version; this check accepts SMB 3.0 (768), as Microsoft does. 785 also blocks Windows 8.1, Server 2012 R2 and older.'
    'SYS-04' = 'CIS wants 3 (good, unknown, and bad but critical); this check also accepts 1 (good only) and 8 (good and unknown).'
    'UAC-02' = 'CIS also accepts 1 (ask for credentials); this check wants 2 (ask for consent), the Microsoft value.'
}

# the CIS benchmark for this Windows version, or $null (Windows 10, Server 2012 R2 and older);
# servers outside a domain get the Stand-alone benchmark where there is one
function Get-CisBenchmark($H) {
    if ($H.server) {
        $b = if ($H.build -ge 26100) { 'ws2025' } elseif ($H.build -ge 20348) { 'ws2022' }
             elseif ($H.build -ge 17763) { 'ws2019' } elseif ($H.build -ge 14393) { 'ws2016' } else { $null }
        if ($b -and -not $H.domain -and $CisBenchmarks.Contains("${b}sa")) { return "${b}sa" }
        return $b
    }
    if ($H.build -ge 22000) { return 'win11' }
    $null
}

# the DISA STIG for this Windows version (Server 2019 and 2022), or $null
function Get-StigBenchmark($H) {
    if (-not $H.server -or $H.build -ge 26100) { return $null }
    if ($H.build -ge 20348) { return 'stig2022' }
    if ($H.build -ge 17763) { return 'stig2019' }
    $null
}

# CIS Benchmark Level 1 recommendations that no check above covers, read from the same PDFs.
# Each runs only where the machine's benchmark lists it (see $CisTable), and is applied only
# with -Apply cis. A setting that is not configured counts as failed, as in a CIS audit.
#   id | kind | area | severity (from the DISA STIG category, else Low) | fix | title
#     reg:   path | value name | op | want | type | value to set
#     sec:   section | key | label | op | want | value to set
#     audit: subcategory | GUID | 1 success, 2 failure, 3 both
# want: a number, a..b (range), a,b (in), s:text, m:item;item (list)
$CisChecks = @'
CIS-001 | sec | CIS accounts | Medium | cis | Maximum password age = 365 or fewer days, but not 0
    System Access | MaximumPasswordAge | Maximum password age | range | 1..365 | 365
CIS-002 | sec | CIS accounts | Medium | cis | Minimum password age = 1 or more day(s)
    System Access | MinimumPasswordAge | Minimum password age | ge | 1
CIS-003 | reg | CIS accounts | Low | cis | Relax minimum password length limits = Enabled
    HKLM:\System\CurrentControlSet\Control\SAM | RelaxMinimumPasswordLengthLimits | eq | 1 | DWord
CIS-004 | sec | CIS user rights | Medium | cis | Add workstations to domain = Administrators
    Privilege Rights | SeMachineAccountPrivilege | Add workstations to domain | only | m:*S-1-5-32-544
CIS-005 | sec | CIS user rights | Low | cis | Adjust memory quotas for a process = Administrators, LOCAL SERVICE, NETWORK SERVICE
    Privilege Rights | SeIncreaseQuotaPrivilege | Adjust memory quotas for a process | only | m:*S-1-5-32-544;*S-1-5-19;*S-1-5-20
CIS-006 | sec | CIS user rights | Medium | manual | Allow log on through Remote Desktop Services = Administrators
    Privilege Rights | SeRemoteInteractiveLogonRight | Allow log on through Remote Desktop Services | only | m:*S-1-5-32-544
    how | Removes Remote Desktop access for everyone else. Check who logs on over Remote Desktop, then set it by hand or in a GPO.
CIS-007 | sec | CIS user rights | Medium | manual | Allow log on through Remote Desktop Services = Administrators, Remote Desktop Users
    Privilege Rights | SeRemoteInteractiveLogonRight | Allow log on through Remote Desktop Services | only | m:*S-1-5-32-544;*S-1-5-32-555
    how | Removes Remote Desktop access for everyone else. Check who logs on over Remote Desktop, then set it by hand or in a GPO.
CIS-008 | sec | CIS user rights | Low | cis | Change the system time = Administrators, LOCAL SERVICE
    Privilege Rights | SeSystemtimePrivilege | Change the system time | only | m:*S-1-5-32-544;*S-1-5-19
CIS-009 | sec | CIS user rights | Medium | cis | Create a pagefile = Administrators
    Privilege Rights | SeCreatePagefilePrivilege | Create a pagefile | only | m:*S-1-5-32-544
CIS-010 | sec | CIS user rights | Medium | cis | Create global objects = Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
    Privilege Rights | SeCreateGlobalPrivilege | Create global objects | only | m:*S-1-5-32-544;*S-1-5-19;*S-1-5-20;*S-1-5-6
CIS-011 | sec | CIS user rights | Medium | cis | Create symbolic links = Administrators
    Privilege Rights | SeCreateSymbolicLinkPrivilege | Create symbolic links | only | m:*S-1-5-32-544
CIS-012 | sec | CIS user rights | Medium | cis | Create symbolic links = Administrators, NT VIRTUAL MACHINE\Virtual Machines
    Privilege Rights | SeCreateSymbolicLinkPrivilege | Create symbolic links | only | m:*S-1-5-32-544;*S-1-5-83-0
CIS-013 | sec | CIS user rights | Medium | cis | Deny log on as a batch job includes Guests
    Privilege Rights | SeDenyBatchLogonRight | Deny log on as a batch job | has | m:*S-1-5-32-546
CIS-014 | sec | CIS user rights | Medium | cis | Deny log on as a service includes Guests
    Privilege Rights | SeDenyServiceLogonRight | Deny log on as a service | has | m:*S-1-5-32-546
CIS-015 | sec | CIS user rights | Medium | cis | Deny log on locally includes Guests
    Privilege Rights | SeDenyInteractiveLogonRight | Deny log on locally | has | m:*S-1-5-32-546
CIS-016 | sec | CIS user rights | Medium | cis | Force shutdown from a remote system = Administrators
    Privilege Rights | SeRemoteShutdownPrivilege | Force shutdown from a remote system | only | m:*S-1-5-32-544
CIS-017 | sec | CIS user rights | Medium | cis | Generate security audits = LOCAL SERVICE, NETWORK SERVICE, RESTRICTED SERVICES\PrintSpoolerService
    Privilege Rights | SeAuditPrivilege | Generate security audits | only | m:*S-1-5-19;*S-1-5-20;*S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229
CIS-018 | sec | CIS user rights | Medium | cis | Impersonate a client after authentication = Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, RESTRICTED SERVICES\PrintSpoolerService
    Privilege Rights | SeImpersonatePrivilege | Impersonate a client after authentication | only | m:*S-1-5-32-544;*S-1-5-19;*S-1-5-20;*S-1-5-6;*S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229
CIS-019 | sec | CIS user rights | Medium | cis | Increase scheduling priority = Administrators, Window Manager\Window Manager Group
    Privilege Rights | SeIncreaseBasePriorityPrivilege | Increase scheduling priority | only | m:*S-1-5-32-544;*S-1-5-90-0
CIS-020 | sec | CIS user rights | Low | cis | Modify an object label = No One
    Privilege Rights | SeRelabelPrivilege | Modify an object label | only | m:
CIS-021 | sec | CIS user rights | Medium | cis | Perform volume maintenance tasks = Administrators
    Privilege Rights | SeManageVolumePrivilege | Perform volume maintenance tasks | only | m:*S-1-5-32-544
CIS-022 | sec | CIS user rights | Medium | cis | Profile single process = Administrators
    Privilege Rights | SeProfileSingleProcessPrivilege | Profile single process | only | m:*S-1-5-32-544
CIS-023 | sec | CIS user rights | Low | cis | Profile system performance = Administrators, NT SERVICE\WdiServiceHost
    Privilege Rights | SeSystemProfilePrivilege | Profile system performance | only | m:*S-1-5-32-544;*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
CIS-024 | sec | CIS user rights | Low | cis | Replace a process level token = LOCAL SERVICE, NETWORK SERVICE
    Privilege Rights | SeAssignPrimaryTokenPrivilege | Replace a process level token | only | m:*S-1-5-19;*S-1-5-20
CIS-025 | sec | CIS user rights | Low | cis | Shut down the system = Administrators
    Privilege Rights | SeShutdownPrivilege | Shut down the system | only | m:*S-1-5-32-544
CIS-026 | sec | CIS user rights | Low | cis | Synchronize directory service data = No One
    Privilege Rights | SeSyncAgentPrivilege | Synchronize directory service data | only | m:
CIS-027 | sec | CIS security options | Medium | manual | Configure Accounts: Rename administrator account
    System Access | NewAdministratorName | Accounts: Rename administrator account | ne | s:Administrator
    how | Rename the built-in Administrator account (Local Security Policy > Security Options > Accounts: Rename administrator account, or a GPO).
CIS-028 | sec | CIS security options | Medium | manual | Configure Accounts: Rename guest account
    System Access | NewGuestName | Accounts: Rename guest account | ne | s:Guest
    how | Rename the built-in Guest account (Local Security Policy > Security Options > Accounts: Rename guest account, or a GPO).
CIS-029 | reg | CIS security options | Low | cis | Audit: Shut down system immediately if unable to log security audits = Disabled
    HKLM:\System\CurrentControlSet\Control\Lsa | CrashOnAuditFail | eq | 0 | DWord
CIS-030 | reg | CIS security options | Low | cis | Devices: Prevent users from installing printer drivers = Enabled
    HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers | AddPrinterDrivers | eq | 1 | DWord
CIS-031 | reg | CIS security options | Low | cis | Domain controller: Allow server operators to schedule tasks = Disabled
    HKLM:\System\CurrentControlSet\Control\Lsa | SubmitControl | eq | 0 | DWord
CIS-032 | reg | CIS security options | Low | cis | Domain controller: Allow vulnerable Netlogon secure channel connections = Not Configured
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | VulnerableChannelAllowList | absent |  | String
CIS-033 | reg | CIS security options | Low | cis | Domain controller: LDAP server channel binding token requirements = Always
    HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters | LdapEnforceChannelBinding | eq | 2 | DWord
CIS-034 | reg | CIS security options | Low | cis | Domain controller: LDAP server signing requirements Enforcement = Enabled
    HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters | LDAPServerEnforceIntegrity | eq | 1 | DWord
CIS-035 | reg | CIS security options | Medium | cis | Domain controller: Refuse machine account password changes = Disabled
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | RefusePasswordChange | eq | 0 | DWord
CIS-036 | reg | CIS security options | Medium | cis | Domain member: Digitally encrypt or sign secure channel data (always) = Enabled
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | RequireSignOrSeal | eq | 1 | DWord
CIS-037 | reg | CIS security options | Medium | cis | Domain member: Digitally encrypt secure channel data (when possible) = Enabled
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | SealSecureChannel | eq | 1 | DWord
CIS-038 | reg | CIS security options | Medium | cis | Domain member: Digitally sign secure channel data (when possible) = Enabled
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | SignSecureChannel | eq | 1 | DWord
CIS-039 | reg | CIS security options | Medium | cis | Domain member: Disable machine account password changes = Disabled
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | DisablePasswordChange | eq | 0 | DWord
CIS-040 | reg | CIS security options | Medium | cis | Domain member: Maximum machine account password age = 30 or fewer days, but not 0
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | MaximumPasswordAge | range | 1..30 | DWord | 30
CIS-041 | reg | CIS security options | Medium | cis | Domain member: Require strong (Windows 2000 or later) session key = Enabled
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | RequireStrongKey | eq | 1 | DWord
CIS-042 | reg | CIS security options | Low | cis | Interactive logon: Don't display last signed-in = Enabled
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | DontDisplayLastUserName | eq | 1 | DWord
CIS-043 | reg | CIS security options | Medium | manual | Configure Interactive logon: Message text for users attempting to log on
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | LegalNoticeText | set |  | String
    how | Set the logon message text your organisation uses (Security Options > Interactive logon: Message text for users attempting to log on).
CIS-044 | reg | CIS security options | Medium | manual | Configure Interactive logon: Message title for users attempting to log on
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | LegalNoticeCaption | set |  | String
    how | Set the logon message title your organisation uses (Security Options > Interactive logon: Message title for users attempting to log on).
CIS-045 | reg | CIS security options | Low | cis | Interactive logon: Prompt user to change password before expiration = between 5 and 14 days
    HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | PasswordExpiryWarning | range | 5..14 | DWord | 14
CIS-046 | reg | CIS security options | Low | cis | Interactive logon: Require Domain Controller Authentication to unlock workstation = Enabled
    HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | ForceUnlockLogon | eq | 1 | DWord
CIS-047 | reg | CIS security options | Low | cis | Microsoft network server: Amount of idle time required before suspending session = 15 or fewer minute(s)
    HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters | AutoDisconnect | le | 15 | DWord | 15
CIS-048 | reg | CIS security options | Low | cis | Microsoft network server: Disconnect clients when logon hours expire = Enabled
    HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters | enableforcedlogoff | eq | 1 | DWord
CIS-049 | reg | CIS security options | Low | cis | Microsoft network server: Server SPN target name validation level = Accept if provided by client or higher
    HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters | SMBServerNameHardeningLevel | in | 1,2 | DWord | 1
CIS-050 | reg | CIS security options | Medium | cis | Network access: Let Everyone permissions apply to anonymous users = Disabled
    HKLM:\System\CurrentControlSet\Control\Lsa | EveryoneIncludesAnonymous | eq | 0 | DWord
CIS-051 | reg | CIS security options | Low | cis | Configure Network access: Named Pipes that can be accessed anonymously (NullSessionPipes) on domain controllers
    HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters | NullSessionPipes | subset | m:LSARPC;NETLOGON;SAMR | MultiString | m:LSARPC;NETLOGON;SAMR
CIS-052 | reg | CIS security options | Low | cis | Configure Network access: Named Pipes that can be accessed anonymously (NullSessionPipes) on other servers
    HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters | NullSessionPipes | subset | m:BROWSER | MultiString | m:
CIS-053 | reg | CIS security options | Low | cis | Configure Network access: Remotely accessible registry paths
    HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths | Machine | subset | m:System\CurrentControlSet\Control\ProductOptions;System\CurrentControlSet\Control\Server Applications;Software\Microsoft\Windows NT\CurrentVersion | MultiString | m:System\CurrentControlSet\Control\ProductOptions;System\CurrentControlSet\Control\Server Applications;Software\Microsoft\Windows NT\CurrentVersion
CIS-054 | reg | CIS security options | Low | cis | Configure Network access: Remotely accessible registry paths and sub-paths
    HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths | Machine | subset | m:System\CurrentControlSet\Control\Print\Printers;System\CurrentControlSet\Services\Eventlog;Software\Microsoft\OLAP Server;Software\Microsoft\Windows NT\CurrentVersion\Print;Software\Microsoft\Windows NT\CurrentVersion\Windows;System\CurrentControlSet\Control\ContentIndex;System\CurrentControlSet\Control\Terminal Server;System\CurrentControlSet\Control\Terminal Server\UserConfig;System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration;Software\Microsoft\Windows NT\CurrentVersion\Perflib;System\CurrentControlSet\Services\SysmonLog;System\CurrentControlSet\Services\CertSvc;System\CurrentControlSet\Services\WINS | MultiString | m:System\CurrentControlSet\Control\Print\Printers;System\CurrentControlSet\Services\Eventlog;Software\Microsoft\OLAP Server;Software\Microsoft\Windows NT\CurrentVersion\Print;Software\Microsoft\Windows NT\CurrentVersion\Windows;System\CurrentControlSet\Control\ContentIndex;System\CurrentControlSet\Control\Terminal Server;System\CurrentControlSet\Control\Terminal Server\UserConfig;System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration;Software\Microsoft\Windows NT\CurrentVersion\Perflib;System\CurrentControlSet\Services\SysmonLog;System\CurrentControlSet\Services\CertSvc;System\CurrentControlSet\Services\WINS
CIS-055 | reg | CIS security options | Low | cis | Network access: Shares that can be accessed anonymously = None
    HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters | NullSessionShares | subset | m: | MultiString | m:
CIS-056 | reg | CIS security options | Low | cis | Network access: Sharing and security model for local accounts = Classic - local users authenticate as themselves
    HKLM:\System\CurrentControlSet\Control\Lsa | ForceGuest | eq | 0 | DWord
CIS-057 | reg | CIS security options | Medium | cis | Network security: Allow Local System to use computer identity for NTLM = Enabled
    HKLM:\System\CurrentControlSet\Control\Lsa | UseMachineId | eq | 1 | DWord
CIS-058 | reg | CIS security options | Medium | cis | Network Security: Allow PKU2U authentication requests to this computer to use online identities = Disabled
    HKLM:\System\CurrentControlSet\Control\Lsa\pku2u | AllowOnlineID | eq | 0 | DWord
CIS-059 | reg | CIS security options | Medium | cis | Network security: Configure encryption types allowed for Kerberos = AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters | SupportedEncryptionTypes | eq | 2147483640 | DWord
CIS-060 | reg | CIS security options | Low | cis | Network security: LDAP client encryption requirements = Negotiate sealing or higher
    HKLM:\System\CurrentControlSet\Services\LDAP | LDAPClientConfidentiality | in | 1,2 | DWord | 1
CIS-061 | reg | CIS security options | Low | cis | Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all
    HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters | AuditNTLMInDomain | eq | 7 | DWord
CIS-062 | reg | CIS security options | Low | cis | Shutdown: Allow system to be shut down without having to log on = Disabled
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | ShutdownWithoutLogon | eq | 0 | DWord
CIS-063 | reg | CIS security options | Low | cis | System objects: Require case insensitivity for non-Windows subsystems = Enabled
    HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel | ObCaseInsensitive | eq | 1 | DWord
CIS-064 | reg | CIS security options | Low | cis | User Account Control: Switch to the secure desktop when prompting for elevation = Enabled
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | PromptOnSecureDesktop | eq | 1 | DWord
CIS-065 | reg | CIS firewall | Low | cis | Windows Firewall: Domain: Settings: Display a notification = No
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile | DisableNotifications | eq | 1 | DWord
CIS-066 | reg | CIS firewall | Low | cis | Configure Windows Firewall: Domain: Logging: Name
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging | LogFilePath | eq | s:%SystemRoot%\System32\logfiles\firewall\domainfw.log | String
CIS-067 | reg | CIS firewall | Low | cis | Windows Firewall: Domain: Logging: Size limit (KB) = 16,384 KB or greater
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging | LogFileSize | ge | 16384 | DWord | 16384
CIS-068 | reg | CIS firewall | Low | cis | Windows Firewall: Private: Settings: Display a notification = No
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile | DisableNotifications | eq | 1 | DWord
CIS-069 | reg | CIS firewall | Low | cis | Configure Windows Firewall: Private: Logging: Name
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging | LogFilePath | eq | s:%SystemRoot%\System32\logfiles\firewall\privatefw.log | String
CIS-070 | reg | CIS firewall | Low | cis | Windows Firewall: Private: Logging: Size limit (KB) = 16,384 KB or greater
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging | LogFileSize | ge | 16384 | DWord | 16384
CIS-071 | reg | CIS firewall | Low | cis | Windows Firewall: Public: Settings: Display a notification = No
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | DisableNotifications | eq | 1 | DWord
CIS-072 | reg | CIS firewall | Medium | manual | Windows Firewall: Public: Settings: Apply local firewall rules = No
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | AllowLocalPolicyMerge | eq | 0 | DWord
    how | Makes the Public profile ignore firewall rules created on this machine. Define the rules it needs in a GPO first.
CIS-073 | reg | CIS firewall | Medium | manual | Windows Firewall: Public: Settings: Apply local connection security rules = No
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile | AllowLocalIPsecPolicyMerge | eq | 0 | DWord
    how | Makes the Public profile ignore firewall rules created on this machine. Define the rules it needs in a GPO first.
CIS-074 | reg | CIS firewall | Low | cis | Configure Windows Firewall: Public: Logging: Name
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging | LogFilePath | eq | s:%SystemRoot%\System32\logfiles\firewall\publicfw.log | String
CIS-075 | reg | CIS firewall | Low | cis | Windows Firewall: Public: Logging: Size limit (KB) = 16,384 KB or greater
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging | LogFileSize | ge | 16384 | DWord | 16384
CIS-076 | audit | CIS audit | Low | cis | Audit Application Group Management = Success and Failure
    Application Group Management | {0cce9239-69ae-11d9-bed3-505054503030} | 3
CIS-077 | audit | CIS audit | Low | cis | Audit Distribution Group Management = include Success
    Distribution Group Management | {0cce9238-69ae-11d9-bed3-505054503030} | 1
CIS-078 | audit | CIS audit | Medium | cis | Audit Logoff = include Success
    Logoff | {0cce9216-69ae-11d9-bed3-505054503030} | 1
CIS-079 | audit | CIS audit | Medium | cis | Audit IPsec Driver = Success and Failure
    IPsec Driver | {0cce9213-69ae-11d9-bed3-505054503030} | 3
CIS-080 | reg | CIS admin templates | Medium | cis | Prevent enabling lock screen camera = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization | NoLockScreenCamera | eq | 1 | DWord
CIS-081 | reg | CIS admin templates | Medium | cis | Prevent enabling lock screen slide show = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization | NoLockScreenSlideshow | eq | 1 | DWord
CIS-082 | reg | CIS admin templates | Low | cis | Allow users to enable online speech recognition services = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization | AllowInputPersonalization | eq | 0 | DWord
CIS-083 | reg | CIS admin templates | Low | cis | Enable Certificate Padding = Enabled
    HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config | EnableCertPaddingCheck | eq | s:1 | String
    HKLM:\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config | EnableCertPaddingCheck | eq | s:1 | String
CIS-084 | reg | CIS admin templates | Low | cis | MSS: (AutoAdminLogon) Enable Automatic Logon = Disabled
    HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | AutoAdminLogon | eq | s:0 | String
CIS-085 | reg | CIS admin templates | Low | cis | MSS: (SafeDllSearchMode) Enable Safe DLL search mode = Enabled
    HKLM:\System\CurrentControlSet\Control\Session Manager | SafeDllSearchMode | eq | 1 | DWord
CIS-086 | reg | CIS admin templates | Low | cis | MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning = 90% or less
    HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security | WarningLevel | le | 90 | DWord | 90
CIS-087 | reg | CIS admin templates | Low | cis | Configure multicast DNS (mDNS) protocol = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient | EnableMDNS | eq | 0 | DWord
CIS-088 | reg | CIS admin templates | Low | cis | Require Encryption = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation | RequireEncryption | eq | 1 | DWord
CIS-089 | reg | CIS admin templates | Low | cis | Prohibit installation and configuration of Network Bridge on your DNS domain network = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections | NC_AllowNetBridge_NLA | eq | 0 | DWord
CIS-090 | reg | CIS admin templates | Low | cis | Prohibit use of Internet Connection Sharing on your DNS domain network = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections | NC_ShowSharedAccessUI | eq | 0 | DWord
CIS-091 | reg | CIS admin templates | Low | cis | Require domain users to elevate when setting a network's location = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections | NC_StdDomainUserSetLocation | eq | 1 | DWord
CIS-092 | reg | CIS admin templates | Low | cis | Minimize the number of simultaneous connections to the Internet or a Windows Domain = 3 = Prevent Wi-Fi when on Ethernet
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy | fMinimizeConnections | eq | 3 | DWord
CIS-093 | reg | CIS admin templates | Low | manual | Allow Print Spooler to accept client connections = Disabled
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers | RegisterSpoolerRemoteRpcEndPoint | eq | 2 | DWord
    how | Stops printer sharing. Leave it on print servers; set it on the other servers by hand or in a GPO.
CIS-094 | reg | CIS admin templates | Low | cis | Configure Redirection Guard = Redirection Guard Enabled
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers | RedirectionguardPolicy | eq | 1 | DWord
CIS-095 | reg | CIS admin templates | Low | cis | Configure RPC connection settings: Protocol to use for outgoing RPC connections = RPC over TCP
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC | RpcUseNamedPipeProtocol | eq | 0 | DWord
CIS-096 | reg | CIS admin templates | Low | cis | Configure RPC connection settings: Use authentication for outgoing RPC connections = Default
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC | RpcAuthentication | eq | 0 | DWord
CIS-097 | reg | CIS admin templates | Low | cis | Configure RPC listener settings: Protocols to allow for incoming RPC connections = RPC over TCP
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC | RpcProtocols | eq | 5 | DWord
CIS-098 | reg | CIS admin templates | Low | cis | Configure RPC listener settings: Authentication protocol to use for incoming RPC connections: = Negotiate or higher
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC | ForceKerberosForRpc | in | 0,1 | DWord | 0
CIS-099 | reg | CIS admin templates | Low | cis | Configure RPC over TCP port = 0
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC | RpcTcpPort | eq | 0 | DWord
CIS-100 | reg | CIS admin templates | Low | cis | Manage processing of Queue-specific files = Limit Queue-specific files to Color profiles
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers | CopyFilesPolicy | eq | 1 | DWord
CIS-101 | reg | CIS admin templates | Low | cis | Point and Print Restrictions: When installing drivers for a new connection = Show warning and elevation prompt
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint | NoWarningNoElevationOnInstall | eq | 0 | DWord
CIS-102 | reg | CIS admin templates | Low | cis | Point and Print Restrictions: When updating drivers for an existing connection = Show warning and elevation prompt
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint | UpdatePromptSettings | eq | 0 | DWord
CIS-103 | reg | CIS admin templates | Low | cis | Prevent automatic download of applications associated with device metadata = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata | PreventDeviceMetadataFromNetwork | eq | 1 | DWord
CIS-104 | reg | CIS admin templates | Low | cis | Enable / disable CLFS logfile authentication = Enabled
    HKLM:\SYSTEM\CurrentControlSet\Policies | ClfsAuthenticationChecking | eq | 1 | DWord
CIS-105 | reg | CIS admin templates | Low | cis | Configure security policy processing: Do not apply during periodic background processing = FALSE
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A} | NoBackgroundPolicy | eq | 0 | DWord
CIS-106 | reg | CIS admin templates | Low | cis | Configure security policy processing: Process even if the Group Policy objects have not changed = TRUE
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A} | NoGPOListChanges | eq | 0 | DWord
CIS-107 | reg | CIS admin templates | Low | cis | Continue experiences on this device = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\System | EnableCdp | eq | 0 | DWord
CIS-108 | reg | CIS admin templates | Low | cis | Turn off background refresh of Group Policy = Disabled
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | DisableBkGndGroupPolicy | absent |  | DWord
CIS-109 | reg | CIS admin templates | Medium | cis | Turn off downloading of print drivers over HTTP = Enabled
    HKLM:\Software\Policies\Microsoft\Windows NT\Printers | DisableWebPnPDownload | eq | 1 | DWord
CIS-110 | reg | CIS admin templates | Low | cis | Turn off Internet download for Web publishing and online ordering wizards = Enabled
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | NoWebServices | eq | 1 | DWord
CIS-111 | reg | CIS admin templates | Low | cis | Do not allow password expiration time longer than required by policy = Enabled
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordExpirationProtectionEnabled | eq | 1 | DWord
CIS-112 | reg | CIS admin templates | Low | cis | Enable password encryption = Enabled
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | ADPasswordEncryptionEnabled | eq | 1 | DWord
CIS-113 | reg | CIS admin templates | Low | cis | Password Settings: Password Complexity = Large letters + small letters + numbers + specials or higher
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordComplexity | in | 4,5,6,7,8 | DWord | 4
CIS-114 | reg | CIS admin templates | Low | cis | Password Settings: Password Length = 15 or more
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordLength | ge | 15 | DWord | 15
CIS-115 | reg | CIS admin templates | Medium | cis | Password Settings: Password Age (Days) = 30 or fewer
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordAgeDays | le | 30 | DWord | 30
CIS-116 | reg | CIS admin templates | Low | cis | Post-authentication actions: Grace period (hours) = 8 or fewer hours, but not 0
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PostAuthenticationResetDelay | range | 1..8 | DWord | 8
CIS-117 | reg | CIS admin templates | Low | cis | Post-authentication actions: Actions = Reset the password and logoff the managed account or higher
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PostAuthenticationActions | in | 3,5,11 | DWord | 3
CIS-118 | reg | CIS admin templates | Low | cis | Allow Custom SSPs and APs to be loaded into LSASS = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\System | AllowCustomSSPsAPs | eq | 0 | DWord
CIS-119 | reg | CIS admin templates | Low | cis | Block user from showing account details on sign-in = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\System | BlockUserFromShowingAccountDetailsOnSignin | eq | 1 | DWord
CIS-120 | reg | CIS admin templates | Medium | cis | Do not display network selection UI = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\System | DontDisplayNetworkSelectionUI | eq | 1 | DWord
CIS-121 | reg | CIS admin templates | Low | cis | Do not enumerate connected users on domain-joined computers = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\System | DontEnumerateConnectedUsers | eq | 1 | DWord
CIS-122 | reg | CIS admin templates | Low | cis | Turn off app notifications on the lock screen = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\System | DisableLockScreenAppNotifications | eq | 1 | DWord
CIS-123 | reg | CIS admin templates | Low | cis | Turn on convenience PIN sign-in = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\System | AllowDomainPINLogon | eq | 0 | DWord
CIS-124 | reg | CIS admin templates | Low | cis | Block NetBIOS-based discovery for domain controller location = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Netlogon\Parameters | BlockNetbiosDiscovery | eq | 1 | DWord
CIS-125 | reg | CIS admin templates | Medium | cis | Require a password when a computer wakes (on battery) = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 | DCSettingIndex | eq | 1 | DWord
CIS-126 | reg | CIS admin templates | Medium | cis | Require a password when a computer wakes (plugged in) = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51 | ACSettingIndex | eq | 1 | DWord
CIS-127 | reg | CIS admin templates | Low | cis | Configure Offer Remote Assistance = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services | fAllowUnsolicited | eq | 0 | DWord
CIS-128 | reg | CIS admin templates | Low | cis | Enable RPC Endpoint Mapper Client Authentication = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc | EnableAuthEpResolution | eq | 1 | DWord
CIS-129 | reg | CIS admin templates | Low | cis | Configure SAM change password RPC methods policy = Allow strong encryption change password RPC method only
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM | SamrChangeUserPasswordApiPolicy | eq | 2 | DWord
CIS-130 | reg | CIS admin templates | Low | cis | Configure SAM change password RPC methods policy = Block all change password RPC methods
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM | SamrChangeUserPasswordApiPolicy | eq | 1 | DWord
CIS-131 | reg | CIS admin templates | Low | cis | Configure validation of ROCA-vulnerable WHfB keys during authentication = Block
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM | SamNGCKeyROCAValidation | eq | 2 | DWord
CIS-132 | reg | CIS admin templates | Low | cis | Enable Windows NTP Client = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient | Enabled | eq | 1 | DWord
CIS-133 | reg | CIS admin templates | Low | cis | Enable Windows NTP Server = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer | Enabled | eq | 0 | DWord
CIS-134 | reg | CIS admin templates | Low | cis | Not allow per-user unsigned packages to install by default (requires explicitly allow per install) = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx | DisablePerUserUnsignedPackagesByDefault | eq | 1 | DWord
CIS-135 | reg | CIS admin templates | Low | cis | Allow Microsoft accounts to be optional = Enabled
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | MSAOptional | eq | 1 | DWord
CIS-136 | reg | CIS admin templates | Low | cis | Configure enhanced anti-spoofing = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures | EnhancedAntiSpoofing | eq | 1 | DWord
CIS-137 | reg | CIS admin templates | Low | cis | Turn off cloud consumer account state content = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent | DisableConsumerAccountStateContent | eq | 1 | DWord
CIS-138 | reg | CIS admin templates | Low | cis | Require pin for pairing = First Time OR Always
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect | RequirePinForPairing | in | 1,2 | DWord | 1
CIS-139 | reg | CIS admin templates | Low | cis | Do not display the password reveal button = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI | DisablePasswordReveal | eq | 1 | DWord
CIS-140 | reg | CIS admin templates | Medium | cis | Enumerate administrator accounts on elevation = Disabled
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI | EnumerateAdministrators | eq | 0 | DWord
CIS-141 | reg | CIS admin templates | Medium | cis | Allow Diagnostic Data = Diagnostic data off (not recommended) or Send required diagnostic data
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection | AllowTelemetry | in | 0,1 | DWord | 0
CIS-142 | reg | CIS admin templates | Low | cis | Do not show feedback notifications = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection | DoNotShowFeedbackNotifications | eq | 1 | DWord
CIS-143 | reg | CIS admin templates | Low | cis | Enable App Installer Experimental Features = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller | EnableExperimentalFeatures | eq | 0 | DWord
CIS-144 | reg | CIS admin templates | Low | cis | Enable App Installer Hash Override = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller | EnableHashOverride | eq | 0 | DWord
CIS-145 | reg | CIS admin templates | Low | cis | Enable App Installer Local Archive Malware Scan Override = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller | EnableLocalArchiveMalwareScanOverride | eq | 0 | DWord
CIS-146 | reg | CIS admin templates | Low | cis | Enable App Installer Microsoft Store Source Certificate Validation Bypass = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller | EnableBypassCertificatePinningForMicrosoftStore | eq | 0 | DWord
CIS-147 | reg | CIS admin templates | Low | cis | Enable App Installer ms-appinstaller protocol = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller | EnableMSAppInstallerProtocol | eq | 0 | DWord
CIS-148 | reg | CIS admin templates | Low | cis | Application: Control Event Log behavior when the log file reaches its maximum size = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application | Retention | eq | s:0 | String
CIS-149 | reg | CIS admin templates | Low | cis | Security: Control Event Log behavior when the log file reaches its maximum size = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security | Retention | eq | s:0 | String
CIS-150 | reg | CIS admin templates | Low | cis | Setup: Control Event Log behavior when the log file reaches its maximum size = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup | Retention | eq | s:0 | String
CIS-151 | reg | CIS admin templates | Low | cis | System: Control Event Log behavior when the log file reaches its maximum size = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System | Retention | eq | s:0 | String
CIS-152 | reg | CIS admin templates | Medium | cis | Turn off Data Execution Prevention for Explorer = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer | NoDataExecutionPrevention | eq | 0 | DWord
CIS-153 | reg | CIS admin templates | Low | cis | Turn off heap termination on corruption = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer | NoHeapTerminationOnCorruption | eq | 0 | DWord
CIS-154 | reg | CIS admin templates | Medium | cis | Turn off shell protocol protected mode = Disabled
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer | PreXPSP2ShellProtocolBehavior | eq | 0 | DWord
CIS-155 | reg | CIS admin templates | Low | cis | Block all consumer Microsoft account user authentication = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount | DisableUserAuth | eq | 1 | DWord
CIS-156 | reg | CIS admin templates | Low | cis | Require use of specific security layer for remote (RDP) connections = SSL
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services | SecurityLayer | eq | 2 | DWord
CIS-157 | reg | CIS admin templates | Low | cis | Set time limit for active but idle Remote Desktop Services sessions = 15 minutes or less, but not Never (0)
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services | MaxIdleTime | range | 1..900000 | DWord | 900000
CIS-158 | reg | CIS admin templates | Low | cis | Do not delete temp folders upon exit = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services | DeleteTempDirsOnExit | eq | 1 | DWord
CIS-159 | reg | CIS admin templates | Low | cis | Do not use temporary folders per session = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services | PerSessionTempDir | eq | 1 | DWord
CIS-160 | reg | CIS admin templates | Medium | cis | Prevent downloading of enclosures = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds | DisableEnclosureDownload | eq | 1 | DWord
CIS-161 | reg | CIS admin templates | Low | cis | Allow Windows Ink Workspace = On, but disallow access above lock OR Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace | AllowWindowsInkWorkspace | in | 0,1 | DWord | 0
CIS-162 | reg | CIS admin templates | Low | cis | Configure the transmission of the user's password in the content of MPR notifications sent by winlogon = Disabled
    HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System | EnableMPR | eq | 0 | DWord
CIS-163 | reg | CIS admin templates | Low | cis | Prevent users from modifying settings = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection | DisallowExploitProtectionOverride | eq | 1 | DWord
CIS-164 | reg | CIS admin templates | Low | manual | No auto-restart with logged on users for scheduled automatic updates installations = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU | NoAutoRebootWithLoggedOnUsers | eq | 0 | DWord
    how | Changes how this machine installs updates and when it restarts. Set it in the Group Policy or patch tool that manages updates.
CIS-165 | reg | CIS admin templates | Low | manual | Configure Automatic Updates = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU | NoAutoUpdate | eq | 0 | DWord
    how | Changes how this machine installs updates and when it restarts. Set it in the Group Policy or patch tool that manages updates.
CIS-166 | reg | CIS admin templates | Low | manual | Configure Automatic Updates: Scheduled install day = 0 - Every day
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU | ScheduledInstallDay | eq | 0 | DWord
    how | Changes how this machine installs updates and when it restarts. Set it in the Group Policy or patch tool that manages updates.
CIS-167 | reg | CIS admin templates | Low | cis | Manage preview builds = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate | ManagePreviewBuildsPolicyValue | eq | 1 | DWord
CIS-168 | reg | CIS admin templates | Low | manual | Select when Quality Updates are received = 0 days
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate | DeferQualityUpdates | eq | 1 | DWord
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate | DeferQualityUpdatesPeriodInDays | eq | 0 | DWord
    how | Changes how this machine installs updates and when it restarts. Set it in the Group Policy or patch tool that manages updates.
CIS-169 | reg | CIS admin templates | Low | cis | Disable HTTP proxy features: Disable WPAD = Checked
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp | DisableWpad | eq | 1 | DWord
CIS-170 | reg | CIS admin templates | Low | cis | Disable HTTP proxy features: Disable proxy authentication = Disable authentication over loopback interfaces or higher
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings | DisableProxyAuthenticationSchemes | in | 256,287 | DWord | 256
CIS-171 | sec | CIS user rights | Medium | cis | Generate security audits = LOCAL SERVICE, NETWORK SERVICE
    Privilege Rights | SeAuditPrivilege | Generate security audits | only | m:*S-1-5-19;*S-1-5-20
CIS-172 | sec | CIS user rights | Medium | cis | Impersonate a client after authentication = Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE
    Privilege Rights | SeImpersonatePrivilege | Impersonate a client after authentication | only | m:*S-1-5-32-544;*S-1-5-19;*S-1-5-20;*S-1-5-6
CIS-173 | reg | CIS security options | Medium | cis | Domain controller: LDAP server signing requirements = Require signing
    HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters | LDAPServerIntegrity | eq | 2 | DWord
CIS-174 | reg | CIS admin templates | Low | cis | Password Settings: Password Complexity = Large letters + small letters + numbers + specials
    HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS | PasswordComplexity | eq | 4 | DWord
CIS-175 | reg | CIS admin templates | Medium | cis | Turn on Basic feed authentication over HTTP = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds | AllowBasicAuthInClear | eq | 0 | DWord
CIS-176 | reg | CIS Defender | Low | cis | Enable EDR in block mode = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features | PassiveRemediation | eq | 1 | DWord
CIS-177 | reg | CIS Defender | Low | cis | Configure local setting override for reporting to Microsoft MAPS = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet | LocalSettingOverrideSpynetReporting | eq | 0 | DWord
CIS-178 | reg | CIS Defender | Low | cis | Configure Attack Surface Reduction rules = Enabled
    HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR | ExploitGuard_ASR_Rules | eq | 1 | DWord
CIS-179 | reg | CIS Defender | Low | cis | Attack surface reduction rule 01443614-cd74-433a-b99e-2ecdc07bfc25 = block, audit or warn
    HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules | 01443614-cd74-433a-b99e-2ecdc07bfc25 | in | 1,2,6 | String | 2
CIS-180 | reg | CIS Defender | Low | cis | Attack surface reduction rule 33ddedf1-c6e0-47cb-833e-de6133960387 = block
    HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules | 33ddedf1-c6e0-47cb-833e-de6133960387 | eq | s:1 | String
CIS-181 | reg | CIS Defender | Low | cis | Enable file hash computation feature = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine | EnableFileHashComputation | eq | 1 | DWord
CIS-182 | reg | CIS Defender | Low | cis | Configure monitoring for incoming and outgoing file and program activity = bi-directional (full on access)
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection | RealtimeScanDirection | eq | 0 | DWord
CIS-183 | reg | CIS Defender | Low | cis | Configure real-time protection and Security Intelligence Updates during OOBE = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection | OobeEnableRtpAndSigUpdate | eq | 1 | DWord
CIS-184 | reg | CIS Defender | Low | cis | Monitor file and program activity on your computer = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection | DisableOnAccessProtection | eq | 0 | DWord
CIS-185 | reg | CIS Defender | Low | cis | Turn on process scanning whenever real-time protection is enabled = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection | DisableScanOnRealtimeEnable | eq | 0 | DWord
CIS-186 | reg | CIS Defender | Low | cis | Configure Remote Encryption Protection Mode = Audit or higher (BruteForceProtectionConfiguredState)
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection | BruteForceProtectionConfiguredState | in | 2,1 | DWord | 2
CIS-187 | reg | CIS Defender | Low | cis | Configure Remote Encryption Protection Mode = Audit or higher (RemoteEncryptionProtectionConfiguredState)
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection | RemoteEncryptionProtectionConfiguredState | in | 2,1 | DWord | 2
CIS-188 | reg | CIS Defender | Low | cis | Configure whether to report Dynamic Signature dropped events = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting | EnableDynamicSignatureDroppedEventReporting | eq | 1 | DWord
CIS-189 | reg | CIS Defender | Low | cis | Check for the latest virus and spyware security intelligence before running a scheduled scan = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | CheckForSignaturesBeforeRunningScan | eq | 1 | DWord
CIS-190 | reg | CIS Defender | Low | cis | Scan archive files = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | DisableArchiveScanning | eq | 0 | DWord
CIS-191 | reg | CIS Defender | Low | cis | Scan excluded files and directories during quick scans = 1
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | QuickScanIncludeExclusions | eq | 1 | DWord
CIS-192 | reg | CIS Defender | Low | cis | Scan packed executables = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | DisablePackedExeScanning | eq | 0 | DWord
CIS-193 | reg | CIS Defender | Low | cis | Specify the day of the week to run a scheduled scan = 0 or higher, but not 8
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | ScheduleDay | in | 0,1,2,3,4,5,6,7 | DWord | 0
CIS-194 | reg | CIS Defender | Low | cis | Specify the scan type to use for a scheduled scan = Quick Scan (default) or higher
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | ScanParameters | in | 1,2 | DWord | 1
CIS-195 | reg | CIS Defender | Low | cis | Specify the time for a daily quick scan = 1 or higher
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | ScheduleQuickScanTime | ge | 1 | DWord | 1
CIS-196 | reg | CIS Defender | Low | cis | Specify the time of day to run a scheduled scan = 1 or higher
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | ScheduleTime | ge | 1 | DWord | 1
CIS-197 | reg | CIS Defender | Low | cis | Trigger a quick scan after X days without any scans = 7
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | DaysUntilAggressiveCatchupQuickScan | eq | 7 | DWord
CIS-198 | reg | CIS Defender | Low | cis | Turn on e-mail scanning = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan | DisableEmailScanning | eq | 0 | DWord
CIS-199 | reg | CIS Defender | Low | cis | Specify the interval to check for security intelligence updates = 4 or fewer, but not 0
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates | SignatureUpdateInterval | in | 4,3,2,1 | DWord | 4
CIS-200 | reg | CIS Defender | Low | cis | Specify threat alert levels at which default action should not be taken when detected = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats | Threats_ThreatSeverityDefaultAction | eq | 1 | DWord
CIS-201 | reg | CIS Defender | Low | cis | Specify threat alert levels at which default action should not be taken when detected = Medium: 2 or 3
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction | 2 | in | 2,3 | String | 2
CIS-202 | reg | CIS Defender | Low | cis | Specify threat alert levels at which default action should not be taken when detected = High: 2 or 3
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction | 4 | in | 2,3 | String | 2
CIS-203 | reg | CIS Defender | Low | cis | Specify threat alert levels at which default action should not be taken when detected = Severe: 2 or 3
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction | 5 | in | 2,3 | String | 2
CIS-204 | reg | CIS Defender | Low | cis | Control whether exclusions are visible to local users = Enabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender | HideExclusionsFromLocalUsers | eq | 1 | DWord
CIS-205 | reg | CIS Defender | Low | cis | Turn off routine remediation = Disabled
    HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender | DisableRoutinelyTakingAction | eq | 0 | DWord
'@

function ConvertFrom-CisValue([string]$Text) {
    if ($Text -eq '') { return $null }
    if ($Text.StartsWith('s:')) { return $Text.Substring(2) }
    # the comma keeps a list a list (PowerShell unrolls arrays returned by a function)
    if ($Text.StartsWith('m:')) { return , [string[]]@($Text.Substring(2) -split ';' | Where-Object { $_ }) }
    if ($Text -match '^(\d+)\.\.(\d+)$') { return , @([long]$Matches[1], [long]$Matches[2]) }
    if ($Text -match ',') { return , @($Text -split ',') }
    [long]$Text
}

function Get-CisCatalog {
    $list = New-Object Collections.Generic.List[hashtable]
    $c = $null
    foreach ($line in ($CisChecks -split "`r?`n")) {
        if (-not $line.Trim()) { continue }
        $f = @($line.Trim() -split '\s*\|\s*')
        if ($line -match '^CIS-') {
            $c = @{ id = $f[0]; kind = $f[1]; area = $f[2]; sev = $f[3]; fix = $f[4]; title = $f[5]; cisOnly = $true
                    match = 'all'; scope = @(); items = @()
                    why = 'CIS Benchmark Level 1 recommendation for this Windows version. It is not part of the Microsoft security baseline.'
                    ms = 'not included (CIS Level 1 only)'
                    impact = 'Not reviewed one by one for side effects: test it on one machine before applying it to many.' }
            if ($c.area -eq 'CIS Defender') { $c.scope = @('defender') }
            $list.Add($c)
            continue
        }
        if ($f[0] -eq 'how') { $c.how = $f[1]; continue }
        switch ($c.kind) {
            'reg'   { $c.items += Reg $f[0] $f[1] (ConvertFrom-CisValue $f[3]) $f[2] -Type $f[4] -Set $(if ($f.Count -gt 5) { ConvertFrom-CisValue $f[5] } else { $null }) }
            'sec'   { $c.items += Sec $f[0] $f[1] $f[2] (ConvertFrom-CisValue $f[4]) $f[3] -Set $(if ($f.Count -gt 5) { ConvertFrom-CisValue $f[5] } else { $null }) }
            'audit' { $c.sub = $f[0]; $c.guid = $f[1]; $c.want = [int]$f[2] }
        }
    }
    $list
}

# CIS recommendations or STIG IDs for one check, like '2.3.11.7 (L1)' or 'WN22-SO-000310 (CAT II)'
function Get-CisRefs([string]$Id, [string]$Bench, [bool]$Dc) {
    if (-not $Bench) { return @() }
    if (-not $script:CisRows) {
        $script:CisRows = @{}
        $cols = $null
        foreach ($line in ($CisTable -split "`r?`n")) {
            $f = @($line.Trim() -split '\s+')
            if ($f[0] -eq '#') { $cols = @($f | Select-Object -Skip 2); continue }
            if ($f.Count -lt 2) { continue }
            $row = @{}
            for ($i = 0; $i -lt $cols.Count; $i++) {
                $row[$cols[$i]] = if ($f[$i + 1] -eq '=' -and $i) { $row[$cols[$i - 1]] } else { $f[$i + 1] }
            }
            $script:CisRows[$f[0]] = $row
        }
    }
    $cell = $script:CisRows[$Id]
    if (-not $cell -or -not $cell[$Bench] -or $cell[$Bench] -eq '-') { return @() }
    foreach ($r in ($cell[$Bench] -split ',')) {
        if ($r -match '!dc$' -and -not $Dc) { continue }
        if ($r -match '!ms$' -and $Dc) { continue }
        $r = $r -replace '!(dc|ms)$', ''
        $n, $lvl = $r -split '/'
        if (-not $lvl) { $lvl = 'L1' }
        if ($lvl -match '^I+$') { "$n (CAT $lvl)" } else { "$n ($lvl)" }
    }
}

# Defender state, plus the audit and security policy (read once, when a check needs them)
function New-Context {
    $ctx = @{ defender = $false; mp = $null; mpMode = 'not installed'; iisCache = @{}; iisSites = $null; iisPools = $null; services = $null; sql = @{} }
    try {
        $st = Get-MpComputerStatus
        $mode = "$($st.AMRunningMode)"
        if (-not $mode) { $mode = if ($st.AntivirusEnabled) { 'Normal' } else { 'turned off' } }
        $ctx.mpMode = $mode
        $ctx.defender = ($mode -eq 'Normal')
        if ($ctx.defender) { $ctx.mp = Get-MpPreference }
    } catch { }
    $ctx
}

# --------------------------------------------------------------------------
# reading and writing settings
# --------------------------------------------------------------------------

function Get-RegValue([string]$Path, [string]$Name) {
    $k = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $k -or @($k.GetValueNames()) -notcontains $Name) { return @{ exists = $false; value = $null; kind = $null } }
    @{ exists = $true; value = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames'); kind = "$($k.GetValueKind($Name))" }
}

function Set-RegValue([string]$Path, [string]$Name, $Value, [string]$Type) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# Remove-ItemProperty would read the * in names like \\*\SYSVOL as a wildcard
function Remove-RegValue([string]$Path, [string]$Name) {
    if (-not (Get-RegValue $Path $Name).exists) { return }
    $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($Path -replace '^HKLM:\\', ''), $true)
    try { $k.DeleteValue($Name) } finally { $k.Close() }
}

# 1 success, 2 failure, 3 both, by subcategory GUID (auditpol /backup is the same in every language)
function Get-AuditPolicy {
    $f = Join-Path $BackupDir "auditpol-$PID.csv"
    try {
        $out = & auditpol.exe /backup "/file:$f" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed (exit $LASTEXITCODE): $out" }
        $map = @{}
        $rows = Get-Content $f | Select-Object -Skip 1 | ConvertFrom-Csv -Header machine, target, sub, guid, incl, excl, value
        foreach ($r in $rows) { if ($r.guid -match '^\{') { $map[$r.guid.ToLower()] = [int]$r.value } }
        $map
    } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
}

function Set-AuditValue([string]$Guid, [int]$Value) {
    $s = if ($Value -band 1) { 'enable' } else { 'disable' }
    $f = if ($Value -band 2) { 'enable' } else { 'disable' }
    $out = & auditpol.exe /set "/subcategory:$Guid" "/success:$s" "/failure:$f" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed (exit $LASTEXITCODE): $out" }
}

# [System Access] and [Privilege Rights] of the local security policy
function Get-SecPolicy {
    $f = Join-Path $BackupDir "secedit-$PID.inf"
    try {
        $out = & secedit.exe /export /cfg "$f" /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        if ($LASTEXITCODE -ne 0) { throw "secedit /export failed (exit $LASTEXITCODE): $out" }
        $ini = @{}; $sec = ''
        foreach ($l in (Get-Content $f)) {
            if ($l -match '^\s*\[(.+)\]\s*$') { $sec = $Matches[1]; $ini[$sec] = @{}; continue }
            if ($sec -and $l -match '^\s*([^=;]+?)\s*=\s*(.*?)\s*$') { $ini[$sec][$Matches[1]] = $Matches[2] }
        }
        $ini
    } finally { Remove-Item $f -Force -ErrorAction SilentlyContinue }
}

function Invoke-Secedit([string]$Section, $Values) {
    $inf = Join-Path $BackupDir "apply-$PID.inf"
    $db = Join-Path $BackupDir "apply-$PID.sdb"
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', "[$Section]")
    foreach ($k in $Values.Keys) { $lines += '{0} = {1}' -f $k, $Values[$k] }
    [IO.File]::WriteAllLines($inf, [string[]]$lines, [Text.Encoding]::Unicode)
    $area = if ($Section -eq 'Privilege Rights') { 'USER_RIGHTS' } else { 'SECURITYPOLICY' }
    try {
        $out = & secedit.exe /configure /db "$db" /cfg "$inf" /areas $area /quiet 2>&1
        # warnings also give a non-zero exit; the check that runs afterwards shows what really changed
        if ($LASTEXITCODE -ne 0) { Write-Log "  secedit /configure exit ${LASTEXITCODE}: $out" }
    } finally {
        Remove-Item $inf, $db, ($db -replace '\.sdb$', '.jfm') -Force -ErrorAction SilentlyContinue
    }
}

$script:SidNames = @{}
function Resolve-Sid([string]$Sid) {
    if (-not $Sid.StartsWith('*')) { return $Sid }
    if (-not $script:SidNames.ContainsKey($Sid)) {
        $n = $Sid.Substring(1)
        try { $n = (New-Object Security.Principal.SecurityIdentifier $n).Translate([Security.Principal.NTAccount]).Value } catch { }
        $script:SidNames[$Sid] = $n
    }
    $script:SidNames[$Sid]
}

# --------------------------------------------------------------------------
# comparing
# --------------------------------------------------------------------------

function Test-Value($Value, $Want, [string]$Op) {
    try {
        switch ($Op) {
            'eq'      { if ($Want -is [string]) { return (("$Value" -replace '\s', '') -eq ($Want -replace '\s', '')) }
                        return ([long]$Value -eq [long]$Want) }
            'ge'      { return ([long]$Value -ge [long]$Want) }
            'le'      { return ([long]$Value -le [long]$Want) }
            'range'   { return ([long]$Value -ge [long]$Want[0] -and [long]$Value -le [long]$Want[1]) }
            'in'      { return (@($Want | ForEach-Object { "$_" }) -contains "$Value") }
            'minutes' { return ([long]$Value -eq -1 -or [long]$Value -ge [long]$Want) }
            'ne'      { return ("$Value".Trim().Trim('"') -ne "$Want") }
            'set'     { return (@($Value | Where-Object { "$_".Trim() }).Count -gt 0) }
            'subset'  { return (@($Value | Where-Object { "$_".Trim() -and @($Want) -notcontains "$_".Trim() }).Count -eq 0) }
        }
    } catch { }
    $false
}

function Format-Value($Value) {
    if ($Value -is [array]) { return (@($Value) -join ', ') }
    "$Value"
}

function Format-Want($Want, [string]$Op) {
    switch ($Op) {
        'ge'      { return ">= $Want" }
        'le'      { return "<= $Want" }
        'range'   { return "$($Want[0]) to $($Want[1])" }
        'in'      { return (@($Want) -join ' or ') }
        'absent'  { return 'not set' }
        'minutes' { return ">= $Want (or -1: until an admin unlocks)" }
        'ne'      { return "not $Want" }
        'set'     { return 'any text' }
        'subset'  { return $(if (@($Want).Count) { 'only: ' + (@($Want) -join ', ') } else { 'empty' }) }
    }
    Format-Value $Want
}

function Format-Audit([int]$Value) {
    @('No auditing', 'Success', 'Failure', 'Success and Failure')[$Value -band 3]
}

function New-CheckItem([string]$Setting, [string]$Want, [string]$Now, [bool]$Ok) {
    [pscustomobject]@{ setting = $Setting; want = $Want; now = $Now; ok = $Ok }
}

# --------------------------------------------------------------------------
# check kinds: reg, audit, sec (local security policy), mp (Defender), asr, custom
# --------------------------------------------------------------------------

function Reg([string]$Path, [string]$Name, $Want, [string]$Op = 'eq', $Default = $null, [string]$Type = 'DWord', $Set = $null, [string]$Note) {
    @{ path = $Path; name = $Name; want = $Want; op = $Op; default = $Default; type = $Type; set = $Set; note = $Note }
}

function Sec([string]$Section, [string]$Key, [string]$Label, $Want, [string]$Op = 'eq', $Set = $null) {
    @{ section = $Section; key = $Key; label = $Label; want = $Want; op = $Op; set = $Set }
}

function Test-RegCheck($C) {
    $state = @(); $shown = @()
    foreach ($i in $C.items) {
        $r = Get-RegValue $i.path $i.name
        # never keep the value of a setting that should not exist (it can be a password)
        $v = if ($i.op -eq 'absent') { $null } else { $r.value }
        $state += [pscustomobject]@{ path = $i.path; name = $i.name; exists = $r.exists; value = $v; kind = $r.kind }
        if ($i.op -eq 'absent') {
            $ok = -not $r.exists
            $now = if ($r.exists) { 'set' } else { 'not set' }
        } elseif ($r.exists) {
            $ok = Test-Value $r.value $i.want $i.op
            $now = Format-Value $r.value
        } elseif ($i.op -eq 'subset') {
            $ok = $true
            $now = 'not set'
        } elseif ($null -ne $i.default) {
            $ok = Test-Value $i.default $i.want $i.op
            $now = 'not set (Windows default: ' + (Format-Value $i.default) + ')'
        } else {
            $ok = $false
            $now = 'not set'
        }
        if ($i.note -and -not $r.exists) { $now = $i.note }
        $label = ($i.path -replace '^HKLM:\\', 'HKLM\') + '\' + $i.name
        $shown += [pscustomobject]@{ setting = $label; want = (Format-Want $i.want $i.op); now = $now; ok = $ok; exists = $r.exists }
    }
    if ($C.match -eq 'any') {
        $ok = @($shown | Where-Object { $_.ok }).Count -gt 0
    } elseif ($C.match -eq 'first') {
        # the first value that is set decides (a policy value over the local one)
        $d = @($shown | Where-Object { $_.exists })
        $d = if ($d.Count) { $d[0] } else { $shown[-1] }
        $shown = @($d)
        $ok = $d.ok
    } else {
        $ok = @($shown | Where-Object { -not $_.ok }).Count -eq 0
    }
    @{ ok = $ok; items = @($shown | Select-Object setting, want, now, ok); state = $state }
}

function Set-RegCheck($C) {
    $targets = if ($C.match -eq 'any' -or $C.match -eq 'first') { @($C.items[0]) } else { $C.items }
    foreach ($i in $targets) {
        if ($i.op -eq 'absent') { Remove-RegValue $i.path $i.name; continue }
        $r = Get-RegValue $i.path $i.name
        if ($r.exists -and (Test-Value $r.value $i.want $i.op)) { continue }
        $v = if ($null -ne $i.set) { $i.set } elseif ($i.want -is [array] -and $i.type -ne 'MultiString') { $i.want[0] } else { $i.want }
        Set-RegValue $i.path $i.name $v $i.type
    }
}

function Restore-RegState($State) {
    foreach ($s in @($State)) {
        if ($s.exists) {
            $v = $s.value
            switch ("$($s.kind)") {
                'Binary'      { $v = [byte[]]@($v) }
                'MultiString' { $v = [string[]]@($v) }
            }
            Set-RegValue $s.path $s.name $v "$($s.kind)"
        } else {
            Remove-RegValue $s.path $s.name
        }
    }
}

function Get-CtxAudit($Ctx) {
    if (-not $Ctx.ContainsKey('audit')) { $Ctx.audit = $null; $Ctx.audit = Get-AuditPolicy }
    if ($null -eq $Ctx.audit) { throw 'the audit policy could not be read (auditpol /backup)' }
    $Ctx.audit
}

function Get-CtxSec($Ctx) {
    if (-not $Ctx.ContainsKey('sec')) { $Ctx.sec = $null; $Ctx.sec = Get-SecPolicy }
    if ($null -eq $Ctx.sec) { throw 'the local security policy could not be read (secedit /export)' }
    $Ctx.sec
}

function Test-AuditCheck($C, $Ctx) {
    $map = Get-CtxAudit $Ctx
    $cur = 0
    if ($map.ContainsKey($C.guid)) { $cur = [int]$map[$C.guid] }
    $ok = ($cur -band $C.want) -eq $C.want
    @{ ok = $ok; state = @{ guid = $C.guid; value = $cur }
       items = @(New-CheckItem "Advanced audit policy: $($C.sub)" "$(Format-Audit $C.want) (at least)" (Format-Audit $cur) $ok) }
}

function Get-RightList([string]$Raw) {
    @("$Raw" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-SecCheck($C, $Ctx) {
    $ini = Get-CtxSec $Ctx
    $state = @(); $shown = @()
    foreach ($i in $C.items) {
        $sect = $ini[$i.section]
        if (-not $sect) { $sect = @{} }
        $exists = $sect.ContainsKey($i.key)
        $raw = if ($exists) { $sect[$i.key] } else { $null }
        $state += [pscustomobject]@{ section = $i.section; key = $i.key; exists = $exists; value = $raw }
        if ($i.section -eq 'Privilege Rights') {
            $cur = Get-RightList $raw
            $want = @($i.want)
            if ($i.op -eq 'only') {
                $ok = @($cur | Where-Object { $want -notcontains $_ }).Count -eq 0
                $w = if ($want.Count) { 'only ' + (($want | ForEach-Object { Resolve-Sid $_ }) -join ', ') } else { 'no one' }
            } else {
                $ok = @($want | Where-Object { $cur -notcontains $_ }).Count -eq 0
                $w = 'includes ' + (($want | ForEach-Object { Resolve-Sid $_ }) -join ', ')
            }
            $now = if ($cur.Count) { ($cur | ForEach-Object { Resolve-Sid $_ }) -join ', ' } else { 'no one' }
        } else {
            $ok = $exists -and (Test-Value $raw $i.want $i.op)
            $now = if ($exists) { "$raw" } else { 'not set' }
            $w = Format-Want $i.want $i.op
        }
        $shown += New-CheckItem $i.label $w $now $ok
    }
    @{ ok = (@($shown | Where-Object { -not $_.ok }).Count -eq 0); items = $shown; state = $state }
}

function Set-SecCheck($C) {
    $ini = Get-SecPolicy
    $bySection = [ordered]@{}
    foreach ($i in $C.items) {
        $sect = $ini[$i.section]
        if (-not $sect) { $sect = @{} }
        $raw = if ($sect.ContainsKey($i.key)) { $sect[$i.key] } else { $null }
        if ($i.section -eq 'Privilege Rights') {
            $cur = Get-RightList $raw
            $want = @($i.want)
            $new = if ($i.op -eq 'only') { @($cur | Where-Object { $want -contains $_ }) }
                   else { @($cur) + @($want | Where-Object { $cur -notcontains $_ }) }
            if (($new -join ',') -eq ($cur -join ',')) { continue }
            $val = $new -join ','
        } else {
            if ($null -ne $raw -and (Test-Value $raw $i.want $i.op)) { continue }
            $val = if ($null -ne $i.set) { $i.set } else { $i.want }
        }
        if (-not $bySection.Contains($i.section)) { $bySection[$i.section] = [ordered]@{} }
        $bySection[$i.section][$i.key] = $val
    }
    foreach ($s in $bySection.Keys) { Invoke-Secedit $s $bySection[$s] }
}

function Restore-SecState($State) {
    $bySection = [ordered]@{}
    foreach ($s in @($State)) {
        if (-not $s.exists -and $s.section -ne 'Privilege Rights') { continue }    # cannot be "unset"
        if (-not $bySection.Contains($s.section)) { $bySection[$s.section] = [ordered]@{} }
        $bySection[$s.section][$s.key] = $(if ($s.exists) { "$($s.value)" } else { '' })
    }
    foreach ($s in $bySection.Keys) { Invoke-Secedit $s $bySection[$s] }
}

function Test-MpCheck($C, $Ctx) {
    $cur = $Ctx.mp.($C.pref)
    $ok = if ($C.want -is [bool]) { [bool]$cur -eq $C.want } else { Test-Value $cur $C.want $C.op }
    $now = if ($null -eq $cur) { 'not set' } else { "$cur" }
    @{ ok = $ok; state = @{ pref = $C.pref; value = $cur }
       items = @(New-CheckItem "Defender: $($C.pref)" (Format-Want $C.want $C.op) $now $ok) }
}

$AsrActions = @{ 0 = 'off'; 1 = 'block'; 2 = 'audit'; 6 = 'warn' }

function Test-AsrCheck($C, $Ctx) {
    $ids = @($Ctx.mp.AttackSurfaceReductionRules_Ids)
    $acts = @($Ctx.mp.AttackSurfaceReductionRules_Actions)
    $cur = $null
    for ($i = 0; $i -lt $ids.Count; $i++) { if ("$($ids[$i])" -eq $C.guid) { $cur = [int]$acts[$i] } }
    $ok = $null -ne $cur -and @($C.accept) -contains $cur
    $now = if ($null -eq $cur) { 'not configured' } elseif ($AsrActions.ContainsKey($cur)) { $AsrActions[$cur] } else { "$cur" }
    @{ ok = $ok; state = @{ guid = $C.guid; action = $cur }
       items = @(New-CheckItem "ASR rule $($C.guid)" $AsrActions[[int]$C.want] $now $ok) }
}

function Test-Check($C, $Ctx) {
    switch ($C.kind) {
        'reg'    { return (Test-RegCheck $C) }
        'audit'  { return (Test-AuditCheck $C $Ctx) }
        'sec'    { return (Test-SecCheck $C $Ctx) }
        'mp'     { return (Test-MpCheck $C $Ctx) }
        'asr'    { return (Test-AsrCheck $C $Ctx) }
        'custom' { return (& $C.get $C $Ctx) }
    }
    throw "unknown check kind $($C.kind)"
}

function Invoke-Fix($C, $R) {
    switch ($C.kind) {
        'reg'    { Set-RegCheck $C }
        'audit'  { Set-AuditValue $C.guid ([int]$R.state.value -bor $C.want) }
        'sec'    { Set-SecCheck $C }
        'mp'     { $p = @{}; $p[$C.pref] = $(if ($null -ne $C.set) { $C.set } else { $C.want }); Set-MpPreference @p }
        'asr'    { Add-MpPreference -AttackSurfaceReductionRules_Ids $C.guid -AttackSurfaceReductionRules_Actions ([int]$C.want) }
        'custom' { & $C.set $C $R.state }
    }
}

function Invoke-Restore($C, $State) {
    switch ($C.kind) {
        'reg'    { Restore-RegState $State }
        'audit'  { Set-AuditValue $State.guid ([int]$State.value) }
        'sec'    { Restore-SecState $State }
        'mp'     { $p = @{}; $p[$State.pref] = $State.value; Set-MpPreference @p }
        'asr'    {
            if ($null -ne $State.action) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $State.guid -AttackSurfaceReductionRules_Actions ([int]$State.action)
            } else {
                Remove-MpPreference -AttackSurfaceReductionRules_Ids $State.guid
            }
        }
        'custom' { & $C.restore $C $State }
    }
}

# --------------------------------------------------------------------------
# the checks
# --------------------------------------------------------------------------

function Get-Catalog($H) {
    $Pol = 'HKLM:\SOFTWARE\Policies\Microsoft'
    $PW = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
    $PNT = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT'
    $TS = "$PNT\Terminal Services"
    $SysP = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $ExpP = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $Svc = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $Lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $Msv = "$Lsa\MSV1_0"
    $Sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $SA = 'System Access'
    $PR = 'Privilege Rights'
    $Admins = '*S-1-5-32-544'
    $srv = [bool]$H.server
    $old = $H.build -lt 14393     # before Windows 10 1607 / Server 2016: SSL 3.0 still on by default

    $list = New-Object Collections.Generic.List[hashtable]

    # --- SMB -------------------------------------------------------------
    $list.Add(@{ id = 'SMB-01'; area = 'SMB'; sev = 'High'; fix = 'safe'; kind = 'custom'
        title = 'Turn off the SMB 1.0 server'
        why = 'SMB 1.0 has no encryption and no protection against tampering; WannaCry and NotPetya spread through it.'
        ms = 'MS Security Guide: Configure SMB v1 server = Disabled'
        impact = 'Windows XP / Server 2003 and very old printers, scanners and NAS boxes can no longer open shares on this machine.'
        get = { param($C, $Ctx)
            $on = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol
            @{ ok = -not $on; state = $on; items = @(New-CheckItem 'SMB server: EnableSMB1Protocol' 'False' "$on" (-not $on)) } }
        set = { param($C, $S) Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false }
        restore = { param($C, $S) Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$S) -Force -Confirm:$false } })
    $list.Add(@{ id = 'SMB-02'; area = 'SMB'; sev = 'High'; fix = 'review'; reboot = $true
        title = 'Turn off the SMB 1.0 client'
        why = 'With the SMB 1.0 client, this machine can be talked into using the insecure protocol by a malicious or old server.'
        ms = 'MS Security Guide: Configure SMB v1 client driver = Disable driver'
        impact = 'Shares on very old NAS boxes or Windows Server 2003 can no longer be opened from this machine.'
        items = @(Reg "$Svc\MrxSmb10" 'Start' 4 -Note 'not installed (fine)' -Default 4) })
    $list.Add(@{ id = 'SMB-03'; area = 'SMB'; sev = 'Medium'; fix = 'review'
        title = 'Require SMB signing on the server side'
        why = 'Without signing, an attacker in the network can relay or change SMB traffic (NTLM relay).'
        ms = 'Microsoft network server: Digitally sign communications (always) = Enabled'
        impact = 'Clients that cannot sign (very old devices) can no longer connect; signing costs some file copy speed.'
        items = @(Reg "$Svc\LanManServer\Parameters" 'RequireSecuritySignature' 1) })
    $list.Add(@{ id = 'SMB-04'; area = 'SMB'; sev = 'Medium'; fix = 'review'
        title = 'Require SMB signing on the client side'
        why = 'Without signing, an attacker in the network can change what this machine reads from file shares.'
        ms = 'Microsoft network client: Digitally sign communications (always) = Enabled'
        impact = 'Shares on servers or NAS boxes that cannot sign can no longer be opened.'
        items = @(Reg "$Svc\LanmanWorkstation\Parameters" 'RequireSecuritySignature' 1) })
    $list.Add(@{ id = 'SMB-05'; area = 'SMB'; sev = 'High'; fix = 'safe'
        title = 'Never send unencrypted passwords to SMB servers'
        why = 'A rogue SMB server could otherwise ask for the password in clear text.'
        ms = 'Microsoft network client: Send unencrypted password to third-party SMB servers = Disabled'
        items = @(Reg "$Svc\LanmanWorkstation\Parameters" 'EnablePlainTextPassword' 0 -Default 0) })
    $list.Add(@{ id = 'SMB-06'; area = 'SMB'; sev = 'Medium'; fix = 'safe'
        title = 'Turn off insecure guest logons to SMB servers'
        why = 'Guest access to shares has no authentication, so a fake server can serve malicious files.'
        ms = 'Lanman Workstation: Enable insecure guest logons = Disabled'
        items = @(Reg "$PW\LanmanWorkstation" 'AllowInsecureGuestAuth' 0) })
    $list.Add(@{ id = 'SMB-07'; area = 'SMB'; sev = 'High'; fix = 'safe'
        title = 'Block anonymous access to named pipes and shares'
        why = 'Anonymous (null session) access lets anyone on the network list and open pipes and shares.'
        ms = 'Network access: Restrict anonymous access to Named Pipes and Shares = Enabled'
        items = @(Reg "$Svc\LanManServer\Parameters" 'RestrictNullSessAccess' 1 -Default 1) })
    $list.Add(@{ id = 'SMB-08'; area = 'SMB'; sev = 'Low'; fix = 'review'; minBuild = 26100
        title = 'Require SMB 3.0 or newer'
        why = 'SMB 2.x lacks the encryption and integrity protections of SMB 3.'
        ms = 'Lanman Server / Lanman Workstation: Mandate the minimum version of SMB = SMB 3.0.0'
        impact = 'Windows 7 / Server 2008 R2 and devices that only speak SMB 2 can no longer connect.'
        items = @((Reg "$PW\LanmanServer" 'MinSmb2Dialect' 768 -Op 'ge' -Set 768), (Reg "$PW\LanmanWorkstation" 'MinSmb2Dialect' 768 -Op 'ge' -Set 768)) })
    $list.Add(@{ id = 'SMB-09'; area = 'SMB'; sev = 'Low'; fix = 'safe'; minBuild = 26100
        title = 'Slow down SMB password guessing'
        why = 'The authentication rate limiter waits 2 seconds after each failed SMB logon, which makes brute force impractical.'
        ms = 'Lanman Server: Enable authentication rate limiter = Enabled, delay 2000 ms'
        items = @((Reg "$PW\LanmanServer" 'EnableAuthRateLimiter' 1), (Reg "$PW\LanmanServer" 'InvalidAuthenticationDelayTimeInMs' 2000 -Op 'ge' -Set 2000)) })
    $list.Add(@{ id = 'SMB-10'; area = 'SMB'; sev = 'Low'; fix = 'safe'; minBuild = 26100
        title = 'Log SMB connections without signing, encryption or with guest logon'
        why = 'The events show which devices would break before you require signing or encryption.'
        ms = 'Lanman Server / Workstation: Audit client/server does not support encryption, signing; Audit insecure guest logon = Enabled'
        items = @((Reg "$PW\LanmanServer" 'AuditClientDoesNotSupportEncryption' 1), (Reg "$PW\LanmanServer" 'AuditClientDoesNotSupportSigning' 1),
                  (Reg "$PW\LanmanServer" 'AuditInsecureGuestLogon' 1), (Reg "$PW\LanmanWorkstation" 'AuditServerDoesNotSupportEncryption' 1),
                  (Reg "$PW\LanmanWorkstation" 'AuditServerDoesNotSupportSigning' 1), (Reg "$PW\LanmanWorkstation" 'AuditInsecureGuestLogon' 1)) })
    $list.Add(@{ id = 'SMB-11'; area = 'SMB'; sev = 'Low'; fix = 'safe'; minBuild = 26100
        title = 'Turn off remote mailslots'
        why = 'Remote mailslots are a legacy, unauthenticated protocol that is no longer needed.'
        ms = 'Lanman Server / Workstation: Enable remote mailslots = Disabled'
        items = @((Reg "$PW\Bowser" 'EnableMailslots' 0), (Reg "$PW\NetworkProvider" 'EnableMailslots' 0)) })

    # --- network ---------------------------------------------------------
    $list.Add(@{ id = 'NET-01'; area = 'Network'; sev = 'Medium'; fix = 'safe'
        title = 'Turn off LLMNR (multicast name resolution)'
        why = 'Attackers answer LLMNR queries to capture password hashes (Responder); DNS is enough.'
        ms = 'DNS Client: Turn off multicast name resolution = Enabled'
        impact = 'Names that only work by broadcast, without DNS, stop resolving.'
        items = @(Reg "$PNT\DNSClient" 'EnableMulticast' 0) })
    $list.Add(@{ id = 'NET-02'; area = 'Network'; sev = 'Medium'; fix = 'review'; minBuild = 22621
        title = 'Turn off NetBIOS name resolution'
        why = 'Like LLMNR, NetBIOS name queries can be answered by an attacker to capture password hashes.'
        ms = 'DNS Client: Configure NetBIOS settings = Disable NetBIOS name resolution'
        impact = 'Old devices or applications that find each other only by NetBIOS name stop working.'
        items = @(Reg "$PNT\DNSClient" 'EnableNetbios' 0) })
    $list.Add(@{ id = 'NET-03'; area = 'Network'; sev = 'Low'; fix = 'review'; reboot = $true
        title = 'Use NetBIOS point-to-point mode (no broadcasts)'
        why = 'P-node asks only the WINS server, never the whole network, so broadcasts cannot be answered by an attacker.'
        ms = 'MS Security Guide: NetBT NodeType configuration = P-node'
        impact = 'NetBIOS names resolve only through WINS.'
        items = @(Reg "$Svc\NetBT\Parameters" 'NodeType' 2) })
    $list.Add(@{ id = 'NET-04'; area = 'Network'; sev = 'Low'; fix = 'safe'
        title = 'Ignore NetBIOS name release requests'
        why = 'Stops other machines from making this one give up its NetBIOS name.'
        ms = 'MSS: (NoNameReleaseOnDemand) = Enabled'
        items = @(Reg "$Svc\NetBT\Parameters" 'NoNameReleaseOnDemand' 1) })
    $list.Add(@{ id = 'NET-05'; area = 'Network'; sev = 'Low'; fix = 'safe'
        title = 'Turn off IP source routing'
        why = 'Source-routed packets let a sender choose the path through the network, around firewalls.'
        ms = 'MSS: (DisableIPSourceRouting) and (DisableIPSourceRouting IPv6) = Highest protection'
        items = @((Reg "$Svc\Tcpip\Parameters" 'DisableIPSourceRouting' 2), (Reg "$Svc\Tcpip6\Parameters" 'DisableIPSourceRouting' 2)) })
    $list.Add(@{ id = 'NET-06'; area = 'Network'; sev = 'Low'; fix = 'safe'
        title = 'Ignore ICMP redirects'
        why = 'ICMP redirects can be used to send this machine''s traffic through an attacker.'
        ms = 'MSS: (EnableICMPRedirect) = Disabled'
        items = @(Reg "$Svc\Tcpip\Parameters" 'EnableICMPRedirect' 0) })
    $list.Add(@{ id = 'NET-07'; area = 'Network'; sev = 'Medium'; fix = 'safe'; scope = @('domain')
        title = 'Harden the SYSVOL and NETLOGON paths'
        why = 'Requires mutual authentication and integrity when Group Policy scripts are read, so they cannot be swapped on the way (MS15-011).'
        ms = 'Network Provider: Hardened UNC Paths = \\*\SYSVOL and \\*\NETLOGON: RequireMutualAuthentication=1, RequireIntegrity=1'
        items = @((Reg "$PW\NetworkProvider\HardenedPaths" '\\*\SYSVOL' 'RequireMutualAuthentication=1,RequireIntegrity=1' -Type 'String'),
                  (Reg "$PW\NetworkProvider\HardenedPaths" '\\*\NETLOGON' 'RequireMutualAuthentication=1,RequireIntegrity=1' -Type 'String')) })
    $list.Add(@{ id = 'NET-08'; area = 'Network'; sev = 'Medium'; fix = 'safe'
        title = 'Sign LDAP requests'
        why = 'Unsigned LDAP traffic to domain controllers can be changed or relayed.'
        ms = 'Network security: LDAP client signing requirements = Negotiate signing'
        items = @(Reg "$Svc\LDAP" 'LDAPClientIntegrity' 1 -Op 'ge' -Default 1 -Set 1) })
    $list.Add(@{ id = 'NET-09'; area = 'Network'; sev = 'Medium'; fix = 'review'; scope = @('notdc')
        title = 'Allow only authenticated RPC clients'
        why = 'Anonymous RPC calls are a common way to probe and attack Windows services.'
        ms = 'Remote Procedure Call: Restrict Unauthenticated RPC clients = Authenticated'
        impact = 'Old software that calls RPC services anonymously stops working.'
        items = @(Reg "$PNT\Rpc" 'RestrictRemoteClients' 1) })

    # --- credentials and LSA ---------------------------------------------
    $list.Add(@{ id = 'LSA-01'; area = 'Credentials'; sev = 'High'; fix = 'safe'
        title = 'Do not keep plain-text passwords in memory (WDigest)'
        why = 'With WDigest on, tools like Mimikatz read logged-on users'' passwords in clear text from LSASS.'
        ms = 'MS Security Guide: WDigest Authentication = Disabled (Windows Server 2022 baseline)'
        items = @(Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 -Default 0) })
    $list.Add(@{ id = 'LSA-02'; area = 'Credentials'; sev = 'High'; fix = 'safe'
        title = 'Do not store LAN Manager password hashes'
        why = 'LM hashes are cracked in seconds.'
        ms = 'Network security: Do not store LAN Manager hash value on next password change = Enabled (Windows Server 2022 baseline)'
        items = @(Reg $Lsa 'NoLMHash' 1 -Default 1) })
    $list.Add(@{ id = 'LSA-03'; area = 'Credentials'; sev = 'Medium'; fix = 'review'
        title = 'Allow only NTLMv2 authentication (refuse LM and NTLMv1)'
        why = 'LM and NTLMv1 responses can be cracked or relayed easily.'
        ms = 'Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM'
        impact = 'Very old clients, appliances or applications that only speak NTLMv1 can no longer log on.'
        items = @(Reg $Lsa 'LmCompatibilityLevel' 5 -Default 3) })
    $list.Add(@{ id = 'LSA-04'; area = 'Credentials'; sev = 'Medium'; fix = 'review'
        title = 'Require NTLMv2 session security and 128-bit encryption'
        why = 'Weaker NTLM sessions can be downgraded and read.'
        ms = 'Network security: Minimum session security for NTLM SSP based clients / servers = Require NTLMv2 session security, Require 128-bit encryption'
        impact = 'Old applications that use weak NTLM sessions stop working.'
        items = @((Reg $Msv 'NTLMMinClientSec' 537395200 -Default 536870912), (Reg $Msv 'NTLMMinServerSec' 537395200 -Default 536870912)) })
    $list.Add(@{ id = 'LSA-05'; area = 'Credentials'; sev = 'Medium'; fix = 'safe'
        title = 'Block anonymous listing of accounts and shares'
        why = 'Anonymous users can otherwise list user names and shares, which helps password guessing.'
        ms = 'Network access: Do not allow anonymous enumeration of SAM accounts (and shares) = Enabled'
        items = @((Reg $Lsa 'RestrictAnonymousSAM' 1 -Default 1), (Reg $Lsa 'RestrictAnonymous' 1 -Default 0)) })
    $list.Add(@{ id = 'LSA-06'; area = 'Credentials'; sev = 'Medium'; fix = 'safe'; scope = @('notdc')
        title = 'Allow only administrators to query local accounts remotely'
        why = 'Stops normal domain users from listing local users and groups (used by BloodHound and similar tools).'
        ms = 'Network access: Restrict clients allowed to make remote calls to SAM = Administrators only'
        items = @(Reg $Lsa 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' -Type 'String' -Default $(if ($old) { $null } else { 'O:BAG:BAD:(A;;RC;;;BA)' })) })
    $list.Add(@{ id = 'LSA-07'; area = 'Credentials'; sev = 'Low'; fix = 'safe'
        title = 'Turn off NULL session fallback for LocalSystem'
        why = 'Prevents services running as LocalSystem from falling back to unauthenticated sessions.'
        ms = 'Network security: Allow LocalSystem NULL session fallback = Disabled'
        items = @(Reg $Msv 'allownullsessionfallback' 0 -Default 0) })
    $list.Add(@{ id = 'LSA-08'; area = 'Credentials'; sev = 'High'; fix = 'safe'
        title = 'Allow blank passwords only at the console'
        why = 'Local accounts with an empty password must never be usable over the network.'
        ms = 'Accounts: Limit local account use of blank passwords to console logon only = Enabled'
        items = @(Reg $Lsa 'LimitBlankPasswordUse' 1 -Default 1) })
    $list.Add(@{ id = 'LSA-09'; area = 'Credentials'; sev = 'Medium'; fix = 'review'; reboot = $true; match = 'any'
        title = 'Run LSASS as a protected process (LSA protection)'
        why = 'Protects the process that holds credentials against memory dumping and code injection.'
        ms = 'Local Security Authority: Configures LSASS to run as a protected process = Enabled'
        impact = 'Third-party LSA plug-ins (some smart card, password filter or security products) that are not signed by Microsoft no longer load. Applied without UEFI lock, so it can be undone.'
        items = @((Reg $Lsa 'RunAsPPL' @(1, 2) -Op 'in' -Set 2), (Reg "$PW\System" 'RunAsPPL' @(1, 2) -Op 'in')) })
    $list.Add(@{ id = 'LSA-10'; area = 'Credentials'; sev = 'Low'; fix = 'safe'
        title = 'Use Remote Credential Guard / Restricted Admin for credential delegation'
        why = 'The remote host gets no reusable copy of your credentials when you connect with RDP.'
        ms = 'Credentials Delegation: Remote host allows delegation of non-exportable credentials = Enabled'
        items = @(Reg "$PW\CredentialsDelegation" 'AllowProtectedCreds' 1) })
    $list.Add(@{ id = 'LSA-11'; area = 'Credentials'; sev = 'Medium'; fix = 'safe'
        title = 'Connect only to patched CredSSP servers'
        why = 'Protects RDP and WinRM logons against the CredSSP encryption oracle attack (CVE-2018-0886).'
        ms = 'Credentials Delegation: Encryption Oracle Remediation = Force Updated Clients'
        items = @(Reg "$SysP\CredSSP\Parameters" 'AllowEncryptionOracle' 0) })
    $list.Add(@{ id = 'LSA-12'; area = 'Credentials'; sev = 'Low'; fix = 'safe'; scope = @('server')
        title = 'Log NTLM usage'
        why = 'Shows where NTLM is still used, so it can be reduced before it is blocked.'
        ms = 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic = all accounts; Outgoing NTLM traffic to remote servers = Audit all'
        items = @((Reg $Msv 'AuditReceivingNTLMTraffic' 2), (Reg $Msv 'RestrictSendingNTLMTraffic' 1 -Op 'ge' -Set 1)) })
    $list.Add(@{ id = 'LSA-13'; area = 'Credentials'; sev = 'Low'; fix = 'manual'; kind = 'custom'; scope = @('notdc')
        title = 'Turn on Credential Guard'
        why = 'Credential Guard keeps NTLM hashes and Kerberos tickets in an isolated, virtualization-protected process.'
        ms = 'Device Guard: Turn On Virtualization Based Security, Credential Guard = Enabled with UEFI lock (Credential Guard baseline GPO)'
        how = 'Needs UEFI, Secure Boot, TPM and virtualization support (on a VM: nested virtualization). Turn it on with the Microsoft baseline Credential Guard GPO or the Device Guard readiness tool, then restart.'
        get = { param($C, $Ctx)
            $run = @()
            try { $run = @((Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard).SecurityServicesRunning) } catch { }
            $ok = $run -contains 1
            @{ ok = $ok; state = $null; items = @(New-CheckItem 'Device Guard: Credential Guard' 'running' $(if ($ok) { 'running' } else { 'not running' }) $ok) } } })

    # --- accounts and UAC ------------------------------------------------
    $list.Add(@{ id = 'UAC-01'; area = 'Accounts'; sev = 'High'; fix = 'review'; reboot = $true
        title = 'Keep User Account Control on'
        why = 'Without UAC every program an administrator starts runs with full rights.'
        ms = 'User Account Control: Run all administrators in Admin Approval Mode = Enabled'
        impact = 'Programs that expect full administrator rights without a prompt need "Run as administrator".'
        items = @(Reg $SysP 'EnableLUA' 1 -Default 1) })
    $list.Add(@{ id = 'UAC-02'; area = 'Accounts'; sev = 'Low'; fix = 'review'
        title = 'Ask administrators for consent on the secure desktop'
        why = 'The default prompt can be skipped by some auto-elevation tricks; the secure desktop cannot be clicked by malware.'
        ms = 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode = Prompt for consent on the secure desktop'
        impact = 'Administrators see a consent prompt for every elevation.'
        items = @(Reg $SysP 'ConsentPromptBehaviorAdmin' 2 -Default 5) })
    $list.Add(@{ id = 'UAC-03'; area = 'Accounts'; sev = 'Low'; fix = 'review'
        title = 'Deny elevation requests from standard users'
        why = 'Standard users should not be asked for administrator passwords (a common phishing trick).'
        ms = 'User Account Control: Behavior of the elevation prompt for standard users = Automatically deny elevation requests'
        impact = 'Standard users must log on as an administrator (or use Run as) to install software.'
        items = @(Reg $SysP 'ConsentPromptBehaviorUser' 0 -Default 3) })
    $list.Add(@{ id = 'UAC-04'; area = 'Accounts'; sev = 'Medium'; fix = 'review'
        title = 'Use Admin Approval Mode for the built-in Administrator'
        why = 'Otherwise the built-in Administrator runs everything with full rights, without UAC.'
        ms = 'User Account Control: Admin Approval Mode for the Built-in Administrator account = Enabled'
        impact = 'Scripts and tools run as the built-in Administrator must be elevated like for other admins.'
        items = @(Reg $SysP 'FilterAdministratorToken' 1 -Default 0) })
    $list.Add(@{ id = 'UAC-05'; area = 'Accounts'; sev = 'Low'; fix = 'safe'
        title = 'Keep the remaining User Account Control protections on'
        why = 'Installer detection, secure UIAccess paths and file/registry virtualization are part of UAC''s protection.'
        ms = 'User Account Control: Detect application installations; Only elevate UIAccess applications in secure locations; Virtualize file and registry write failures = Enabled'
        items = @((Reg $SysP 'EnableInstallerDetection' 1), (Reg $SysP 'EnableSecureUIAPaths' 1 -Default 1), (Reg $SysP 'EnableVirtualization' 1 -Default 1)) })
    $list.Add(@{ id = 'UAC-06'; area = 'Accounts'; sev = 'Medium'; fix = 'safe'; scope = @('member')
        title = 'Apply UAC to local accounts on network logons'
        why = 'Stops a stolen local administrator password or hash from being used to take over other machines (pass-the-hash).'
        ms = 'MS Security Guide: Apply UAC restrictions to local accounts on network logons = Enabled'
        impact = 'Remote administration with a local account (not a domain account) gets only standard rights.'
        items = @(Reg $SysP 'LocalAccountTokenFilterPolicy' 0 -Default 0) })
    $list.Add(@{ id = 'ACC-01'; area = 'Accounts'; sev = 'Medium'; fix = 'review'; kind = 'sec'; scope = @('notdc')
        title = 'Require passwords of at least 14 characters'
        why = 'Short passwords are guessed or cracked quickly. On a domain member this applies to local accounts; domain accounts follow the domain policy.'
        ms = 'Password Policy: Minimum password length = 14'
        impact = 'Users have to choose a longer password at the next change.'
        items = @(Sec $SA 'MinimumPasswordLength' 'Minimum password length' 14 -Op 'ge') })
    $list.Add(@{ id = 'ACC-02'; area = 'Accounts'; sev = 'Medium'; fix = 'safe'; kind = 'sec'; scope = @('notdc')
        title = 'Require complex passwords'
        why = 'Complexity rules stop the most common, easily guessed passwords.'
        ms = 'Password Policy: Password must meet complexity requirements = Enabled'
        items = @(Sec $SA 'PasswordComplexity' 'Password must meet complexity requirements' 1) })
    $list.Add(@{ id = 'ACC-03'; area = 'Accounts'; sev = 'Low'; fix = 'safe'; kind = 'sec'; scope = @('notdc')
        title = 'Remember the last 24 passwords'
        why = 'Stops users from switching back to a previous (possibly leaked) password.'
        ms = 'Password Policy: Enforce password history = 24'
        items = @(Sec $SA 'PasswordHistorySize' 'Enforce password history' 24 -Op 'ge') })
    $list.Add(@{ id = 'ACC-04'; area = 'Accounts'; sev = 'High'; fix = 'safe'; kind = 'sec'; scope = @('notdc')
        title = 'Do not store passwords with reversible encryption'
        why = 'Reversibly encrypted passwords are as good as plain text.'
        ms = 'Password Policy: Store passwords using reversible encryption = Disabled'
        items = @(Sec $SA 'ClearTextPassword' 'Store passwords using reversible encryption' 0) })
    $lock = if ($srv) { 3 } else { 10 }
    $list.Add(@{ id = 'ACC-05'; area = 'Accounts'; sev = 'Medium'; fix = 'review'; kind = 'sec'; scope = @('notdc')
        title = "Lock accounts after $lock wrong passwords"
        why = 'Without a lockout, local passwords can be guessed without limit.'
        ms = "Account Lockout: Account lockout threshold = $lock"
        impact = 'Users (and service accounts with an old password) get locked out after repeated wrong passwords.'
        items = @(Sec $SA 'LockoutBadCount' 'Account lockout threshold' @(1, $lock) -Op 'range' -Set $lock) })
    $dur = if ($srv) { 15 } else { 10 }
    $list.Add(@{ id = 'ACC-06'; area = 'Accounts'; sev = 'Low'; fix = 'safe'; kind = 'sec'; scope = @('notdc')
        title = "Keep locked accounts locked for $dur minutes"
        why = 'A short lockout lets an attacker keep guessing.'
        ms = "Account Lockout: Account lockout duration = $dur; Reset account lockout counter after = $dur"
        items = @((Sec $SA 'LockoutDuration' 'Account lockout duration (minutes)' $dur -Op 'minutes' -Set $dur),
                  (Sec $SA 'ResetLockoutCount' 'Reset account lockout counter after (minutes)' $dur -Op 'ge' -Set $dur)) })
    $list.Add(@{ id = 'ACC-07'; area = 'Accounts'; sev = 'Low'; fix = 'safe'; kind = 'sec'; scope = @('notdc'); minBuild = 20348
        title = 'Let the Administrator account be locked out too'
        why = 'Otherwise the built-in Administrator can be guessed without limit.'
        ms = 'Account Lockout: Allow Administrator account lockout = Enabled'
        items = @(Sec $SA 'AllowAdministratorLockout' 'Allow Administrator account lockout' 1) })
    $list.Add(@{ id = 'ACC-08'; area = 'Accounts'; sev = 'Medium'; fix = 'safe'; kind = 'sec'; scope = @('notdc')
        title = 'Keep the Guest account disabled'
        why = 'The Guest account allows logons without a password.'
        ms = 'Accounts: Guest account status = Disabled (Windows default)'
        items = @(Sec $SA 'EnableGuestAccount' 'Guest account status' 0) })
    $list.Add(@{ id = 'ACC-09'; area = 'Accounts'; sev = 'Medium'; fix = 'safe'; kind = 'sec'
        title = 'Block anonymous SID / name translation'
        why = 'Anonymous users could otherwise find the real name of the Administrator account.'
        ms = 'Network access: Allow anonymous SID/Name translation = Disabled'
        items = @(Sec $SA 'LSAAnonymousNameLookup' 'Allow anonymous SID/Name translation' 0) })
    $list.Add(@{ id = 'ACC-10'; area = 'Accounts'; sev = 'Low'; fix = 'safe'
        title = 'Lock idle sessions after 15 minutes'
        why = 'An unattended, unlocked session can be used by anyone at the console or in RDP.'
        ms = 'Interactive logon: Machine inactivity limit = 900 seconds'
        items = @(Reg $SysP 'InactivityTimeoutSecs' @(1, 900) -Op 'range' -Set 900) })
    $list.Add(@{ id = 'ACC-11'; area = 'Accounts'; sev = 'Low'; fix = 'safe'
        title = 'Do not sign in the last user automatically after a restart'
        why = 'Automatic restart sign-on keeps the user''s credentials so Windows can log on by itself.'
        ms = 'Windows Logon Options: Sign-in and lock last interactive user automatically after a restart = Disabled'
        items = @(Reg $SysP 'DisableAutomaticRestartSignOn' 1) })
    $list.Add(@{ id = 'ACC-12'; area = 'Accounts'; sev = 'High'; fix = 'manual'
        title = 'Remove the auto-logon password from the registry'
        why = 'With auto-logon, the password is stored in clear text in the registry (Winlogon DefaultPassword), readable by every administrator and by malware.'
        ms = 'Microsoft guidance: do not use auto-logon with a stored password'
        how = 'Turn auto-logon off (netplwiz, or delete DefaultPassword and set AutoAdminLogon to 0 under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon), then change that account''s password. For kiosks, use Sysinternals Autologon, which stores the password encrypted.'
        items = @(Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword' $null -Op 'absent') })
    $list.Add(@{ id = 'ACC-13'; area = 'Accounts'; sev = 'Medium'; fix = 'manual'; match = 'any'; scope = @('member')
        title = 'Manage the local Administrator password with LAPS'
        why = 'Without LAPS the local Administrator password is often the same on many machines, so one stolen hash opens them all.'
        ms = 'LAPS: Configure password backup directory = Active Directory (Windows 11 baseline)'
        how = 'Turn on Windows LAPS (built into Windows since April 2023) with Group Policy: Computer Configuration > Administrative Templates > System > LAPS, "Configure password backup directory" = Active Directory, after running Update-LapsADSchema once.'
        items = @((Reg 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory' @(1, 2) -Op 'in'),
                  (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS' 'BackupDirectory' @(1, 2) -Op 'in'),
                  (Reg "$Pol Services\AdmPwd" 'AdmPwdEnabled' 1)) })
    $list.Add(@{ id = 'ACC-14'; area = 'Accounts'; sev = 'Low'; fix = 'safe'
        title = 'Lock the session when the smart card is removed'
        why = 'Users who pull their smart card expect the session to lock.'
        ms = 'Interactive logon: Smart card removal behavior = Lock Workstation'
        items = @(Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScRemoveOption' '1' -Type 'String') })

    # --- user rights (local security policy) ------------------------------
    $rights = @(
        @('URA-01', 'High',   'SeTcbPrivilege',                   'Act as part of the operating system', @(), 'only', 'This right lets a process become any user.', 'safe'),
        @('URA-02', 'High',   'SeCreateTokenPrivilege',           'Create a token object', @(), 'only', 'This right lets a process create any access token, with any rights.', 'safe'),
        @('URA-03', 'Medium', 'SeTrustedCredManAccessPrivilege',  'Access Credential Manager as a trusted caller', @(), 'only', 'This right gives access to all saved credentials.', 'safe'),
        @('URA-04', 'Medium', 'SeDebugPrivilege',                 'Debug programs', @($Admins), 'only', 'Debug rights are enough to read passwords from LSASS.', 'review'),
        @('URA-05', 'Medium', 'SeLoadDriverPrivilege',            'Load and unload device drivers', @($Admins), 'only', 'A driver runs in the kernel, so this right equals full control.', 'review'),
        @('URA-06', 'Medium', 'SeTakeOwnershipPrivilege',         'Take ownership of files or other objects', @($Admins), 'only', 'Ownership allows changing the permissions of any file.', 'review'),
        @('URA-07', 'Medium', 'SeSecurityPrivilege',              'Manage auditing and security log', @($Admins), 'only', 'This right allows clearing the Security event log.', 'review'),
        @('URA-08', 'Low',    'SeBackupPrivilege',                'Back up files and directories', @($Admins), 'only', 'Backup rights read every file, including the SAM and NTDS databases.', 'review'),
        @('URA-09', 'Low',    'SeRestorePrivilege',               'Restore files and directories', @($Admins), 'only', 'Restore rights overwrite any file, including system files.', 'review'),
        @('URA-10', 'Low',    'SeSystemEnvironmentPrivilege',     'Modify firmware environment values', @($Admins), 'only', 'Firmware settings can turn off Secure Boot protections.', 'review'),
        @('URA-11', 'Low',    'SeLockMemoryPrivilege',            'Lock pages in memory', @(), 'only', 'Locked memory pages cannot be paged out, which can starve the system.', 'review'),
        @('URA-12', 'Low',    'SeCreatePermanentPrivilege',       'Create permanent shared objects', @(), 'only', 'Permanent objects outlive the process that created them.', 'safe')
    )
    if (-not $H.dc) { $rights += , @('URA-13', 'Medium', 'SeEnableDelegationPrivilege', 'Enable computer and user accounts to be trusted for delegation', @(), 'only', 'Delegation lets a service act as any user who connects to it.', 'safe') }
    foreach ($r in $rights) {
        $list.Add(@{ id = $r[0]; area = 'User rights'; sev = $r[1]; fix = $r[7]; kind = 'sec'; scope = @('notdc')
            title = $(if ($r[4].Count) { "Give `"$($r[3])`" only to Administrators" } else { "Give `"$($r[3])`" to no one" })
            why = $r[6]
            ms = "User Rights Assignment: $($r[3]) = $(if ($r[4].Count) { 'Administrators' } else { 'No One' })"
            impact = $(if ($r[7] -eq 'review') { 'Backup, monitoring or database software (for example SQL Server with "Lock pages in memory") may have been given this right on purpose: check its service account before removing it.' } else { $null })
            items = @(Sec $PR $r[2] $r[3] $r[4] -Op $r[5]) })
    }
    $denyNet = if ($srv) { @('*S-1-5-114', '*S-1-5-32-546') } else { @('*S-1-5-113') }
    $list.Add(@{ id = 'URA-14'; area = 'User rights'; sev = 'Medium'; fix = 'review'; kind = 'sec'; scope = @('member')
        title = 'Deny network logon to local administrator accounts'
        why = 'Local administrator passwords are often reused; blocking them over the network stops lateral movement with a stolen hash.'
        ms = 'User Rights Assignment: Deny access to this computer from the network = ' + $(if ($srv) { 'Guests, Local account and member of Administrators group' } else { 'Local account' })
        impact = 'Remote administration with local accounts stops working; use domain accounts.'
        items = @(Sec $PR 'SeDenyNetworkLogonRight' 'Deny access to this computer from the network' $denyNet -Op 'has') })
    $list.Add(@{ id = 'URA-15'; area = 'User rights'; sev = 'Medium'; fix = 'review'; kind = 'sec'; scope = @('member')
        title = 'Deny Remote Desktop logon to local administrator accounts'
        why = 'Forces Remote Desktop logons to use domain accounts, which are audited and can be disabled centrally.'
        ms = 'User Rights Assignment: Deny log on through Remote Desktop Services = ' + $(if ($srv) { 'Guests, Local account and member of Administrators group' } else { 'Local account' })
        impact = 'Remote Desktop with local accounts stops working; keep console access or a domain admin account.'
        items = @(Sec $PR 'SeDenyRemoteInteractiveLogonRight' 'Deny log on through Remote Desktop Services' $denyNet -Op 'has') })
    $netAllow = if ($srv) { @($Admins, '*S-1-5-11') } else { @($Admins, '*S-1-5-32-555') }
    $list.Add(@{ id = 'URA-16'; area = 'User rights'; sev = 'Low'; fix = 'review'; kind = 'sec'; scope = @('notdc')
        title = 'Limit who can access this computer from the network'
        why = 'The default also includes Everyone, Users and Backup Operators.'
        ms = 'User Rights Assignment: Access this computer from the network = ' + $(if ($srv) { 'Administrators, Authenticated Users' } else { 'Administrators, Remote Desktop Users' })
        impact = 'Accounts not in these groups can no longer open shares or other network services on this machine.'
        items = @(Sec $PR 'SeNetworkLogonRight' 'Access this computer from the network' $netAllow -Op 'only') })
    $localAllow = if ($srv) { @($Admins) } else { @($Admins, '*S-1-5-32-545') }
    $list.Add(@{ id = 'URA-17'; area = 'User rights'; sev = 'Low'; fix = 'review'; kind = 'sec'; scope = @('notdc')
        title = 'Limit who can log on at the console'
        why = 'On servers only administrators should log on locally.'
        ms = 'User Rights Assignment: Allow log on locally = ' + $(if ($srv) { 'Administrators' } else { 'Administrators, Users' })
        impact = 'Other accounts (for example Backup Operators or kiosk users) can no longer log on at the console.'
        items = @(Sec $PR 'SeInteractiveLogonRight' 'Allow log on locally' $localAllow -Op 'only') })

    # --- audit policy and logging ----------------------------------------
    $g = '-69ae-11d9-bed3-505054503030}'
    $audit = @(
        @('AUD-01', 'Credential Validation', '{0cce923f', 3, 'Medium'),
        @('AUD-02', 'Security Group Management', '{0cce9237', 1, 'Low'),
        @('AUD-03', 'User Account Management', '{0cce9235', 3, 'Medium'),
        @('AUD-04', 'PNP Activity', '{0cce9248', 1, 'Low'),
        @('AUD-05', 'Process Creation', '{0cce922b', 1, 'Medium'),
        @('AUD-06', 'Account Lockout', '{0cce9217', 2, 'Low'),
        @('AUD-07', 'Group Membership', '{0cce9249', 1, 'Low'),
        @('AUD-08', 'Logon', '{0cce9215', 3, 'Medium'),
        @('AUD-09', 'Other Logon/Logoff Events', '{0cce921c', 3, 'Low'),
        @('AUD-10', 'Special Logon', '{0cce921b', 1, 'Low'),
        @('AUD-11', 'Detailed File Share', '{0cce9244', 2, 'Low'),
        @('AUD-12', 'File Share', '{0cce9224', 3, 'Low'),
        @('AUD-13', 'Other Object Access Events', '{0cce9227', 3, 'Low'),
        @('AUD-14', 'Removable Storage', '{0cce9245', 3, 'Low'),
        @('AUD-15', 'Audit Policy Change', '{0cce922f', $(if ($srv) { 3 } else { 1 }), 'Medium'),
        @('AUD-16', 'Authentication Policy Change', '{0cce9230', 1, 'Low'),
        @('AUD-17', 'MPSSVC Rule-Level Policy Change', '{0cce9232', 3, 'Low'),
        @('AUD-18', 'Other Policy Change Events', '{0cce9234', 2, 'Low'),
        @('AUD-19', 'Sensitive Privilege Use', '{0cce9228', $(if ($srv) { 3 } else { 1 }), 'Low'),
        @('AUD-20', 'Other System Events', '{0cce9214', 3, 'Low'),
        @('AUD-21', 'Security State Change', '{0cce9210', 1, 'Low'),
        @('AUD-22', 'Security System Extension', '{0cce9211', 1, 'Low'),
        @('AUD-23', 'System Integrity', '{0cce9212', 3, 'Low')
    )
    if ($srv) { $audit += , @('AUD-24', 'Authorization Policy Change', '{0cce9231', 1, 'Low') }
    if ($H.dc) {
        $audit += @(
            @('AUD-25', 'Kerberos Authentication Service', '{0cce9242', 3, 'Medium'),
            @('AUD-26', 'Kerberos Service Ticket Operations', '{0cce9240', 2, 'Low'),
            @('AUD-27', 'Computer Account Management', '{0cce9236', 1, 'Low'),
            @('AUD-28', 'Other Account Management Events', '{0cce923a', 1, 'Low'),
            @('AUD-29', 'Directory Service Access', '{0cce923b', 2, 'Low'),
            @('AUD-30', 'Directory Service Changes', '{0cce923c', 1, 'Medium')
        )
    }
    foreach ($a in $audit) {
        $list.Add(@{ id = $a[0]; area = 'Audit'; sev = $a[4]; fix = 'safe'; kind = 'audit'
            title = "Audit $($a[1]): $(Format-Audit $a[3])"
            why = 'Without these events, attacks and their traces cannot be found in the Security log or your SIEM.'
            ms = "Advanced Audit Policy: Audit $($a[1]) = $(Format-Audit $a[3])"
            sub = $a[1]; guid = $a[2] + $g; want = [int]$a[3] })
    }
    $list.Add(@{ id = 'AUD-40'; area = 'Audit'; sev = 'Low'; fix = 'safe'
        title = 'Use the advanced audit policy (subcategories)'
        why = 'Without this, old category settings can silently override the detailed audit policy.'
        ms = 'Audit: Force audit policy subcategory settings to override audit policy category settings = Enabled'
        items = @(Reg $Lsa 'SCENoApplyLegacyAuditPolicy' 1) })
    $list.Add(@{ id = 'AUD-41'; area = 'Audit'; sev = 'Low'; fix = 'safe'
        title = 'Include the command line in process creation events'
        why = 'The command line (event 4688) shows what a process was told to do, for example an encoded PowerShell command.'
        ms = 'Audit Process Creation: Include command line in process creation events = Enabled'
        items = @(Reg "$SysP\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 1) })
    $list.Add(@{ id = 'AUD-42'; area = 'Audit'; sev = 'Medium'; fix = 'safe'
        title = 'Turn on PowerShell script block logging'
        why = 'Logs the PowerShell code that runs (event 4104), including de-obfuscated malicious scripts.'
        ms = 'Windows PowerShell: Turn on PowerShell Script Block Logging = Enabled'
        items = @(Reg "$PW\PowerShell\ScriptBlockLogging" 'EnableScriptBlockLogging' 1) })
    $list.Add(@{ id = 'AUD-43'; area = 'Audit'; sev = 'Low'; fix = 'safe'; kind = 'custom'
        title = 'Make the event logs large enough'
        why = 'Small logs overwrite the evidence within hours on a busy server.'
        ms = 'Event Log Service: Specify the maximum log file size = Application 32768 KB, Security 196608 KB, System 32768 KB'
        logs = [ordered]@{ Application = 32768; Security = 196608; System = 32768 }
        get = { param($C, $Ctx)
            $items = @(); $st = @{}
            foreach ($l in $C.logs.Keys) {
                $cur = [long](Get-WinEvent -ListLog $l).MaximumSizeInBytes
                $st[$l] = $cur
                $items += New-CheckItem ('{0} log: maximum size' -f $l) ('>= {0} KB' -f $C.logs[$l]) ('{0} KB' -f [long]($cur / 1KB)) ($cur -ge $C.logs[$l] * 1KB)
            }
            @{ ok = (@($items | Where-Object { -not $_.ok }).Count -eq 0); items = $items; state = $st } }
        set = { param($C, $S)
            foreach ($l in $C.logs.Keys) {
                if ([long]$S.$l -lt $C.logs[$l] * 1KB) {
                    $out = & wevtutil.exe sl $l "/ms:$($C.logs[$l] * 1KB)" 2>&1
                    if ($LASTEXITCODE -ne 0) { throw "wevtutil $l failed: $out" }
                }
            } }
        restore = { param($C, $S) foreach ($l in $C.logs.Keys) { if ($S.$l) { & wevtutil.exe sl $l "/ms:$($S.$l)" | Out-Null } } } })

    # --- Microsoft Defender ----------------------------------------------
    $list.Add(@{ id = 'DEF-01'; area = 'Defender'; sev = 'Medium'; fix = 'manual'; kind = 'custom'
        title = 'Run Microsoft Defender Antivirus (or another antivirus)'
        why = 'The Defender checks of the baseline apply only when Defender is the active antivirus.'
        ms = 'Microsoft Defender Antivirus baseline GPO'
        how = 'Turn Microsoft Defender Antivirus on (on servers: Install-WindowsFeature Windows-Defender). If another antivirus protects this machine, add DEF-01 to hardening_exclude in the config.'
        get = { param($C, $Ctx)
            @{ ok = $Ctx.defender; state = $null; items = @(New-CheckItem 'Microsoft Defender Antivirus' 'active (normal mode)' $Ctx.mpMode $Ctx.defender) } } })
    $mp = @(
        @('DEF-02', 'High',   'DisableRealtimeMonitoring', $false, $null, 'Keep real-time protection on', 'Turn off real-time protection = Disabled', 'Without real-time protection, malware is only found by scheduled scans, if at all.'),
        @('DEF-03', 'Medium', 'DisableBehaviorMonitoring', $false, $null, 'Keep behavior monitoring on', 'Turn on behavior monitoring = Enabled', 'Behavior monitoring catches malware by what it does, not only by its signature.'),
        @('DEF-04', 'Medium', 'DisableIOAVProtection', $false, $null, 'Scan all downloaded files and attachments', 'Scan all downloaded files and attachments = Enabled', 'Downloads are the most common way malware arrives.'),
        @('DEF-05', 'Medium', 'DisableScriptScanning', $false, $null, 'Scan scripts', 'Turn on script scanning = Enabled', 'Script scanning (AMSI) sees PowerShell, VBScript and JavaScript after de-obfuscation.'),
        @('DEF-06', 'Medium', 'MAPSReporting', 1, 2, 'Use cloud-delivered protection (MAPS)', 'Join Microsoft MAPS = Advanced MAPS', 'Cloud protection blocks new malware within seconds instead of waiting for the next signature update.'),
        @('DEF-07', 'Medium', 'DisableBlockAtFirstSeen', $false, $null, 'Turn on Block at First Sight', 'Configure the Block at First Sight feature = Enabled', 'Unknown files are checked in the cloud before they can run.'),
        @('DEF-08', 'Low',    'SubmitSamplesConsent', @(1, 3), 1, 'Send safe samples for analysis', 'Send file samples when further analysis is required = Send safe samples', 'Needed for Block at First Sight to analyse unknown files.'),
        @('DEF-09', 'Low',    'CloudBlockLevel', 2, 2, 'Use the high cloud protection level', 'Select cloud protection level = High blocking level', 'Blocks more suspicious unknown files.'),
        @('DEF-10', 'Medium', 'PUAProtection', 1, 1, 'Block potentially unwanted applications', 'Configure detection for potentially unwanted applications = Block', 'Blocks adware, bundlers and "hacking tools" that often come with malware.'),
        @('DEF-11', 'Low',    'DisableRemovableDriveScanning', $false, $null, 'Scan removable drives', 'Scan removable drives = Enabled', 'USB drives are still a common way in.')
    )
    foreach ($m in $mp) {
        $op = if ($m[3] -is [array]) { 'in' } elseif ($m[3] -is [bool]) { 'eq' } else { 'ge' }
        $list.Add(@{ id = $m[0]; area = 'Defender'; sev = $m[1]; fix = 'safe'; kind = 'mp'; scope = @('defender')
            pref = $m[2]; want = $m[3]; op = $op; set = $m[4]
            title = $m[5]; why = $m[7]; ms = "Microsoft Defender Antivirus: $($m[6])" })
    }
    $list.Add(@{ id = 'DEF-12'; area = 'Defender'; sev = 'Medium'; fix = 'review'; kind = 'mp'; scope = @('defender', 'client')
        pref = 'EnableNetworkProtection'; want = 1; op = 'eq'
        title = 'Turn on network protection'
        why = 'Blocks connections to known phishing, malware and command-and-control sites from every program.'
        ms = 'Microsoft Defender Exploit Guard: Prevent users and apps from accessing dangerous websites = Block'
        impact = 'Connections to sites Microsoft rates as dangerous are blocked for all programs.' })
    $asr = @(
        @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'Block credential stealing from LSASS', 'Medium', 'all'),
        @('56a863a9-875e-4185-98a7-b882c64b5ce5', 'Block abuse of exploited vulnerable signed drivers', 'Medium', 'all'),
        @('c1db55ab-c21a-4637-bb3f-a12568109d35', 'Use advanced protection against ransomware', 'Medium', 'all'),
        @('e6db77e5-3df2-4cf1-b95a-636979351e5b', 'Block persistence through WMI event subscription', 'Low', 'all'),
        @('5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'Block execution of potentially obfuscated scripts', 'Low', 'all'),
        @('d3e037e1-3eb8-44c8-a917-57927947596d', 'Block JavaScript or VBScript from launching downloaded executable content', 'Low', 'all'),
        @('b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', 'Block untrusted and unsigned processes that run from USB', 'Low', 'all'),
        @('a8f5898e-1dc8-49a9-9878-85004b8a61e6', 'Block web shell creation for servers', 'Medium', 'server'),
        @('be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', 'Block executable content from email client and webmail', 'Medium', 'client'),
        @('d4f940ab-401b-4efc-aadc-ad5f3c50688a', 'Block all Office applications from creating child processes', 'Medium', 'client'),
        @('3b576869-a4ec-4529-8536-b80a7769e899', 'Block Office applications from creating executable content', 'Low', 'client'),
        @('75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', 'Block Office applications from injecting code into other processes', 'Low', 'client'),
        @('92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', 'Block Win32 API calls from Office macros', 'Low', 'client'),
        @('26190899-1602-49e8-8b27-eb1d0a1ce869', 'Block Office communication application from creating child processes', 'Low', 'client'),
        @('7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', 'Block Adobe Reader from creating child processes', 'Low', 'client'),
        @('d1e49aac-8f56-4280-b9ba-993a6d77406c', 'Audit process creations from PSExec and WMI commands', 'Low', 'client')
    )
    $n = 20
    foreach ($a in $asr) {
        $n++
        $isAudit = $a[1].StartsWith('Audit')
        $list.Add(@{ id = "DEF-$n"; area = 'Defender'; sev = $a[2]; fix = 'review'; kind = 'asr'
            scope = @('defender') + $(if ($a[3] -ne 'all') { @($a[3]) } else { @() })
            guid = $a[0]; want = $(if ($isAudit) { 2 } else { 1 }); accept = $(if ($isAudit) { @(1, 2) } else { @(1) })
            title = "Attack surface reduction: $($a[1])"
            why = 'Attack surface reduction rules stop behaviour that malware typically shows and legitimate software rarely needs.'
            ms = "Configure Attack Surface Reduction rules: $($a[0]) = $(if ($isAudit) { 'Audit' } else { 'Block' })"
            impact = 'Some line-of-business software trips ASR rules. Run the rule in audit mode first (Add-MpPreference -AttackSurfaceReductionRules_Actions AuditMode) and check the Defender events 1121/1122.' })
    }

    # --- firewall ----------------------------------------------------------
    foreach ($p in 'Domain', 'Private', 'Public') {
        $list.Add(@{ id = "FW-0$(@{ Domain = 1; Private = 2; Public = 3 }[$p])"; area = 'Firewall'; sev = 'High'; fix = 'review'; kind = 'custom'
            profile = $p
            title = "Turn on the Windows Firewall ($p profile) and block unsolicited inbound connections"
            why = 'The firewall is the last barrier between the network and every listening service on this machine.'
            ms = "Windows Defender Firewall, $p profile: Firewall state = On, Inbound connections = Block"
            impact = 'Inbound connections that no firewall rule allows are blocked: check that the rules for the services this machine offers exist first.'
            get = { param($C, $Ctx)
                $a = Get-NetFirewallProfile -Name $C.profile -PolicyStore ActiveStore
                $l = Get-NetFirewallProfile -Name $C.profile
                $on = "$($a.Enabled)" -eq 'True'
                $in = "$($a.DefaultInboundAction)"
                $inOk = $in -ne 'Allow'
                @{ ok = ($on -and $inOk); state = @{ enabled = "$($l.Enabled)"; inbound = "$($l.DefaultInboundAction)" }
                   items = @((New-CheckItem 'Firewall state' 'On' $(if ($on) { 'On' } else { 'Off' }) $on),
                             (New-CheckItem 'Inbound connections' 'Block' $(if ($in -eq 'NotConfigured') { 'Block (default)' } else { $in }) $inOk)) } }
            set = { param($C, $S) Set-NetFirewallProfile -Name $C.profile -Enabled True -DefaultInboundAction Block }
            restore = { param($C, $S) Set-NetFirewallProfile -Name $C.profile -Enabled $S.enabled -DefaultInboundAction $S.inbound } })
    }
    $list.Add(@{ id = 'FW-04'; area = 'Firewall'; sev = 'Low'; fix = 'safe'; kind = 'custom'
        title = 'Log dropped packets and allowed connections in the firewall'
        why = 'The firewall log shows scans and blocked connection attempts.'
        ms = 'Windows Defender Firewall, all profiles: Log dropped packets = Yes, Log successful connections = Yes'
        get = { param($C, $Ctx)
            $items = @(); $st = @{}
            foreach ($p in 'Domain', 'Private', 'Public') {
                $a = Get-NetFirewallProfile -Name $p -PolicyStore ActiveStore
                $l = Get-NetFirewallProfile -Name $p
                $st[$p] = @{ blocked = "$($l.LogBlocked)"; allowed = "$($l.LogAllowed)" }
                $b = "$($a.LogBlocked)" -eq 'True'
                $w = "$($a.LogAllowed)" -eq 'True'
                $items += New-CheckItem ('{0} profile: log dropped packets / successful connections' -f $p) 'Yes / Yes' ('{0} / {1}' -f $(if ($b) { 'Yes' } else { 'No' }), $(if ($w) { 'Yes' } else { 'No' })) ($b -and $w)
            }
            @{ ok = (@($items | Where-Object { -not $_.ok }).Count -eq 0); items = $items; state = $st } }
        set = { param($C, $S) Set-NetFirewallProfile -Name Domain, Private, Public -LogBlocked True -LogAllowed True }
        restore = { param($C, $S) foreach ($p in 'Domain', 'Private', 'Public') { Set-NetFirewallProfile -Name $p -LogBlocked $S.$p.blocked -LogAllowed $S.$p.allowed } } })

    # --- remote access -----------------------------------------------------
    $list.Add(@{ id = 'RDP-01'; area = 'Remote access'; sev = 'High'; fix = 'review'; match = 'first'
        title = 'Require Network Level Authentication for Remote Desktop'
        why = 'Without NLA the logon screen is reachable before authentication, which exposes the machine to pre-auth exploits like BlueKeep and to password spraying.'
        ms = 'Remote Desktop Session Host: Require user authentication for remote connections by using Network Level Authentication = Enabled'
        impact = 'Very old RDP clients without CredSSP can no longer connect; users whose password has expired must change it elsewhere first.'
        items = @((Reg $TS 'UserAuthentication' 1), (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1)) })
    $list.Add(@{ id = 'RDP-02'; area = 'Remote access'; sev = 'Medium'; fix = 'safe'
        title = 'Use high encryption and secure RPC for Remote Desktop'
        why = 'Lower levels allow weaker encryption of the RDP session.'
        ms = 'Remote Desktop Session Host: Set client connection encryption level = High Level; Require secure RPC communication = Enabled'
        items = @((Reg $TS 'MinEncryptionLevel' 3), (Reg $TS 'fEncryptRPCTraffic' 1)) })
    $list.Add(@{ id = 'RDP-03'; area = 'Remote access'; sev = 'Low'; fix = 'safe'
        title = 'Do not let the Remote Desktop client save passwords'
        why = 'Saved RDP passwords can be read back by anyone who gets into the user''s session.'
        ms = 'Remote Desktop Connection Client: Do not allow passwords to be saved = Enabled'
        items = @(Reg $TS 'DisablePasswordSaving' 1) })
    $list.Add(@{ id = 'RDP-04'; area = 'Remote access'; sev = 'Low'; fix = 'review'
        title = 'Always ask for the password on Remote Desktop connections'
        why = 'Stops logons with credentials that were saved in a client.'
        ms = 'Remote Desktop Session Host: Always prompt for password upon connection = Enabled'
        impact = 'Single sign-on from saved RDP credentials stops working.'
        items = @(Reg $TS 'fPromptForPassword' 1) })
    $list.Add(@{ id = 'RDP-05'; area = 'Remote access'; sev = 'Low'; fix = 'review'
        title = 'Do not allow drive redirection in Remote Desktop'
        why = 'Redirected drives let files move between the client and this machine unnoticed (malware in, data out).'
        ms = 'Remote Desktop Session Host: Do not allow drive redirection = Enabled'
        impact = 'Users can no longer copy files through their local drives in an RDP session.'
        items = @(Reg $TS 'fDisableCdm' 1) })
    $list.Add(@{ id = 'RDP-06'; area = 'Remote access'; sev = 'Low'; fix = 'safe'
        title = 'Turn off solicited Remote Assistance'
        why = 'Remote Assistance invitations give someone else control of the session.'
        ms = 'Remote Assistance: Configure Solicited Remote Assistance = Disabled (Windows 11 baseline)'
        items = @(Reg $TS 'fAllowToGetHelp' 0) })
    $list.Add(@{ id = 'WRM-01'; area = 'Remote access'; sev = 'High'; fix = 'review'
        title = 'Do not allow Basic authentication or unencrypted traffic on the WinRM service'
        why = 'Basic authentication sends the password with every request; unencrypted WinRM can be read on the network.'
        ms = 'WinRM Service: Allow Basic authentication = Disabled; Allow unencrypted traffic = Disabled'
        impact = 'Tools that connect with Basic authentication (some Linux or monitoring tools) must switch to Kerberos, NTLM or certificates over HTTPS.'
        items = @((Reg "$PW\WinRM\Service" 'AllowBasic' 0), (Reg "$PW\WinRM\Service" 'AllowUnencryptedTraffic' 0)) })
    $list.Add(@{ id = 'WRM-02'; area = 'Remote access'; sev = 'Medium'; fix = 'safe'
        title = 'Do not use Basic or Digest authentication or unencrypted traffic in the WinRM client'
        why = 'This machine would otherwise send passwords in a weakly protected form when it connects to other machines.'
        ms = 'WinRM Client: Allow Basic authentication = Disabled; Allow unencrypted traffic = Disabled; Disallow Digest authentication = Enabled'
        items = @((Reg "$PW\WinRM\Client" 'AllowBasic' 0), (Reg "$PW\WinRM\Client" 'AllowUnencryptedTraffic' 0), (Reg "$PW\WinRM\Client" 'AllowDigest' 0)) })
    $list.Add(@{ id = 'WRM-03'; area = 'Remote access'; sev = 'Low'; fix = 'safe'
        title = 'Do not let WinRM store RunAs credentials'
        why = 'Stored RunAs credentials of PowerShell session configurations can be misused.'
        ms = 'WinRM Service: Disallow WinRM from storing RunAs credentials = Enabled'
        items = @(Reg "$PW\WinRM\Service" 'DisableRunAs' 1) })

    # --- system ------------------------------------------------------------
    $list.Add(@{ id = 'SYS-01'; area = 'System'; sev = 'Medium'; fix = 'safe'
        title = 'Turn off AutoRun and AutoPlay'
        why = 'AutoRun starts programs from inserted media without asking.'
        ms = 'AutoPlay Policies: Turn off Autoplay = All drives; Set the default behavior for AutoRun = Do not execute; Disallow Autoplay for non-volume devices = Enabled'
        items = @((Reg $ExpP 'NoDriveTypeAutoRun' 255), (Reg $ExpP 'NoAutorun' 1), (Reg "$PW\Explorer" 'NoAutoplayfornonVolume' 1)) })
    $list.Add(@{ id = 'SYS-02'; area = 'System'; sev = 'High'; fix = 'safe'
        title = 'Never install Windows Installer packages with elevated rights'
        why = 'With "Always install elevated", every user can become administrator with a crafted .msi file.'
        ms = 'Windows Installer: Always install with elevated privileges = Disabled; Allow user control over installs = Disabled'
        items = @((Reg "$PW\Installer" 'AlwaysInstallElevated' 0 -Default 0), (Reg "$PW\Installer" 'EnableUserControl' 0 -Default 0)) })
    $list.Add(@{ id = 'SYS-03'; area = 'System'; sev = 'Low'; fix = 'safe'
        title = 'Turn on SEHOP exploit protection'
        why = 'Structured Exception Handler Overwrite Protection blocks a common class of memory exploits.'
        ms = 'MS Security Guide: Enable Structured Exception Handling Overwrite Protection (SEHOP) = Enabled'
        items = @(Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0) })
    $list.Add(@{ id = 'SYS-04'; area = 'System'; sev = 'Low'; fix = 'safe'
        title = 'Do not load boot drivers that the antimalware rates as bad'
        why = 'Early Launch Antimalware checks boot drivers before they start.'
        ms = 'Early Launch Antimalware: Boot-Start Driver Initialization Policy = Good, unknown and bad but critical'
        items = @(Reg 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' 'DriverLoadPolicy' @(1, 3, 8) -Op 'in' -Default 3 -Set 3) })
    $list.Add(@{ id = 'SYS-05'; area = 'System'; sev = 'Low'; fix = 'safe'
        title = 'Strengthen the permissions of internal system objects'
        why = 'Stops normal users from changing shared system objects such as symbolic links.'
        ms = 'System objects: Strengthen default permissions of internal system objects = Enabled'
        items = @(Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' 1 -Default 1) })
    $list.Add(@{ id = 'SYS-06'; area = 'System'; sev = 'Low'; fix = 'review'
        title = 'Block external devices that do not support Kernel DMA Protection'
        why = 'Thunderbolt and other DMA devices can read memory directly, for example to steal BitLocker keys.'
        ms = 'Kernel DMA Protection: Enumeration policy for external devices incompatible with Kernel DMA Protection = Block all'
        impact = 'Older Thunderbolt docks and devices stop working until a user logs on, or at all.'
        items = @(Reg "$PW\Kernel DMA Protection" 'DeviceEnumerationPolicy' 0) })
    $list.Add(@{ id = 'SYS-07'; area = 'System'; sev = 'Low'; fix = 'review'
        title = 'Turn on SmartScreen for downloaded programs'
        why = 'SmartScreen warns before unknown or malicious downloaded programs run, and the user cannot ignore the warning.'
        ms = 'File Explorer: Configure Windows Defender SmartScreen = Warn and prevent bypass'
        impact = 'Unsigned or rare downloaded programs are blocked until an administrator unblocks them.'
        items = @((Reg "$PW\System" 'EnableSmartScreen' 1), (Reg "$PW\System" 'ShellSmartScreenLevel' 'Block' -Type 'String')) })
    $list.Add(@{ id = 'SYS-08'; area = 'System'; sev = 'Low'; fix = 'safe'; minBuild = 26100
        title = 'Keep the Mark of the Web on files copied from untrusted places'
        why = 'The Mark of the Web makes Office and SmartScreen treat downloaded files with care.'
        ms = 'File Explorer: Do not apply the Mark of the Web tag to files copied from insecure sources = Disabled'
        items = @(Reg "$PW\Explorer" 'DisableMotWOnInsecurePathCopy' 0) })
    $list.Add(@{ id = 'SYS-09'; area = 'System'; sev = 'Low'; fix = 'safe'; minBuild = 26100
        title = 'Turn off sudo for Windows'
        why = 'Sudo is a new way to elevate that bypasses the usual UAC experience.'
        ms = 'System: Configure the behavior of the sudo command = Disabled'
        items = @(Reg "$PW\Sudo" 'Enabled' 0) })
    $list.Add(@{ id = 'SYS-10'; area = 'System'; sev = 'Low'; fix = 'safe'
        title = 'Do not index encrypted files'
        why = 'The search index would keep the contents of encrypted files unencrypted.'
        ms = 'Search: Allow indexing of encrypted files = Disabled'
        items = @(Reg "$PW\Windows Search" 'AllowIndexingEncryptedStoresOrItems' 0) })
    $list.Add(@{ id = 'SYS-11'; area = 'System'; sev = 'Low'; fix = 'safe'; scope = @('member')
        title = 'Do not list local users on the logon screen'
        why = 'The list tells an attacker which local accounts to try.'
        ms = 'Logon: Enumerate local users on domain-joined computers = Disabled'
        items = @(Reg "$PW\System" 'EnumerateLocalUsers' 0) })
    $list.Add(@{ id = 'SYS-12'; area = 'System'; sev = 'High'; fix = 'safe'
        title = 'Let only administrators install printer drivers'
        why = 'Point and Print driver installation by normal users was the PrintNightmare attack (CVE-2021-34527).'
        ms = 'Printers: Limits print driver installation to Administrators = Enabled'
        items = @(Reg "$PNT\Printers\PointAndPrint" 'RestrictDriverInstallationToAdministrators' 1 -Default 1) })
    $list.Add(@{ id = 'SYS-13'; area = 'System'; sev = 'Medium'; fix = 'safe'
        title = 'Require packet privacy for print spooler RPC'
        why = 'Protects the print spooler RPC interface against relay attacks (CVE-2021-1678).'
        ms = 'MS Security Guide: Configure RPC packet level privacy setting for incoming connections = Enabled'
        items = @(Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Print' 'RpcAuthnLevelPrivacyEnabled' 1 -Default 1) })
    $list.Add(@{ id = 'SYS-14'; area = 'System'; sev = 'Low'; fix = 'safe'
        title = 'Re-apply registry policies even when Group Policy has not changed'
        why = 'Puts back policy settings that were changed locally, at every Group Policy refresh.'
        ms = 'Group Policy: Configure registry policy processing = Process even if the Group Policy objects have not changed'
        items = @((Reg "$PW\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" 'NoGPOListChanges' 0),
                  (Reg "$PW\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" 'NoBackgroundPolicy' 0)) })
    $list.Add(@{ id = 'SYS-15'; area = 'System'; sev = 'High'; fix = 'review'; kind = 'custom'; scope = @('dc')
        title = 'Turn off the Print Spooler on domain controllers'
        why = 'A running spooler on a DC can be forced to authenticate to an attacker (PrinterBug) and has had many critical flaws (PrintNightmare).'
        ms = 'Microsoft guidance: disable the Print Spooler service on domain controllers'
        impact = 'The DC can no longer print or share printers, and printer pruning of published printers stops.'
        allowShared = $false
        get = { param($C, $Ctx) Test-Spooler $C }
        set = { param($C, $S) Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled }
        restore = { param($C, $S) if ($S) { Set-Service Spooler -StartupType $S.start; if ($S.running) { Start-Service Spooler } } } })
    $list.Add(@{ id = 'SYS-16'; area = 'System'; sev = 'Low'; fix = 'review'; kind = 'custom'; scope = @('server', 'notdc')
        title = 'Turn off the Print Spooler on servers that are not print servers'
        why = 'The spooler is a frequent target (PrintNightmare) and not needed on a server that shares no printers.'
        ms = 'Microsoft guidance: disable the Print Spooler where it is not needed'
        impact = 'Nobody can print from this server any more (for example from an RDP session or an application that prints).'
        allowShared = $true
        get = { param($C, $Ctx) Test-Spooler $C }
        set = { param($C, $S) Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled }
        restore = { param($C, $S) if ($S) { Set-Service Spooler -StartupType $S.start; if ($S.running) { Start-Service Spooler } } } })
    $list.Add(@{ id = 'SYS-17'; area = 'System'; sev = 'Medium'; fix = 'safe'; kind = 'custom'; reboot = $true
        title = 'Remove Windows PowerShell 2.0'
        why = 'PowerShell 2.0 has no script block logging and no AMSI, so attackers use it to run scripts unseen. Microsoft removed it from Windows 11 24H2 and Server 2025.'
        ms = 'Microsoft guidance: Windows PowerShell 2.0 is deprecated, remove it'
        get = { param($C, $Ctx)
            $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
            $state = if ($f) { "$($f.State)" } else { 'not available' }
            $ok = $state -ne 'Enabled'
            @{ ok = $ok; state = $state; items = @(New-CheckItem 'Windows feature MicrosoftWindowsPowerShellV2Root' 'Disabled' $state $ok) } }
        set = { param($C, $S) Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -WarningAction SilentlyContinue | Out-Null }
        restore = { param($C, $S) if ($S -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -All -NoRestart -WarningAction SilentlyContinue | Out-Null } } })
    $list.Add(@{ id = 'SYS-18'; area = 'System'; sev = 'Low'; fix = 'manual'; kind = 'custom'
        title = 'Boot with Secure Boot'
        why = 'Secure Boot stops boot kits and is needed for Credential Guard and LSA protection with UEFI lock.'
        ms = 'Microsoft guidance: UEFI with Secure Boot'
        how = 'Turn on Secure Boot in the UEFI firmware (on Hyper-V: a generation 2 VM, Settings > Security > Enable Secure Boot). Machines that boot in legacy BIOS mode must be converted with mbr2gpt first.'
        get = { param($C, $Ctx)
            $now = try { if (Confirm-SecureBootUEFI) { 'on' } else { 'off' } } catch { 'not supported (legacy BIOS boot)' }
            @{ ok = ($now -eq 'on'); state = $null; items = @(New-CheckItem 'Secure Boot' 'on' $now ($now -eq 'on')) } } })
    $list.Add(@{ id = 'SYS-19'; area = 'System'; sev = 'Medium'; fix = 'manual'; kind = 'custom'; scope = @('client')
        title = 'Encrypt the system drive with BitLocker'
        why = 'Without disk encryption, anyone with the device can read all data and the cached credentials.'
        ms = 'Windows 11 baseline: BitLocker GPO'
        how = 'Turn on BitLocker for the system drive (manage-bde -on C: -RecoveryPassword, or through Intune / MBAM), and keep the recovery key in Active Directory or Entra ID.'
        get = { param($C, $Ctx)
            $d = $env:SystemDrive
            $v = $null
            try { $v = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$d'" } catch { }
            $now = if (-not $v) { 'BitLocker is not available' } elseif ($v.ProtectionStatus -eq 1) { 'protection on' } else { 'protection off' }
            @{ ok = ($now -eq 'protection on'); state = $null; items = @(New-CheckItem "BitLocker on $d" 'protection on' $now ($now -eq 'protection on')) } } })

    # --- TLS -----------------------------------------------------------------
    $tls = @(
        @('TLS-01', 'SSL 3.0', 'High', $(if ($old) { 1 } else { 0 })),
        @('TLS-02', 'TLS 1.0', 'Medium', 1),
        @('TLS-03', 'TLS 1.1', 'Low', 1)
    )
    foreach ($t in $tls) {
        $list.Add(@{ id = $t[0]; area = 'TLS'; sev = $t[2]; fix = 'review'; reboot = $true
            title = "Turn off $($t[1])"
            why = "$($t[1]) has known weaknesses (POODLE, BEAST) and is deprecated; Microsoft is turning TLS 1.0 and 1.1 off by default in new Windows versions."
            ms = 'Microsoft TLS guidance: TLS 1.0 and TLS 1.1 deprecation in Windows (not part of the GPO baseline)'
            impact = "Clients and servers that cannot use TLS 1.2 (old Windows, Java 6/7, old SQL Server drivers, old appliances) can no longer connect to or from this machine. Check the Schannel events and IIS logs first."
            items = @((Reg "$Sch\$($t[1])\Server" 'Enabled' 0 -Default $t[3]), (Reg "$Sch\$($t[1])\Client" 'Enabled' 0 -Default $t[3])) })
    }
    $list.Add(@{ id = 'TLS-04'; area = 'TLS'; sev = 'Low'; fix = 'safe'
        title = 'Let .NET Framework applications use strong cryptography and the system TLS versions'
        why = 'Without these, older .NET applications may still offer TLS 1.0 and weak ciphers.'
        ms = 'Microsoft TLS guidance: Transport Layer Security best practices with the .NET Framework'
        items = @((Reg 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto' 1),
                  (Reg 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SystemDefaultTlsVersions' 1),
                  (Reg 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto' 1),
                  (Reg 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' 'SystemDefaultTlsVersions' 1)) })

    foreach ($c in $list) {
        if (-not $c.kind) { $c.kind = 'reg' }
        if (-not $c.match) { $c.match = 'all' }
        if (-not $c.scope) { $c.scope = @() }
    }
    $list
}

function Test-Spooler($C) {
    $s = Get-Service Spooler -ErrorAction SilentlyContinue
    if (-not $s) { return @{ ok = $true; state = $null; items = @(New-CheckItem 'Print Spooler service' 'Disabled' 'not installed' $true) } }
    $start = "$($s.StartType)"
    $shared = 0
    if ($C.allowShared) { $shared = @(Get-CimInstance Win32_Printer -Filter 'Shared = TRUE' -ErrorAction SilentlyContinue).Count }
    $ok = $start -eq 'Disabled' -or $shared -gt 0
    $now = "$start, $($s.Status)" + $(if ($shared) { ", shares $shared printers (needed)" } else { '' })
    $want = if ($C.allowShared) { 'Disabled (unless this is a print server)' } else { 'Disabled' }
    @{ ok = $ok; state = @{ start = $start; running = ("$($s.Status)" -eq 'Running') }; items = @(New-CheckItem 'Print Spooler service' $want $now $ok) }
}

# --------------------------------------------------------------------------
# IIS and SQL Server: these checks run only on machines where they are installed
# --------------------------------------------------------------------------

# IIS: the version (10.0 on Windows Server 2016 and later), or $null when IIS is not installed
function Get-IisInfo {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\InetStp' 'MajorVersion'
    if (-not $v.exists -or -not (Get-Service W3SVC -ErrorAction SilentlyContinue)) { return $null }
    "$($v.value).$([int](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\InetStp' 'MinorVersion').value)"
}

# the SQL Server database engine instances on this machine
function Get-SqlInstances {
    $base = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
    $names = Get-ItemProperty "$base\Instance Names\SQL" -ErrorAction SilentlyContinue
    if (-not $names) { return }
    foreach ($p in $names.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $setup = Get-ItemProperty "$base\$($p.Value)\Setup" -ErrorAction SilentlyContinue
        $ver = if ($setup.PatchLevel) { "$($setup.PatchLevel)" } else { "$($setup.Version)" }
        $default = $p.Name -eq 'MSSQLSERVER'
        [pscustomobject]@{
            name = $p.Name; id = "$($p.Value)"; version = $ver; major = [int](@("$ver" -split '\.')[0] -replace '\D', '0')
            key = "$base\$($p.Value)"; server = $(if ($default) { '.' } else { ".\$($p.Name)" })
        }
    }
}

function Get-IisManager {
    if (-not $script:IisManager) {
        Add-Type -Path (Join-Path $env:windir 'System32\inetsrv\Microsoft.Web.Administration.dll')
        $script:IisManager = New-Object Microsoft.Web.Administration.ServerManager
    }
    $script:IisManager
}

# a configuration element as a hashtable: attributes by name (enums and flags by their names),
# the names of the attributes set in a configuration file under '@set', child elements by tag
# name and the entries of a collection under '@items'
function ConvertFrom-IisElement($E, [int]$Depth) {
    $h = @{}
    $set = @()
    foreach ($a in $E.Attributes) {
        $v = $a.Value
        try {
            $ev = @($a.Schema.GetEnumValues())
            if ($ev.Count -and $null -ne $v -and "$v" -match '^\d+$') {
                $n = [long]$v
                $v = if ($a.Schema.Type -eq 'flags') {
                    (@($ev | Where-Object { $_.Value -and ($n -band $_.Value) -eq $_.Value } | ForEach-Object { $_.Name }) -join ',')
                } else { "$(@($ev | Where-Object { $_.Value -eq $n } | ForEach-Object { $_.Name })[0])" }
            }
        } catch { }
        if (-not $a.IsInheritedFromDefaultValue) { $set += $a.Name }
        $h[$a.Name] = $v
    }
    $h['@set'] = $set
    if ($Depth -lt 5) {
        foreach ($c in $E.ChildElements) { $h[$c.ElementTagName] = ConvertFrom-IisElement $c ($Depth + 1) }
        if ($E.Schema.CollectionSchema) { $h['@items'] = @(foreach ($i in $E.GetCollection()) { ConvertFrom-IisElement $i ($Depth + 1) }) }
    }
    $h
}

# one configuration section, at the server level ($Site empty) or as one website sees it
function Get-IisConfig([string]$Section, [string]$Site) {
    $sm = Get-IisManager
    $cfg = if ($Site) { $sm.GetWebConfiguration($Site) } else { $sm.GetApplicationHostConfiguration() }
    ConvertFrom-IisElement $cfg.GetSection($Section) 0
}

function Get-IisSites {
    foreach ($s in (Get-IisManager).Sites) {
        $app = $s.Applications['/']
        $vd = if ($app) { $app.VirtualDirectories['/'] } else { $null }
        [pscustomobject]@{
            name  = "$($s.Name)"
            pool  = $(if ($app) { "$($app.ApplicationPoolName)" } else { '' })
            path  = $(if ($vd) { [Environment]::ExpandEnvironmentVariables("$($vd.PhysicalPath)") } else { '' })
            https = (@($s.Bindings | Where-Object { $_.Protocol -eq 'https' }).Count -gt 0)
            log   = (ConvertFrom-IisElement $s.LogFile 0)
        }
    }
}

function Get-IisPools {
    foreach ($p in (Get-IisManager).ApplicationPools) { [pscustomobject]@{ name = "$($p.Name)"; identity = "$($p.ProcessModel.IdentityType)" } }
}

# read once per run
function Get-CtxIisSection($Ctx, [string]$Section, [string]$Site) {
    $k = "$Site|$Section"
    if (-not $Ctx.iisCache.ContainsKey($k)) { $Ctx.iisCache[$k] = Get-IisConfig $Section $Site }
    $Ctx.iisCache[$k]
}

function Get-CtxIisSites($Ctx) {
    if ($null -eq $Ctx.iisSites) { $Ctx.iisSites = @(Get-IisSites) }
    $Ctx.iisSites
}

function Get-CtxIisPools($Ctx) {
    if ($null -eq $Ctx.iisPools) { $Ctx.iisPools = @(Get-IisPools) }
    $Ctx.iisPools
}

function Get-CtxServices($Ctx) {
    if ($null -eq $Ctx.services) { $Ctx.services = @(Get-CimInstance Win32_Service) }
    $Ctx.services
}

function Split-IisList($Value) { @("$Value" -split '\s*,\s*' | Where-Object { $_ }) }

function New-ItemsResult($Items) {
    @{ ok = (@($Items | Where-Object { -not $_.ok }).Count -eq 0); state = $null; items = @($Items) }
}

# ASP.NET is installed in IIS when its integration module is loaded
function Test-IisAspNet($Ctx) {
    @((Get-CtxIisSection $Ctx 'system.webServer/globalModules' '').'@items' | Where-Object { "$($_.name)" -like 'ManagedEngine*' }).Count -gt 0
}

# one item for the server level and one for each website; $Eval gets the section and returns @{ now; ok }
function Get-IisItems($Ctx, [string]$Section, [string]$Label, [string]$Want, [scriptblock]$Eval, [switch]$ServerOnly) {
    $places = @('')
    if (-not $ServerOnly) { $places += @(Get-CtxIisSites $Ctx | ForEach-Object { $_.name }) }
    $items = @(); $errs = @()
    foreach ($p in $places) {
        $where = if ($p) { "site $p" } else { 'server' }
        try { $r = & $Eval (Get-CtxIisSection $Ctx $Section $p) }
        catch { $errs += "${where}: $($_.Exception.Message)"; continue }
        $now = if ("$($r.now)" -eq '') { 'not set' } else { "$($r.now)" }
        $items += New-CheckItem "${where}: $Label" $Want $now ([bool]$r.ok)
    }
    if ($errs.Count) { throw ('could not read the IIS configuration: ' + ($errs -join '; ')) }
    New-ItemsResult $items
}

# a log setting of a website: its own value when it sets one, otherwise the siteDefaults one
function Get-IisSiteLog($Site, $Defaults, [string]$Attr) {
    if (@($Site.log.'@set') -contains $Attr) { return $Site.log[$Attr] }
    $Defaults[$Attr]
}

function Get-IisLogFields($Log) {
    @(@($Log.customFields.'@items') | Where-Object { $_ } | ForEach-Object { "$($_.sourceType)/$($_.sourceName)" })
}

function ConvertTo-Minutes($Value) {
    if ($Value -is [TimeSpan]) { return [int]$Value.TotalMinutes }
    [int]([TimeSpan]::Parse("$Value")).TotalMinutes
}

function Test-RunningAsSystem {
    try { [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem } catch { $false }
}

function Get-CurrentAccount {
    try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "$env:USERDOMAIN\$env:USERNAME" }
}

# rows of a query on the local instance, as hashtables, with the Windows account that runs the script
function Invoke-SqlQuery([string]$Server, [string]$Query) {
    $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$Server;Database=master;Integrated Security=SSPI;" +
        'Connect Timeout=15;TrustServerCertificate=True;Application Name=vulnagent')
    try {
        $cn.Open()
        $cmd = $cn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = 60
        $rd = $cmd.ExecuteReader()
        $rows = New-Object Collections.Generic.List[hashtable]
        while ($rd.Read()) {
            $h = @{}
            for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }
            $rows.Add($h)
        }
        $rd.Close()
        $rows.ToArray()
    } finally { $cn.Dispose() }
}

# what the SQL Server checks need from one instance, queried once per run. These queries need
# only what NT AUTHORITY\SYSTEM has by default (CONNECT SQL, VIEW ANY DATABASE): the logins and
# server audits are visible only with VIEW ANY DEFINITION, and the checks say so when they are not.
function Get-SqlFacts($Ctx, $I) {
    if ($Ctx.sql.ContainsKey($I.name)) { return $Ctx.sql[$I.name] }
    $perms = "SELECT permission_name AS p FROM fn_my_permissions(NULL, 'SERVER')"
    if (-not (Test-RunningAsSystem)) { $perms = "EXECUTE AS LOGIN = N'NT AUTHORITY\SYSTEM'; $perms; REVERT;" }
    $q = [ordered]@{
        config  = 'SELECT name, CAST(value_in_use AS int) AS v FROM sys.configurations'
        info    = "SELECT CAST(SERVERPROPERTY('IsClustered') AS int) AS clustered, CAST(SERVERPROPERTY('IsHadrEnabled') AS int) AS hadr, " +
                  "HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DEFINITION') AS viewdef"
        sa      = 'SELECT name, CAST(is_disabled AS int) AS disabled FROM sys.sql_logins WHERE principal_id = 1'
        logins  = "SELECT name FROM sys.sql_logins WHERE is_disabled = 0 AND sid <> 0x01 AND name NOT LIKE '##%##' AND (is_policy_checked = 0 OR is_expiration_checked = 0)"
        trusted = "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name <> 'msdb'"
        audit   = 'SELECT DISTINCT d.audit_action_name AS a FROM sys.server_audit_specifications s JOIN sys.server_audits a ON s.audit_guid = a.audit_guid ' +
                  'JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id ' +
                  "WHERE a.is_state_enabled = 1 AND s.is_state_enabled = 1 AND d.audit_action_name IN ('SUCCESSFUL_LOGIN_GROUP', 'FAILED_LOGIN_GROUP')"
        perms   = $perms
    }
    $f = @{ errors = @{}; connect = $null }
    foreach ($k in $q.Keys) {
        if ($f.connect) { $f.errors[$k] = $f.connect; continue }
        try { $f[$k] = @(Invoke-SqlQuery $I.server $q[$k]) }
        catch {
            $m = ("$($_.Exception.Message)" -replace '\s+', ' ').Trim()
            if ($k -eq 'config') { $f.connect = "could not connect to $($I.server) as $(Get-CurrentAccount): $m" ; $m = $f.connect }
            $f.errors[$k] = $m
        }
    }
    $Ctx.sql[$I.name] = $f
    $f
}

function Get-SqlFact($F, [string]$Key) {
    if ($F.errors.ContainsKey($Key)) { throw $F.errors[$Key] }
    $F[$Key]
}

function Get-SqlConfig($F, [string]$Name) {
    $row = @(Get-SqlFact $F 'config' | Where-Object { "$($_.name)" -eq $Name })
    if ($row.Count) { return [int]$row[0].v }
    $null
}

# one item (or more) per instance; $Test gets the instance and its facts and returns @{ label; want; now; ok }
function Get-SqlItems($C, $Ctx, [scriptblock]$Test) {
    $items = @(); $errs = @()
    foreach ($i in @($C.instances)) {
        try { $rs = @(& $Test $i (Get-SqlFacts $Ctx $i)) }
        catch { $errs += "$($i.name): $($_.Exception.Message)"; continue }
        foreach ($r in $rs) { $items += New-CheckItem "$($i.name): $($r.label)" $r.want $r.now ([bool]$r.ok) }
    }
    if ($errs.Count) { throw ($errs -join '; ') }
    New-ItemsResult $items
}

# sys.configurations options, as 'name=value'; an option this SQL Server version does not have passes
function Test-SqlOptions($C, $Ctx) {
    $sqlOpts = @($C.options)
    Get-SqlItems $C $Ctx {
        param($I, $F)
        foreach ($o in $sqlOpts) {
            $name, $want = $o -split '='
            $v = Get-SqlConfig $F $name
            @{ label = $name; want = $want; now = $(if ($null -eq $v) { 'not in this version' } else { "$v" }); ok = ($null -eq $v -or "$v" -eq $want) }
        }
    }
}

function Get-AppCatalog($H, $Cfg) {
    $appcmd = '%windir%\system32\inetsrv\appcmd.exe'
    $Http = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters'
    $sqlcfg = "In SQL Server: EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '<option>', <value>; RECONFIGURE;"
    $iis = @()
    $sql = @()

    if ($Cfg.iis_checks) { $iis = @(
    @{ id = 'IIS-01'; sev = 'Medium'; stig = @('IIST-SV-000138 (CAT II)', 'IIST-SI-000231 (CAT II)')
        title = 'Turn off directory browsing'
        why = 'A directory listing shows every file in a folder, including backups and files that were never meant to be linked.'
        how = "$appcmd set config /section:system.webServer/directoryBrowse /enabled:false, and the same with the site name for a website that turns it on."
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/directoryBrowse' 'directory browsing' 'off' { param($s) @{ now = $(if ("$($s.enabled)" -eq 'True') { 'on' } else { 'off' }); ok = "$($s.enabled)" -ne 'True' } } } }

    @{ id = 'IIS-02'; sev = 'Medium'; stig = @('IIST-SV-000140 (CAT II)', 'IIST-SI-000233 (CAT II)')
        title = 'Show detailed error pages only to local requests'
        why = 'Detailed error pages show paths, modules and configuration to anyone who can cause an error.'
        how = "$appcmd set config /section:system.webServer/httpErrors /errorMode:DetailedLocalOnly"
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/httpErrors' 'error pages (errorMode)' 'DetailedLocalOnly or Custom' { param($s) @{ now = $s.errorMode; ok = @('DetailedLocalOnly', 'Custom') -contains "$($s.errorMode)" } } } }

    @{ id = 'IIS-03'; sev = 'Medium'; stig = @('IIST-SV-000125 (CAT II)')
        title = 'Remove WebDAV publishing'
        why = 'WebDAV lets clients create, change and move files on the web server.'
        how = 'Uninstall-WindowsFeature Web-DAV-Publishing'
        impact = 'Applications that publish or edit files through WebDAV stop working.'
        get = { param($C, $Ctx)
            $on = @((Get-CtxIisSection $Ctx 'system.webServer/globalModules' '').'@items' | Where-Object { "$($_.name)" -eq 'WebDAVModule' }).Count -gt 0
            New-ItemsResult @(New-CheckItem 'WebDAV Publishing (WebDAVModule)' 'not installed' $(if ($on) { 'installed' } else { 'not installed' }) (-not $on)) } }

    @{ id = 'IIS-04'; sev = 'Medium'; stig = @('IIST-SV-000124 (CAT II)', 'IIST-SI-000214 (CAT II)')
        title = 'Remove the MIME types of shell programs (.exe, .dll, .com, .bat, .csh)'
        why = 'With these MIME types, the server hands out executables and scripts that sit in the content folders.'
        how = "$appcmd set config /section:staticContent /-`"[fileExtension='.exe']`", and the same for .dll, .com, .bat and .csh."
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/staticContent' 'MIME types for .exe .dll .com .bat .csh' 'none' {
            param($s) $m = @($s.'@items' | ForEach-Object { "$($_.fileExtension)".ToLower() } | Where-Object { @('.exe', '.dll', '.com', '.bat', '.csh') -contains $_ })
            @{ now = $(if ($m.Count) { $m -join ' ' } else { 'none' }); ok = ($m.Count -eq 0) } } } }

    @{ id = 'IIS-05'; sev = 'Medium'; stig = @('IIST-SV-000103 (CAT II)', 'IIST-SI-000206 (CAT II)')
        title = 'Log to both the log file and Event Tracing for Windows (ETW)'
        why = 'ETW gives the log events in real time to monitoring tools, while the file keeps them.'
        how = "$appcmd set config /section:system.applicationHost/sites /siteDefaults.logFile.logTargetW3C:`"File,ETW`" /commit:apphost (IIS Manager: server > Logging > Both log file and ETW event)."
        get = { param($C, $Ctx)
            $d = (Get-CtxIisSection $Ctx 'system.applicationHost/sites' '').siteDefaults.logFile
            $want = 'File,ETW'
            $places = @(@{ n = 'siteDefaults'; v = $d.logTargetW3C }) + @(Get-CtxIisSites $Ctx | ForEach-Object { @{ n = "site $($_.name)"; v = (Get-IisSiteLog $_ $d 'logTargetW3C') } })
            New-ItemsResult @(foreach ($p in $places) { $l = Split-IisList $p.v
                New-CheckItem "$($p.n): log destination" $want ($l -join ',') (($l -contains 'File') -and ($l -contains 'ETW')) }) } }

    @{ id = 'IIS-06'; sev = 'Medium'; stig = @('IIST-SV-000110 (CAT II)', 'IIST-SV-000111 (CAT II)', 'IIST-SI-000209 (CAT II)', 'IIST-SI-000210 (CAT II)')
        title = 'Log the user, client and result of each request'
        why = 'Without the user name, user agent, referrer and these headers, the log cannot show who did what and whether it worked.'
        how = 'IIS Manager: server > Logging > Format W3C > Select Fields: tick User Agent, User Name and Referer; add the custom fields Request Header Connection, Warning and Authorization, and Response Header Content-Type.'
        get = { param($C, $Ctx)
            $d = (Get-CtxIisSection $Ctx 'system.applicationHost/sites' '').siteDefaults.logFile
            $std = @('UserAgent', 'UserName', 'Referer')
            $cus = @('RequestHeader/Connection', 'RequestHeader/Warning', 'RequestHeader/Authorization', 'ResponseHeader/Content-Type')
            $places = @(@{ n = 'siteDefaults'; format = $d.logFormat; flags = $d.logExtFileFlags; fields = @(Get-IisLogFields $d) })
            foreach ($s in Get-CtxIisSites $Ctx) {
                $f = @(Get-IisLogFields $s.log)
                if (-not $f.Count) { $f = @(Get-IisLogFields $d) }
                $places += @{ n = "site $($s.name)"; format = (Get-IisSiteLog $s $d 'logFormat'); flags = (Get-IisSiteLog $s $d 'logExtFileFlags'); fields = $f }
            }
            New-ItemsResult @(foreach ($p in $places) {
                $miss = @()
                if ("$($p.format)" -ne 'W3C') { $miss += "W3C format (now $($p.format))" }
                $have = Split-IisList $p.flags
                $miss += @($std | Where-Object { $have -notcontains $_ })
                $miss += @($cus | Where-Object { @($p.fields) -notcontains $_ } | ForEach-Object { $t, $n = $_ -split '/'; "$n ($(($t -replace 'Header', '').ToLower()) header)" })
                New-CheckItem "$($p.n): log fields" 'W3C with User Agent, User Name, Referer and the custom fields Connection, Warning, Authorization, Content-Type' $(if ($miss.Count) { 'missing: ' + ($miss -join ', ') } else { 'all logged' }) ($miss.Count -eq 0) }) } }

    @{ id = 'IIS-07'; sev = 'Medium'; kind = 'reg'; fix = 'review'; reboot = $true; stig = @('IIST-SI-000270 (CAT II)')
        title = 'Remove the HTTP.sys Server header'
        why = 'The Server header (Microsoft-HTTPAPI/2.0) tells attackers which software and version answer.'
        impact = 'Takes effect after the HTTP service or the machine restarts. Rarely, a client or monitoring check expects the header.'
        items = @(Reg $Http 'DisableServerHeader' @(1, 2) -Op 'in' -Set 1) }

    @{ id = 'IIS-08'; sev = 'Low'; minBuild = 17763
        title = 'Remove the IIS Server header'
        why = 'The Server header (Microsoft-IIS/10.0) tells attackers which software answers.'
        how = "$appcmd set config /section:system.webServer/security/requestFiltering /removeServerHeader:true"
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/security/requestFiltering' 'removeServerHeader' 'True' { param($s) @{ now = $s.removeServerHeader; ok = "$($s.removeServerHeader)" -eq 'True' } } } }

    @{ id = 'IIS-09'; sev = 'Low'; stig = @('IIST-SV-000215 (CAT III)')
        title = 'Remove the X-Powered-By header'
        why = 'The header tells attackers that ASP.NET runs on the server.'
        how = "$appcmd set config /section:system.webServer/httpProtocol /-`"customHeaders.[name='X-Powered-By']`""
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/httpProtocol' 'X-Powered-By header' 'removed' {
            param($s) $on = @($s.customHeaders.'@items' | Where-Object { "$($_.name)" -eq 'X-Powered-By' }).Count -gt 0
            @{ now = $(if ($on) { 'sent' } else { 'removed' }); ok = -not $on } } } }

    @{ id = 'IIS-10'; sev = 'Low'; minBuild = 17763; stig = @('IIST-SV-000205 (CAT III)')
        title = 'Turn on HTTP Strict Transport Security (HSTS)'
        why = 'HSTS makes browsers use HTTPS only, so a first plain HTTP request cannot be intercepted or downgraded.'
        how = "$appcmd set config /section:system.applicationHost/sites /siteDefaults.hsts.enabled:true /siteDefaults.hsts.max-age:31536000 /siteDefaults.hsts.includeSubDomains:true /siteDefaults.hsts.redirectHttpToHttps:true /commit:apphost"
        impact = 'Browsers then refuse plain HTTP for the site and, with includeSubDomains, for all its subdomains. Every website and subdomain needs a working HTTPS binding first.'
        get = { param($C, $Ctx)
            $h = (Get-CtxIisSection $Ctx 'system.applicationHost/sites' '').siteDefaults.hsts
            if (-not $h) { return New-ItemsResult @(New-CheckItem 'siteDefaults: HSTS' 'on' 'not available in this IIS version' $true) }
            New-ItemsResult @(
                (New-CheckItem 'siteDefaults: hsts enabled' 'True' "$($h.enabled)" ("$($h.enabled)" -eq 'True')),
                (New-CheckItem 'siteDefaults: hsts max-age' 'more than 0' "$($h['max-age'])" ([long]"0$($h['max-age'])" -gt 0)),
                (New-CheckItem 'siteDefaults: hsts includeSubDomains' 'True' "$($h.includeSubDomains)" ("$($h.includeSubDomains)" -eq 'True')),
                (New-CheckItem 'siteDefaults: hsts redirectHttpToHttps' 'True' "$($h.redirectHttpToHttps)" ("$($h.redirectHttpToHttps)" -eq 'True'))) } }

    @{ id = 'IIS-11'; sev = 'Medium'; stig = @('IIST-SV-000134 (CAT II)', 'IIST-SV-000135 (CAT II)', 'IIST-SI-000202 (CAT II)')
        title = 'Keep ASP.NET session IDs in cookies, with a 15-minute time-out'
        why = 'Session IDs in the URL end up in logs, browser history and referrer headers; a short time-out limits how long a stolen ID works.'
        how = "$appcmd set config /section:system.web/sessionState /cookieless:UseCookies /timeout:00:15:00 (IIS Manager: server > Session State)."
        impact = 'Users are signed out after 15 idle minutes.'
        get = { param($C, $Ctx)
            if (-not (Test-IisAspNet $Ctx)) { return New-ItemsResult @(New-CheckItem 'ASP.NET' 'not installed, or session state in cookies' 'not installed' $true) }
            $r = Get-IisItems $Ctx 'system.web/sessionState' 'session state mode (cookieless)' 'UseCookies' { param($s) @{ now = $s.cookieless; ok = "$($s.cookieless)" -eq 'UseCookies' } }
            $m = ConvertTo-Minutes (Get-CtxIisSection $Ctx 'system.web/sessionState' '').timeout
            New-ItemsResult (@($r.items) + @(New-CheckItem 'server: session time-out' '15 minutes or less' "$m minutes" ($m -le 15))) } }

    @{ id = 'IIS-12'; sev = 'Medium'; stig = @('IIST-SV-000137 (CAT II)')
        title = 'Use SHA-2 for the ASP.NET machine key'
        why = 'The machine key protects view state and forms authentication cookies; SHA-1 and MD5 validation can be forged more easily.'
        how = "$appcmd set config /section:system.web/machineKey /validation:HMACSHA256 /decryption:Auto (IIS Manager: server > Machine Key)."
        get = { param($C, $Ctx)
            if (-not (Test-IisAspNet $Ctx)) { return New-ItemsResult @(New-CheckItem 'ASP.NET' 'not installed, or SHA-2' 'not installed' $true) }
            $k = Get-CtxIisSection $Ctx 'system.web/machineKey' ''
            New-ItemsResult @(
                (New-CheckItem 'server: machineKey validation' 'HMACSHA256, HMACSHA384 or HMACSHA512' "$($k.validation)" (@('HMACSHA256', 'HMACSHA384', 'HMACSHA512') -contains "$($k.validation)")),
                (New-CheckItem 'server: machineKey decryption' 'Auto' "$($k.decryption)" ("$($k.decryption)" -eq 'Auto'))) } }

    @{ id = 'IIS-13'; sev = 'Medium'; kind = 'reg'; fix = 'review'; reboot = $true; stig = @('IIST-SV-000220 (CAT II)')
        title = 'Turn on the HTTP request smuggling filter'
        why = 'Without the filter, a request that a proxy and IIS read differently can be used to hijack other users'' requests.'
        impact = 'HTTP.sys rejects ambiguous requests. Takes effect after the HTTP service or the machine restarts.'
        items = @(Reg $Http 'DisableRequestSmuggling' 1) }

    @{ id = 'IIS-14'; sev = 'Low'
        title = 'Block TRACE requests'
        why = 'TRACE echoes the request back, including headers, which can help cross-site tracing attacks.'
        how = "$appcmd set config /section:system.webServer/security/requestFiltering /+`"verbs.[verb='TRACE',allowed='false']`""
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/security/requestFiltering' 'TRACE requests' 'blocked' {
            param($s) $t = @($s.verbs.'@items' | Where-Object { "$($_.verb)" -eq 'TRACE' })
            $blocked = if ($t.Count) { "$($t[0].allowed)" -eq 'False' } else { "$($s.verbs.allowUnlisted)" -eq 'False' }
            @{ now = $(if ($blocked) { 'blocked' } else { 'allowed' }); ok = $blocked } } } }

    @{ id = 'IIS-15'; sev = 'Medium'; stig = @('IIST-SI-000229 (CAT II)')
        title = 'Reject double-encoded URLs'
        why = 'Double encoding is used to slip paths and characters past filters.'
        how = "$appcmd set config /section:system.webServer/security/requestFiltering /allowDoubleEscaping:false"
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/security/requestFiltering' 'allowDoubleEscaping' 'False' { param($s) @{ now = $s.allowDoubleEscaping; ok = "$($s.allowDoubleEscaping)" -eq 'False' } } } }

    @{ id = 'IIS-16'; sev = 'Medium'; stig = @('IIST-SI-000228 (CAT II)')
        title = 'Reject URLs with non-ASCII characters'
        why = 'Non-ASCII characters in URLs are used to get around filters and to attack the URL parsers.'
        how = "$appcmd set config /section:system.webServer/security/requestFiltering /allowHighBitCharacters:false"
        impact = 'URLs with characters such as accented letters in file or folder names then get error 404.'
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/security/requestFiltering' 'allowHighBitCharacters' 'False' { param($s) @{ now = $s.allowHighBitCharacters; ok = "$($s.allowHighBitCharacters)" -eq 'False' } } } }

    @{ id = 'IIS-17'; sev = 'Medium'; stig = @('IIST-SI-000225 (CAT II)', 'IIST-SI-000226 (CAT II)', 'IIST-SI-000227 (CAT II)')
        title = 'Limit the length of URLs and query strings and the size of requests'
        why = 'Request limits protect against buffer overflows and requests that tie up the server.'
        how = "$appcmd set config /section:system.webServer/security/requestFiltering /requestLimits.maxUrl:4096 /requestLimits.maxQueryString:2048 /requestLimits.maxAllowedContentLength:30000000"
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/security/requestFiltering' 'request limits' 'maxUrl 4096, maxQueryString 2048, maxAllowedContentLength 2147483647 or less' {
            param($s) $l = $s.requestLimits
            @{ now = "maxUrl $($l.maxUrl), maxQueryString $($l.maxQueryString), maxAllowedContentLength $($l.maxAllowedContentLength)"
               ok = ([long]"0$($l.maxUrl)" -le 4096 -and [long]"0$($l.maxQueryString)" -le 2048 -and [long]"0$($l.maxAllowedContentLength)" -le 2147483647) } } } }

    @{ id = 'IIS-18'; sev = 'Medium'; stig = @('IIST-SI-000230 (CAT II)')
        title = 'Allow only listed file extensions'
        why = 'With unlisted extensions allowed, backups, configuration and other files the site never meant to serve can be requested.'
        how = "List the extensions the site uses, for example $appcmd set config /section:requestFiltering /+`"fileExtensions.[fileExtension='.html',allowed='true']`", then $appcmd set config /section:requestFiltering /fileExtensions.allowUnlisted:false"
        impact = 'Every file type the site serves must be listed first, including the extensionless URLs, or those requests get error 404.'
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/security/requestFiltering' 'unlisted file extensions' 'not allowed' {
            param($s) $a = "$($s.fileExtensions.allowUnlisted)" -ne 'False'
            @{ now = $(if ($a) { 'allowed' } else { 'not allowed' }); ok = -not $a } } } }

    @{ id = 'IIS-19'; sev = 'Medium'; stig = @('IIST-SI-000234 (CAT II)')
        title = 'Turn off ASP.NET debugging'
        why = 'Debug compilation shows detailed errors and source details and slows the application.'
        how = "$appcmd set config `"<site>`" /section:system.web/compilation /debug:false, or set debug=`"false`" in the site's web.config."
        get = { param($C, $Ctx)
            if (-not (Test-IisAspNet $Ctx)) { return New-ItemsResult @(New-CheckItem 'ASP.NET' 'not installed, or debugging off' 'not installed' $true) }
            Get-IisItems $Ctx 'system.web/compilation' 'compilation debug' 'False' { param($s) @{ now = $s.debug; ok = "$($s.debug)" -ne 'True' } } } }

    @{ id = 'IIS-20'; sev = 'Medium'; stig = @('IIST-SI-000251 (CAT II)')
        title = 'Give each website its own application pool'
        why = 'Websites that share a pool run in the same process and with the same identity, so one compromised site reaches the others.'
        how = "Create a pool per website and assign it: $appcmd add apppool /name:<site>, then $appcmd set app `"<site>/`" /applicationPool:<site>"
        get = { param($C, $Ctx)
            $sites = @(Get-CtxIisSites $Ctx)
            if (-not $sites.Count) { return New-ItemsResult @(New-CheckItem 'websites' 'own application pool' 'no websites' $true) }
            New-ItemsResult @(foreach ($s in $sites) {
                $others = @($sites | Where-Object { $_.pool -eq $s.pool -and $_.name -ne $s.name } | ForEach-Object { $_.name })
                New-CheckItem "site $($s.name): application pool" 'used by this website only' $(if ($others.Count) { "$($s.pool), shared with " + ($others -join ', ') } else { $s.pool }) ($others.Count -eq 0) }) } }

    @{ id = 'IIS-21'; sev = 'Medium'; stig = @('IIST-SI-000224 (CAT II)')
        title = 'Keep website content off the system drive'
        why = 'Content on the system drive can fill it up, and path traversal bugs reach the system files more easily.'
        how = 'Move the content to another volume and change the physical path of the website (IIS Manager: site > Basic Settings).'
        get = { param($C, $Ctx)
            $sys = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
            $sites = @(Get-CtxIisSites $Ctx)
            if (-not $sites.Count) { return New-ItemsResult @(New-CheckItem 'websites' 'content off the system drive' 'no websites' $true) }
            New-ItemsResult @(foreach ($s in $sites) {
                $on = $s.path -eq $sys -or $s.path -like "$sys\*"
                New-CheckItem "site $($s.name): content folder" "not on $sys" $s.path (-not $on) }) } }

    @{ id = 'IIS-22'; sev = 'Medium'
        title = 'Run application pools under their own identity, not LocalSystem or a shared service account'
        why = 'A pool running as LocalSystem gives full control of the machine to whoever compromises the website; NetworkService and LocalService are shared with other services.'
        how = "$appcmd set apppool <pool> /processModel.identityType:ApplicationPoolIdentity (or a dedicated account)"
        impact = 'The website then runs as IIS AppPool\<pool>, which needs read access to its content and, for network resources, its own rights.'
        get = { param($C, $Ctx)
            $pools = @(Get-CtxIisPools $Ctx)
            if (-not $pools.Count) { return New-ItemsResult @(New-CheckItem 'application pools' 'own identity' 'no application pools' $true) }
            New-ItemsResult @(foreach ($p in $pools) {
                New-CheckItem "pool $($p.name): identity" 'ApplicationPoolIdentity or a dedicated account' $p.identity (@('LocalSystem', 'NetworkService', 'LocalService') -notcontains $p.identity) }) } }

    @{ id = 'IIS-23'; sev = 'Low'
        title = 'Do not allow unlisted ISAPI and CGI modules'
        why = 'Only the ISAPI and CGI modules that were explicitly allowed should be able to run.'
        how = "$appcmd set config /section:system.webServer/security/isapiCgiRestriction /notListedIsapisAllowed:false /notListedCgisAllowed:false"
        get = { param($C, $Ctx)
            $r = Get-CtxIisSection $Ctx 'system.webServer/security/isapiCgiRestriction' ''
            New-ItemsResult @(
                (New-CheckItem 'server: notListedIsapisAllowed' 'False' "$($r.notListedIsapisAllowed)" ("$($r.notListedIsapisAllowed)" -ne 'True')),
                (New-CheckItem 'server: notListedCgisAllowed' 'False' "$($r.notListedCgisAllowed)" ("$($r.notListedCgisAllowed)" -ne 'True'))) } }

    @{ id = 'IIS-24'; sev = 'Low'
        title = 'Do not give handlers both write and script or execute access'
        why = 'If uploaded files can also run, an attacker who can write a file can run code on the server.'
        how = "$appcmd set config /section:system.webServer/handlers /accessPolicy:Read,Script"
        get = { param($C, $Ctx) Get-IisItems $Ctx 'system.webServer/handlers' 'handler access policy' 'not Write together with Script or Execute' {
            param($s) $a = Split-IisList $s.accessPolicy
            @{ now = ($a -join ','); ok = -not (($a -contains 'Write') -and (($a -contains 'Script') -or ($a -contains 'Execute'))) } } } }
    ) }

    if ($Cfg.sql_checks) { $sql = @(
    @{ id = 'SQL-01'; sev = 'Medium'; stig = @('SQLI-22-016200 (CAT II)')
        title = 'Disable the sa login'
        why = 'sa is the best-known SQL Server administrator login and the first one attackers try.'
        how = 'In SQL Server: ALTER LOGIN [sa] DISABLE; (with its current name if it was renamed). Check first that no application signs in as sa.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $sa = @(Get-SqlFact $F 'sa')
            if (-not $sa.Count) { throw 'the sa login is not visible to this account' }
            @{ label = 'sa login'; want = 'disabled'; now = $(if ($sa[0].disabled) { 'disabled' } else { 'enabled' }) + " (name: $($sa[0].name))"; ok = [bool]$sa[0].disabled } } } }

    @{ id = 'SQL-02'; sev = 'Medium'; stig = @('SQLI-22-016300 (CAT II)')
        title = 'Rename the sa login'
        why = 'Attackers guess passwords for the name sa; another name has to be found first.'
        how = 'In SQL Server: ALTER LOGIN [sa] WITH NAME = [<new name>];'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $sa = @(Get-SqlFact $F 'sa')
            if (-not $sa.Count) { throw 'the sa login is not visible to this account' }
            @{ label = 'name of the sa login'; want = 'not sa'; now = "$($sa[0].name)"; ok = "$($sa[0].name)" -ne 'sa' } } } }

    @{ id = 'SQL-03'; sev = 'Medium'; stig = @('SQLI-22-007200 (CAT II)'); options = @('xp_cmdshell=0')
        title = 'Turn off xp_cmdshell'
        why = 'xp_cmdshell runs operating system commands from SQL, with the rights of the SQL Server service.'
        how = $sqlcfg.Replace('<option>', 'xp_cmdshell').Replace('<value>', '0')
        get = { param($C, $Ctx) Test-SqlOptions $C $Ctx } }

    @{ id = 'SQL-04'; sev = 'Medium'; stig = @('SQLI-22-007300 (CAT II)'); options = @('clr enabled=0')
        title = 'Turn off CLR integration unless an application needs it'
        why = 'CLR assemblies run .NET code inside SQL Server.'
        how = $sqlcfg.Replace('<option>', 'clr enabled').Replace('<value>', '0')
        impact = 'Databases that use CLR assemblies (for example SSIS catalogs or some vendor applications) stop working: check with SELECT * FROM sys.assemblies WHERE is_user_defined = 1 in each database first.'
        get = { param($C, $Ctx) Test-SqlOptions $C $Ctx } }

    @{ id = 'SQL-05'; sev = 'Medium'; stig = @('SQLI-22-017000 (CAT II)'); options = @('Ole Automation Procedures=0')
        title = 'Turn off OLE Automation procedures'
        why = 'OLE Automation procedures create COM objects from SQL, with the rights of the SQL Server service.'
        how = $sqlcfg.Replace('<option>', 'Ole Automation Procedures').Replace('<value>', '0')
        get = { param($C, $Ctx) Test-SqlOptions $C $Ctx } }

    @{ id = 'SQL-06'; sev = 'Medium'; stig = @('SQLI-22-017200 (CAT II)'); options = @('remote access=0')
        title = 'Turn off remote access (remote stored procedure calls)'
        why = 'Remote access lets other servers run stored procedures on this instance; it is deprecated and replaced by linked servers.'
        how = $sqlcfg.Replace('<option>', 'remote access').Replace('<value>', '0')
        get = { param($C, $Ctx) Test-SqlOptions $C $Ctx } }

    @{ id = 'SQL-07'; sev = 'Medium'
        stig = @('SQLI-22-017700 (CAT II)', 'SQLI-22-017900 (CAT II)', 'SQLI-22-017500 (CAT II)', 'SQLI-22-017400 (CAT II)', 'SQLI-22-017600 (CAT II)', 'SQLI-22-016800 (CAT II)', 'SQLI-22-017100 (CAT II)')
        options = @('external scripts enabled=0', 'replication xps=0', 'allow polybase export=0', 'hadoop connectivity=0', 'remote data archive=0', 'filestream access level=0', 'user options=0')
        title = 'Turn off the SQL Server features that are not needed'
        why = 'Every feature that is on (external scripts, replication procedures, PolyBase export, Hadoop, Stretch, FILESTREAM, user options) adds code that can be attacked.'
        how = $sqlcfg + ' Turn off only the features that are not used: replication needs replication xps, and FILESTREAM databases need filestream access level.'
        get = { param($C, $Ctx) Test-SqlOptions $C $Ctx } }

    @{ id = 'SQL-08'; sev = 'Low'
        options = @('Ad Hoc Distributed Queries=0', 'cross db ownership chaining=0', 'scan for startup procs=0', 'remote admin connections=0', 'contained database authentication=0')
        title = 'Turn off the server options that widen access'
        why = 'Ad hoc distributed queries, cross-database ownership chaining, startup procedures, remote admin connections and contained database logins all open ways around the normal permissions.'
        how = $sqlcfg + ' A failover cluster may need remote admin connections, and replication may need scan for startup procs.'
        get = { param($C, $Ctx) Test-SqlOptions $C $Ctx } }

    @{ id = 'SQL-09'; sev = 'High'; stig = @('SQLI-22-007900 (CAT I)')
        title = 'Use Windows Authentication, or make SQL logins follow the password policy and expiry'
        why = 'SQL logins have their own passwords; without the Windows password policy they can be short, never expire and are never locked out.'
        how = 'For each SQL login: ALTER LOGIN [<login>] WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON; or switch the instance to Windows Authentication mode (server Properties > Security) and restart it.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $want = 'Windows only, or SQL logins with CHECK_POLICY and CHECK_EXPIRATION'
            if ([int](Get-RegValue "$($I.key)\MSSQLServer" 'LoginMode').value -eq 1) { return @{ label = 'authentication'; want = $want; now = 'Windows only'; ok = $true } }
            if ([int]@(Get-SqlFact $F 'info')[0].viewdef -ne 1) {
                return @{ label = 'authentication'; want = $want; now = 'Windows and SQL logins; the SQL logins are not visible to this account, check them as a SQL administrator'; ok = $false }
            }
            $bad = @(Get-SqlFact $F 'logins' | ForEach-Object { $_.name })
            @{ label = 'authentication'; want = $want; ok = ($bad.Count -eq 0)
               now = 'Windows and SQL logins; ' + $(if ($bad.Count) { 'without the password policy or expiry: ' + ($bad -join ', ') } else { 'all SQL logins use the policy and expiry' }) } } } }

    @{ id = 'SQL-10'; sev = 'Medium'; stig = @('SQLI-22-014800 (CAT II)')
        title = 'Audit successful and failed logins'
        why = 'Without login auditing, password guessing and the use of stolen logins leave no trace.'
        how = 'SSMS: server Properties > Security > Login auditing: Both failed and successful logins, then restart the SQL Server service. Or a server audit with SUCCESSFUL_LOGIN_GROUP and FAILED_LOGIN_GROUP.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $want = 'both failed and successful logins (or a server audit of both)'
            $lvl = [int](Get-RegValue "$($I.key)\MSSQLServer" 'AuditLevel').value
            $now = @('none', 'successful logins only', 'failed logins only', 'both failed and successful logins')[$lvl -band 3]
            if (($lvl -band 3) -eq 3) { return @{ label = 'login auditing'; want = $want; now = $now; ok = $true } }
            $groups = @(); $seen = $false
            try { $groups = @(Get-SqlFact $F 'audit' | ForEach-Object { $_.a }); $seen = [int]@(Get-SqlFact $F 'info')[0].viewdef -eq 1 } catch { }
            $both = ($groups -contains 'SUCCESSFUL_LOGIN_GROUP') -and ($groups -contains 'FAILED_LOGIN_GROUP')
            $now += '; server audit: ' + $(if ($both) { 'logs both' } elseif ($seen) { 'does not log both' } else { 'not visible to this account' })
            @{ label = 'login auditing'; want = $want; now = $now; ok = $both } } } }

    @{ id = 'SQL-11'; sev = 'High'; stig = @('SQLI-22-008200 (CAT I)')
        title = 'Force encrypted connections when SQL logins are used'
        why = 'With SQL logins, the password crosses the network; without forced encryption and a proper certificate it can be captured.'
        how = 'SQL Server Configuration Manager > SQL Server Network Configuration > Protocols for <instance> > Properties: on Certificate choose the server certificate, on Flags set Force Encryption to Yes; then restart the SQL Server service.'
        impact = 'Clients that cannot use TLS 1.2, or do not trust the certificate, can no longer connect.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $want = 'Force Encryption on, with a certificate (not needed with Windows Authentication only)'
            if ([int](Get-RegValue "$($I.key)\MSSQLServer" 'LoginMode').value -eq 1) { return @{ label = 'encryption'; want = $want; now = 'Windows Authentication only: not needed'; ok = $true } }
            $nl = "$($I.key)\MSSQLServer\SuperSocketNetLib"
            $fe = [int](Get-RegValue $nl 'ForceEncryption').value -eq 1
            $cert = "$((Get-RegValue $nl 'Certificate').value)".Trim() -ne ''
            @{ label = 'encryption'; want = $want; now = "Force Encryption $(if ($fe) { 'on' } else { 'off' }), certificate $(if ($cert) { 'set' } else { 'not set' })"; ok = ($fe -and $cert) } } } }

    @{ id = 'SQL-12'; sev = 'Medium'; stig = @('SQLI-22-016000 (CAT II)')
        title = 'Turn off customer feedback and error reporting to Microsoft'
        why = 'Usage and error reports can contain details of the server and its data.'
        how = 'Set CustomerFeedback and EnableErrorReporting to 0 under HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance ID>\CPE and HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<version, such as 160>, or use the SQL Server Error and Usage Reporting tool.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $on = @()
            foreach ($k in @("$($I.key)\CPE", "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($I.major * 10)")) {
                foreach ($n in 'CustomerFeedback', 'EnableErrorReporting') {
                    $r = Get-RegValue $k $n
                    if ($r.exists -and [int]$r.value -ne 0) { $on += "$(@($k -split '\\')[-1])\$n" }
                }
            }
            @{ label = 'feedback and error reporting'; want = 'off'; now = $(if ($on.Count) { 'on: ' + ($on -join ', ') } else { 'off' }); ok = ($on.Count -eq 0) } } } }

    @{ id = 'SQL-13'; sev = 'Medium'; stig = @('SQLI-22-017800 (CAT II)')
        title = 'Disable the SQL Server Browser service unless named instances need it'
        why = 'The Browser service answers on UDP 1434 and tells anyone which instances and ports the server has.'
        how = 'Set-Service SQLBrowser -StartupType Disabled; Stop-Service SQLBrowser. Clients of named instances then connect with server,port.'
        impact = 'Clients that connect to a named instance by name only (server\instance) stop finding it until they use the port.'
        get = { param($C, $Ctx)
            $b = @(Get-CtxServices $Ctx | Where-Object { $_.Name -eq 'SQLBrowser' })
            if (-not $b.Count) { return New-ItemsResult @(New-CheckItem 'SQL Server Browser service' 'Disabled' 'not installed' $true) }
            New-ItemsResult @(New-CheckItem 'SQL Server Browser service' 'Disabled' "$($b[0].StartMode), $($b[0].State)" ("$($b[0].StartMode)" -eq 'Disabled')) } }

    @{ id = 'SQL-14'; sev = 'Medium'; stig = @('SQLI-22-012400 (CAT II)')
        title = 'Run each SQL Server service under its own account'
        why = 'A service running as LocalSystem, or sharing an account with another service, gives an attacker who takes over SQL Server more than that one service.'
        how = 'SQL Server Configuration Manager > SQL Server Services > Properties > Log On: use the virtual account (NT SERVICE\<service>), a group managed service account or a dedicated domain account per service.'
        get = { param($C, $Ctx)
            $svc = @(Get-CtxServices $Ctx | Where-Object { $_.Name -match '^(MSSQLSERVER|SQLSERVERAGENT|MSSQLServerOLAPService|ReportServer|MSSQLFDLauncher|MSSQLLaunchpad|SQLPBDMS|SQLPBENGINE)$|^(MSSQL|SQLAgent|MSOLAP|ReportServer|MSSQLFDLauncher|MSSQLLaunchpad)\$|^MsDtsServer\d+$' })
            if (-not $svc.Count) { return New-ItemsResult @(New-CheckItem 'SQL Server services' 'own account' 'none found' $true) }
            New-ItemsResult @(foreach ($s in $svc) {
                $a = "$($s.StartName)"
                $builtin = $a -match '^(\.\\)?LocalSystem$|^NT AUTHORITY\\(SYSTEM|NETWORK ?SERVICE|LOCAL ?SERVICE)$'
                $shared = ($a -notmatch '^NT SERVICE\\') -and @($svc | Where-Object { "$($_.StartName)" -eq $a -and $_.Name -ne $s.Name }).Count -gt 0
                New-CheckItem "$($s.Name): account" 'its own account' $(if ($shared) { "$a (shared)" } else { $a }) (-not ($builtin -or $shared)) }) } }

    @{ id = 'SQL-15'; sev = 'Medium'; stig = @('SQLI-22-004100 (CAT II)')
        title = 'Do not give NT AUTHORITY\SYSTEM administrative rights in SQL Server'
        why = 'Every service on the machine runs as SYSTEM; with administrative rights in SQL Server, any of them can read and change all databases.'
        how = 'In SQL Server, remove NT AUTHORITY\SYSTEM (and any Windows group it belongs to, such as BUILTIN\Administrators) from sysadmin and revoke its other server permissions.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $info = @(Get-SqlFact $F 'info')[0]
            $allowed = @('CONNECT SQL', 'VIEW ANY DATABASE')
            if ([int]$info.hadr -eq 1) { $allowed += 'CREATE AVAILABILITY GROUP', 'ALTER ANY AVAILABILITY GROUP', 'VIEW SERVER STATE', 'VIEW SERVER PERFORMANCE STATE', 'VIEW SERVER SECURITY STATE' }
            elseif ([int]$info.clustered -eq 1) { $allowed += 'VIEW SERVER STATE', 'VIEW SERVER PERFORMANCE STATE', 'VIEW SERVER SECURITY STATE' }
            $extra = @(Get-SqlFact $F 'perms' | ForEach-Object { "$($_.p)" } | Where-Object { $allowed -notcontains $_ } | Sort-Object -Unique)
            $now = if (-not $extra.Count) { 'nothing more' } elseif ($extra.Count -gt 6) { 'also ' + (($extra | Select-Object -First 6) -join ', ') + " and $($extra.Count - 6) more" } else { 'also ' + ($extra -join ', ') }
            @{ label = 'permissions of NT AUTHORITY\SYSTEM'; want = 'only ' + ($allowed -join ', '); now = $now; ok = ($extra.Count -eq 0) } } } }

    @{ id = 'SQL-16'; sev = 'Low'; options = @('default trace enabled=1')
        title = 'Keep the default trace on'
        why = 'The default trace records configuration changes, logins added and objects dropped; it is often the only record of what happened.'
        how = $sqlcfg.Replace('<option>', 'default trace enabled').Replace('<value>', '1')
        get = { param($C, $Ctx) Test-SqlOptions $C $Ctx } }

    @{ id = 'SQL-17'; sev = 'Low'
        title = 'Keep at least 12 SQL Server error logs'
        why = 'With the default of 6, a few restarts are enough to delete the logs of an incident.'
        how = 'SSMS: Management > SQL Server Logs > Configure: limit the number of error log files to 12 or more.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $r = Get-RegValue "$($I.key)\MSSQLServer" 'NumErrorLogs'
            $n = if ($r.exists) { [int]$r.value } else { 6 }
            @{ label = 'number of error logs'; want = '12 or more'; now = $(if ($r.exists) { "$n" } else { 'not set (default 6)' }); ok = ($n -ge 12) } } } }

    @{ id = 'SQL-18'; sev = 'Medium'
        title = 'Do not mark user databases TRUSTWORTHY'
        why = 'In a TRUSTWORTHY database, its owner (often a sysadmin) can be impersonated by code in the database, which leads to sysadmin rights.'
        how = 'In SQL Server: ALTER DATABASE [<database>] SET TRUSTWORTHY OFF; check first whether an application needs it.'
        get = { param($C, $Ctx) Get-SqlItems $C $Ctx { param($I, $F)
            $db = @(Get-SqlFact $F 'trusted' | ForEach-Object { $_.name })
            @{ label = 'TRUSTWORTHY databases (except msdb)'; want = 'none'; now = $(if ($db.Count) { $db -join ', ' } else { 'none' }); ok = ($db.Count -eq 0) } } } }
    ) }

    foreach ($c in $iis) { $c.area = 'IIS'; $c.scope = @('iis'); $c.ms = 'not included (IIS setting)'
                           $c.stigName = 'DISA STIG Microsoft IIS 10.0 Server V3R7 and Site V2R16' }
    foreach ($c in $sql) { $c.area = 'SQL Server'; $c.scope = @('sql'); $c.ms = 'not included (SQL Server setting)'; $c.instances = @($H.sql)
                           $c.stigName = 'DISA STIG Microsoft SQL Server 2022 Instance V1R4' }
    $all = @($iis) + @($sql)
    foreach ($c in $all) {
        $c.app = $true
        if (-not $c.kind) { $c.kind = 'custom' }
        if (-not $c.fix) { $c.fix = 'manual' }
        if (-not $c.match) { $c.match = 'all' }
        if (-not $c.stig) { $c.stig = @() }
        if (-not $c.stig.Count) { $c.stigName = $null }
    }
    $all
}

function Test-Scope($C, $H, $Ctx) {
    if ($C.cisOnly -and -not (@($C.cis).Count + @($C.def).Count)) { return $false }
    foreach ($s in @($C.scope)) {
        switch ($s) {
            'server'   { if (-not $H.server) { return $false } }
            'client'   { if ($H.server) { return $false } }
            'dc'       { if (-not $H.dc) { return $false } }
            'notdc'    { if ($H.dc) { return $false } }
            'member'   { if (-not $H.domain -or $H.dc) { return $false } }
            'domain'   { if (-not $H.domain) { return $false } }
            'defender' { if (-not $Ctx.defender) { return $false } }
            'iis'      { if (-not $H.iis) { return $false } }
            'sql'      { if (-not @($H.sql).Count) { return $false } }
        }
    }
    -not ($C.minBuild -and $H.build -lt $C.minBuild)
}

# --------------------------------------------------------------------------
# audit, findings
# --------------------------------------------------------------------------

function Invoke-Audit($Catalog, $Ctx, $Accepted) {
    foreach ($c in $Catalog) {
        $r = [pscustomobject]@{ id = $c.id; area = $c.area; title = $c.title; severity = $c.sev; fix = $c.fix
                                status = 'pass'; items = @(); state = $null; error = $null; changed = $false; check = $c }
        try {
            $t = Test-Check $c $Ctx
            $r.items = @($t.items)
            $r.state = $t.state
            $r.status = if ($t.ok) { 'pass' } else { 'fail' }
        } catch {
            $r.status = 'error'
            $r.error = $_.Exception.Message
        }
        if ($r.status -ne 'pass' -and (Test-IdMatch $c.id $c.area $Accepted)) { $r.status = 'exception' }
        $r
    }
}

function New-Finding([hashtable]$F) {
    $out = [ordered]@{}
    foreach ($k in 'title', 'severity', 'description', 'mitigation', 'references', 'component_name',
                   'component_version', 'vuln_id_from_tool', 'unique_id_from_tool') {
        $v = $F[$k]
        if ($null -eq $v -or ($v -is [string] -and $v -eq '')) { continue }
        $out[$k] = $v
    }
    $out['title'] = Get-Clip $out['title'] 500
    $out['static_finding'] = $true
    $out['dynamic_finding'] = $false
    $out['tags'] = $F['tags']
    $out
}

function Get-FixText($C) {
    switch ($C.fix) {
        'safe'   { return "Fix: vulnagent-local-harden.ps1 -Apply safe -Only $($C.id)" }
        'review' { return "Test the impact first, then fix: vulnagent-local-harden.ps1 -Apply all -Only $($C.id)" }
        'cis'    { return "Test the impact first, then fix: vulnagent-local-harden.ps1 -Apply cis -Only $($C.id)" }
    }
    "Fix by hand: $($C.how)"
}

function ConvertTo-HardeningFinding($R, [bool]$Passed) {
    $c = $R.check
    $desc = @("**Check:** $($c.id) ($($c.area))", "**Why:** $($c.why)", "**Microsoft baseline:** $($c.ms)")
    $desc += '**Expected:** ' + (($R.items | ForEach-Object { '{0} = {1}' -f $_.setting, $_.want }) -join '; ')
    if ($c.impact) { $desc += "**Possible impact:** $($c.impact)" }
    if ($c.reboot) { $desc += '**Restart needed** after the change.' }
    if ($c.cisName) {
        $desc += "**$($c.cisName):** " + $(if ($c.cis) { $c.cis -join ', ' } elseif ($c.def) { 'see the Defender Antivirus benchmark' } else { 'no matching recommendation' })
        if ($c.cis -and $CisNotes[$c.id]) { $desc += "**CIS value:** $($CisNotes[$c.id])" }
    }
    if ($c.def) { $desc += "**$($CisBenchmarks.defender):** " + ($c.def -join ', ') }
    if ($c.stig) { $desc += "**$($c.stigName):** " + ($c.stig -join ', ') }
    if ($Passed) {
        $title = "$($c.title) (compliant)"; $sev = 'Info'; $uid = "harden-ok|$($c.id)"
        $mit = 'Nothing to do.'
    } else {
        $title = $c.title; $sev = $c.sev; $uid = "harden|$($c.id)"
        # the current value goes here, not in the description, so a changed value does not reopen the finding
        $now = ($R.items | Where-Object { -not $_.ok } | ForEach-Object { '{0} = {1}' -f $_.setting, $_.now }) -join '; '
        $mit = "Now: $now. " + (Get-FixText $c)
        if ($c.fix -ne 'manual') { $mit += ' In a domain, set it in a Group Policy instead, or it may be overwritten.' }
    }
    New-Finding @{
        title = $title; severity = $sev; description = ($desc -join "`n"); mitigation = $mit
        references = $(if ($c.app) { $(if ($c.stig) { 'https://public.cyber.mil/stigs/' } else { '' }) } else {
                     'https://www.microsoft.com/en-us/download/details.aspx?id=55319' +
                     $(if ($c.cis -or $c.def) { "`nhttps://www.cisecurity.org/cis-benchmarks" } else { '' }) +
                     $(if ($c.stig) { "`nhttps://public.cyber.mil/stigs/" } else { '' }) })
        component_name = 'Windows hardening'; vuln_id_from_tool = $c.id; unique_id_from_tool = $uid
        tags = @(@('vulnagent', 'windows', 'hardening', ($c.area.ToLower() -replace ' ', '-'), "fix-$($c.fix)") +
                 @(@($c.cis) + @($c.def) | Where-Object { $_ } | ForEach-Object { 'cis-' + ($_ -replace '^.*\((\w+)\)$', '$1').ToLower() } | Select-Object -Unique) +
                 @($c.stig | Where-Object { $_ } | ForEach-Object { 'stig-' + ($_ -replace '^.*\((CAT \w+)\)$', '$1').ToLower().Replace(' ', '-') } | Select-Object -Unique))
    }
}

# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

function Format-Html($Text) { [Net.WebUtility]::HtmlEncode("$Text") }

function Get-StatusBadge($R) {
    switch ($R.status) {
        'fail'      { return '<span class="sev s-' + $R.severity.ToLower() + '">' + $R.severity + '</span>' }
        'pass'      { return '<span class="sev s-pass">Pass</span>' }
        'exception' { return '<span class="sev s-exc">Exception</span>' }
    }
    '<span class="sev s-err">Error</span>'
}

$FixLabels = @{ safe = 'safe: -Apply safe'; review = 'review: -Apply all'; cis = 'CIS: -Apply cis'; manual = 'by hand' }

$HtmlStyle = @'
body{font:14px/1.45 "Segoe UI",system-ui,sans-serif;background:#fff;color:#1d1d1f;margin:0 auto;padding:24px 16px;max-width:1300px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 8px}h2 small{font-weight:400;color:#666}
.mut,th,.kind,.none{color:#666}.none{font-style:italic}
.cards{display:flex;flex-wrap:wrap;margin:18px -5px 6px}
.card{background:#f4f4f6;border:2px solid transparent;border-radius:8px;padding:8px 16px;margin:5px;min-width:96px;text-align:left;font:inherit;color:inherit}
button.card{cursor:pointer}button.card.on{border-color:#1d1d1f}
.n{display:block;font-size:24px;font-weight:700;line-height:1.2}
.c-critical,.bad{color:#b00020}.c-high,.soon{color:#e65100}.c-medium{color:#b7791f}.c-low{color:#0277bd}.c-info,.c-exception{color:#777}.good,.c-pass{color:#2e7d32}.c-error{color:#6a1b9a}.bad{font-weight:700}
.sev{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700;min-width:54px;text-align:center}
.s-critical{background:#b00020}.s-high{background:#e65100}.s-medium{background:#f9a825;color:#1d1d1f}.s-low{background:#0277bd}.s-info{background:#888}
.s-pass{background:#2e7d32}.s-exc{background:#777}.s-err{background:#6a1b9a}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid #e3e3e3;padding:6px 8px;text-align:left;vertical-align:top}th{font-weight:600;white-space:nowrap}
.wrap{overflow-x:auto}summary{cursor:pointer}
.desc{margin:6px 0 2px;padding:8px 10px;background:#f4f4f6;border-radius:6px;word-wrap:break-word}
.desc table{margin:6px 0;font-size:12px}.desc th,.desc td{padding:3px 6px;border-color:#ddd}
.kind{white-space:nowrap}.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}
.bar{display:flex;flex-wrap:wrap;align-items:center;margin:8px 0}.bar>*{margin:0 10px 6px 0}
#q{width:320px;max-width:100%;padding:6px 10px;border:1px solid #bbb;border-radius:6px;font:inherit;background:inherit;color:inherit}
#all{padding:6px 10px;border:1px solid #bbb;border-radius:6px;background:inherit;color:inherit;font:inherit;cursor:pointer}
.warn{border-left:4px solid #e65100;background:#fff4e5;padding:8px 12px;margin:14px 0;border-radius:4px}
.since{border-left:4px solid #0277bd;background:#eef6fb;padding:8px 12px;margin:14px 0;border-radius:4px}.since details{margin-top:4px}
.okbox{border-left:4px solid #2e7d32;background:#edf7ee;padding:8px 12px;margin:14px 0;border-radius:4px}
.chg{color:#2e7d32;font-weight:600}
a{color:inherit}ul{margin:4px 0;padding-left:20px}
@media (prefers-color-scheme:dark){body{background:#141416;color:#ececec}.mut,th,.kind,.none,h2 small{color:#9a9a9a}
.card,.desc{background:#1e1e22}th,td{border-color:#2c2c30}.desc th,.desc td{border-color:#34343a}button.card.on{border-color:#ececec}
.warn{background:#2a2015}.okbox{background:#15241a}.since{background:#15202a}
.c-critical,.bad{color:#ff6b6b}.c-high,.soon{color:#ff9e40}.c-medium{color:#f9c74f}.c-low{color:#4fc3f7}.good,.c-pass,.chg{color:#81c784}.c-error{color:#ce93d8}}
@media print{.bar,#all{display:none}body{max-width:none}}
'@

$HtmlScript = @'
(function () {
  var q = document.getElementById('q'), sp = document.getElementById('sp'), on = {}, rows = document.getElementById('checks').tBodies[0].rows;
  function each(list, fn) { for (var i = 0; i < list.length; i++) fn(list[i]); }
  function apply() {
    var t = q.value.toLowerCase(), any = false, n = 0, k;
    for (k in on) { if (on[k]) any = true; }
    each(rows, function (r) {
      var key = r.getAttribute('data-key');
      var ok = (any ? on[key] : (sp.checked || key !== 'pass')) && (!t || r.textContent.toLowerCase().indexOf(t) >= 0);
      r.style.display = ok ? '' : 'none';
      if (ok) n++;
    });
    document.getElementById('shown').innerHTML = n;
  }
  each(document.querySelectorAll('button.card'), function (c) {
    c.onclick = function () {
      var s = c.getAttribute('data-key');
      on[s] = !on[s];
      c.className = on[s] ? 'card on' : 'card';
      apply();
    };
  });
  q.oninput = apply; q.onkeyup = apply; sp.onclick = apply;
  document.getElementById('all').onclick = function () {
    var d = document.querySelectorAll('#checks details'), o = !(d.length && d[0].open);
    each(d, function (x) { x.open = o; });
  };
  window.onbeforeprint = function () { each(document.querySelectorAll('details'), function (x) { x.open = true; }); };
  apply();
})();
'@

function ConvertTo-HardeningHtml($Report, $Results) {
    $hi = $Report.system
    $sum = $Report.summary
    $all = @($Results | Sort-Object { $StatusOrder[$_.status] }, { $SeverityOrder[$_.severity] }, { $_.id })
    $out = New-Object Collections.Generic.List[string]
    $out.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge">')
    $out.Add('<meta name="viewport" content="width=device-width,initial-scale=1"><title>Hardening - ' + (Format-Html $hi.host) + '</title>')
    $out.Add('<style>' + $HtmlStyle + '</style></head><body>')
    $out.Add('<h1>Hardening report &ndash; ' + (Format-Html $hi.host) + '</h1>')
    $meta = @(("$($hi.os) $($hi.version).$($hi.ubr)" + $(if ($hi.release) { " ($($hi.release))" } else { '' })), $hi.role,
              "generated $(([string]$Report.generated).Replace('T', ' '))", $Report.agent)
    if ($DryRun -and ($Report.changes -or $Report.undone)) { $meta += 'dry run: nothing changed' }
    $out.Add('<div class="mut">' + (($meta | ForEach-Object { Format-Html $_ }) -join ' &middot; ') + '</div>')
    $out.Add('<div class="mut">Compared with: ' + (Format-Html $Report.baseline) + '</div>')
    if ($Report.cis_benchmark) { $out.Add('<div class="mut">CIS numbers from: ' + (Format-Html $Report.cis_benchmark) + '</div>') }
    if ($Report.stig_benchmark) { $out.Add('<div class="mut">STIG IDs from: ' + (Format-Html $Report.stig_benchmark) + '</div>') }
    foreach ($a in @($Report.also_checked)) { $out.Add('<div class="mut">Also checked: ' + (Format-Html $a) + '</div>') }

    if ($Report.errors) {
        $out.Add('<div class="warn"><b>Some checks or changes failed</b>, so this report may be incomplete:<ul>' +
                 (($Report.errors | ForEach-Object { '<li>' + (Format-Html $_) + '</li>' }) -join '') + '</ul></div>')
    }
    $out.Add((ConvertTo-ChangesHtml $Report.since_last))
    if (@($Report.changes).Count) {
        $verb = if ($DryRun) { '<b>Would change</b> (dry run):' } else { '<b>Changed in this run:</b>' }
        $undoHint = if ($DryRun) { '' } else { ' Undo with <span class="mono">vulnagent-local-harden.ps1 -Undo last</span>.' }
        $out.Add('<div class="okbox">' + $verb + ' ' + @($Report.changes).Count + ' checks.' + $undoHint + '<ul>' +
                 ((@($Report.changes) | ForEach-Object { '<li>' + (Format-Html "$($_.id) $($_.title)") + '</li>' }) -join '') + '</ul>' +
                 $(if ($Report.restart_needed) { '<b>Restart the machine</b> to finish some of the changes.' } else { '' }) + '</div>')
    }
    if (@($Report.undone).Count) {
        $out.Add('<div class="okbox"><b>Undone in this run:</b> ' + ((@($Report.undone) | ForEach-Object { Format-Html $_ }) -join ', ') + '</div>')
    }

    # cards: the severity and status cards filter the table
    $out.Add('<div class="cards">')
    $cls = if ($sum.score -ge 90) { 'good' } elseif ($sum.score -ge 70) { 'soon' } else { 'bad' }
    $out.Add('<div class="card"><span class="n ' + $cls + '">' + $sum.score + '%</span>compliant (' + $sum.passed + ' of ' + $sum.checks + ' checks)</div>')
    if ($sum.cis_checks) {
        $out.Add('<div class="card"><span class="n">' + $sum.cis_passed + ' / ' + $sum.cis_checks + '</span>CIS Level 1 checks outside the Microsoft baseline pass</div>')
    }
    foreach ($s in $SeverityOrder.Keys) {
        $n = @($all | Where-Object { $_.status -eq 'fail' -and $_.severity -eq $s }).Count
        if ($s -eq 'Info' -and -not $n) { continue }
        $out.Add('<button class="card" data-key="' + $s + '" title="Show only failed ' + $s + ' checks"><span class="n c-' + $s.ToLower() + '">' + $n + '</span>' + $s + '</button>')
    }
    foreach ($s in @(@('pass', 'passed'), @('exception', 'exceptions'), @('error', 'errors'))) {
        $n = @($all | Where-Object { $_.status -eq $s[0] }).Count
        if ($s[0] -ne 'pass' -and -not $n) { continue }
        $out.Add('<button class="card" data-key="' + $s[0] + '"><span class="n c-' + $s[0] + '">' + $n + '</span>' + $s[1] + '</button>')
    }
    $out.Add('</div>')

    $out.Add('<h2>Checks <small>(<span id="shown">' + $all.Count + '</span> of ' + $all.Count + ' shown)</small></h2>')
    $out.Add('<div class="bar"><input id="q" type="search" placeholder="Search checks, settings, IDs..."><label><input id="sp" type="checkbox"> show passed checks</label><button id="all" type="button">Expand / collapse all</button></div>')
    $rows = foreach ($r in $all) {
        $c = $r.check
        $key = if ($r.status -eq 'fail') { $r.severity } else { $r.status }
        $det = '<b>Why:</b> ' + (Format-Html $c.why)
        if ($r.items.Count) {
            $det += '<table><thead><tr><th>Setting</th><th>Expected</th><th>Now</th></tr></thead><tbody>' +
                    (($r.items | ForEach-Object { '<tr><td class="mono">' + (Format-Html $_.setting) + '</td><td>' + (Format-Html $_.want) +
                        '</td><td class="' + $(if ($_.ok) { 'good' } else { 'bad' }) + '">' + (Format-Html $_.now) + '</td></tr>' }) -join '') + '</tbody></table>'
        }
        if ($r.error) { $det += '<b>Error:</b> ' + (Format-Html $r.error) + '<br>' }
        if ($c.impact) { $det += '<b>Possible impact:</b> ' + (Format-Html $c.impact) + '<br>' }
        if ($c.how) { $det += '<b>How to fix:</b> ' + (Format-Html $c.how) + '<br>' }
        if ($c.reboot) { $det += '<b>Restart needed</b> after a change.<br>' }
        $det += '<b>Microsoft baseline:</b> ' + (Format-Html $c.ms)
        if ($c.cisName) { $det += '<br><b>CIS:</b> ' + $(if ($c.cis) { Format-Html ($c.cis -join ', ') } elseif ($c.def) { 'see CIS Defender Antivirus below' } else { 'no matching recommendation' }) }
        if ($c.cis -and $CisNotes[$c.id]) { $det += '<br><b>CIS value:</b> ' + (Format-Html $CisNotes[$c.id]) }
        if ($c.def) { $det += '<br><b>CIS Defender Antivirus:</b> ' + (Format-Html ($c.def -join ', ')) }
        if ($c.stig) { $det += '<br><b>' + $(if ($c.app) { Format-Html $c.stigName } else { 'DISA STIG' }) + ':</b> ' + (Format-Html ($c.stig -join ', ')) }
        $title = (Format-Html $r.title) + $(if ($r.changed) { ' <span class="chg">(changed now)</span>' } else { '' })
        $fix = if ($r.status -eq 'pass') { '-' } else { $FixLabels[$r.fix] }
        '<tr data-key="' + $key + '"><td>' + (Get-StatusBadge $r) + '</td><td><details><summary><span class="mono">' + $r.id + '</span> ' + $title +
            '</summary><div class="desc">' + $det + '</div></details></td><td class="kind">' + (Format-Html $r.area) + '</td><td class="kind">' + $fix + '</td></tr>'
    }
    $out.Add('<div class="wrap"><table id="checks"><thead><tr><th>Status</th><th>Check (click for details)</th><th>Area</th><th>Fix</th></tr></thead><tbody>')
    $out.Add(($rows -join "`n"))
    $out.Add('</tbody></table></div>')
    $out.Add('<p class="mut" style="margin-top:32px">Fix: "safe" can be applied with <span class="mono">-Apply safe</span>; "review" can break old clients or applications, test it, then use <span class="mono">-Apply all</span>; "CIS" are CIS Level 1 settings outside the Microsoft baseline, test them, then use <span class="mono">-Apply cis</span>; "by hand" needs hardware, Active Directory or a decision. Full data: ' + (Format-Html (Join-Path $DataDir 'reports\hardening.json')) + '; all reports: ' + (Format-Html (Join-Path $DataDir 'reports\index.html')) + '</p>')
    $out.Add('<script>' + $HtmlScript + '</script></body></html>')
    $out -join "`n"
}

# --------------------------------------------------------------------------
# local reports
# --------------------------------------------------------------------------

# ConvertFrom-Json in PowerShell 7 turns dates into [datetime], 5.1 keeps the string
function Format-When($Value) {
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    "$Value".Replace('T', ' ')
}

# what is new and what was fixed since the previous run, by unique_id_from_tool;
# when part of this run failed, a finding that is gone may only not have been checked
function Compare-Findings([string]$PreviousFile, $Findings, [string]$Skip, [bool]$Incomplete) {
    if (-not (Test-Path $PreviousFile)) { return $null }
    try { $prev = Get-Content -Path $PreviousFile -Raw | ConvertFrom-Json } catch { return $null }
    $old = @($prev.findings | Where-Object { $_ -and (-not $Skip -or "$($_.unique_id_from_tool)" -notlike $Skip) })
    $cur = @($Findings | Where-Object { -not $Skip -or "$($_.unique_id_from_tool)" -notlike $Skip })
    $was = @{}; foreach ($f in $old) { $was["$($f.unique_id_from_tool)"] = $true }
    $is = @{}; foreach ($f in $cur) { $is["$($f.unique_id_from_tool)"] = $true }
    [ordered]@{
        previous = (Get-Item $PreviousFile).LastWriteTime.ToString('s'); incomplete = $Incomplete
        new      = @($cur | Where-Object { -not $was.ContainsKey("$($_.unique_id_from_tool)") } | ForEach-Object { [ordered]@{ severity = $_.severity; title = $_.title } })
        fixed    = @($old | Where-Object { -not $is.ContainsKey("$($_.unique_id_from_tool)") } | ForEach-Object { [ordered]@{ severity = $_.severity; title = $_.title } })
    }
}

function ConvertTo-ChangesHtml($Since) {
    if (-not $Since) { return '<div class="since">First report on this machine: the next one shows what changed since this run.</div>' }
    $gone = if ($Since.incomplete) { 'Gone, but part of this run failed, so some may not be fixed' } else { 'Fixed' }
    $parts = foreach ($p in @(@('New', $Since.new), @($gone, $Since.fixed))) {
        if (@($p[1]).Count) {
            '<details><summary>' + $p[0] + ' (' + @($p[1]).Count + ')</summary><ul>' +
                ((@($p[1]) | ForEach-Object { '<li><span class="sev s-' + "$($_.severity)".ToLower() + '">' + (Format-Html $_.severity) + '</span> ' + (Format-Html $_.title) + '</li>' }) -join '') +
                '</ul></details>'
        }
    }
    '<div class="since"><b>Since the last run</b> (' + (Format-Html (Format-When $Since.previous)) + '): ' +
        @($Since.new).Count + ' new, ' + @($Since.fixed).Count + $(if ($Since.incomplete) { ' gone (part of this run failed).' } else { ' fixed.' }) +
        ($parts -join '') + '</div>'
}

# <kind>.html, <kind>.json and <kind>-findings.json are the latest run; history keeps a dated copy of each run
function Save-Reports([string]$Kind, $Report, $Doc, [string]$Page, $Cfg, $Counts) {
    $dir = Join-Path $DataDir 'reports'
    $hist = Join-Path $dir 'history'
    New-Item -ItemType Directory -Force -Path $hist | Out-Null
    Write-JsonFile (Join-Path $dir "$Kind.json") $Report
    Write-JsonFile (Join-Path $dir "$Kind-findings.json") $Doc
    $stamp = '{0}-{1}' -f ([datetime]$Report.generated).ToString('yyyyMMdd-HHmmss'), $Kind
    if ($Page) {
        Write-TextFile (Join-Path $dir "$Kind.html") $Page
        Write-TextFile (Join-Path $hist "$stamp.html") $Page
    }
    $since = $Report.since_last
    Write-JsonFile (Join-Path $hist "$stamp.json") ([ordered]@{
        kind = $Kind; generated = $Report.generated; host = $Report.host; agent = $Report.agent
        description = $Doc.description; severities = $Counts; score = $Report.summary.score
        new = $(if ($since) { @($since.new).Count } else { $null }); fixed = $(if ($since) { @($since.fixed).Count } else { $null })
        errors = @($Report.errors).Count; html = $(if ($Page) { "history/$stamp.html" } else { $null })
    })
    $days = [int]$Cfg.keep_reports_days
    if ($days -gt 0) {
        $limit = (Get-Date).AddDays(-$days)
        Get-ChildItem -Path $hist -File | Where-Object { $_.LastWriteTime -lt $limit } | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    # the scan and the hardening check both rewrite the index; if they collide, the next run fixes it
    try { Update-ReportIndex } catch { Write-Log "ERROR report index: $($_.Exception.Message)" }
}

function Update-ReportIndex {
    $dir = Join-Path $DataDir 'reports'
    $runs = @(foreach ($f in @(Get-ChildItem -Path (Join-Path $dir 'history') -Filter '*.json' -File | Sort-Object Name -Descending)) {
        try { Get-Content -Path $f.FullName -Raw | ConvertFrom-Json } catch { }
    })
    $name = if ($runs.Count) { $runs[0].host } else { $env:COMPUTERNAME }
    $out = New-Object Collections.Generic.List[string]
    $out.Add('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="X-UA-Compatible" content="IE=edge">')
    $out.Add('<meta name="viewport" content="width=device-width,initial-scale=1"><title>Reports - ' + (Format-Html $name) + '</title>')
    $out.Add('<style>' + $HtmlStyle + 'a.card{text-decoration:none}</style></head><body>')
    $out.Add('<h1>Security reports &ndash; ' + (Format-Html $name) + '</h1>')
    $out.Add('<div class="mut">vulnagent-local: these reports stay on this machine, in ' + (Format-Html $dir) + '. Updated ' + (Get-Date).ToString('yyyy-MM-dd HH:mm') + '.</div>')
    $out.Add('<div class="cards">')
    foreach ($k in @(@('scan', 'Latest scan'), @('hardening', 'Latest hardening check'))) {
        $last = @($runs | Where-Object { $_.kind -eq $k[0] }) | Select-Object -First 1
        if (-not $last -or -not (Test-Path (Join-Path $dir "$($k[0]).html"))) { continue }
        $big = if ($k[0] -eq 'hardening') { "$($last.score)%" } else { [string](@($last.severities.PSObject.Properties | ForEach-Object { [int]$_.Value }) | Measure-Object -Sum).Sum }
        $what = if ($k[0] -eq 'hardening') { 'compliant' } else { 'findings' }
        $out.Add('<a class="card" href="' + $k[0] + '.html"><span class="n">' + $big + '</span>' + $what + ' &middot; ' + $k[1] + ', ' +
                 (Format-Html (Format-When $last.generated)) + '</a>')
    }
    $out.Add('</div>')
    $out.Add('<h2>All reports <small>(' + $runs.Count + ')</small></h2>')
    if ($runs.Count) {
        $out.Add('<div class="wrap"><table><thead><tr><th>When</th><th>Report</th><th>Result</th>' +
                 (($SeverityOrder.Keys | ForEach-Object { '<th>' + $_ + '</th>' }) -join '') + '<th>New</th><th>Fixed</th></tr></thead><tbody>')
        foreach ($r in $runs) {
            $label = if ($r.kind -eq 'hardening') { 'Hardening' } else { 'Scan' }
            if ($r.html -and (Test-Path (Join-Path $dir $r.html))) { $label = '<a href="' + (Format-Html $r.html) + '">' + $label + '</a>' }
            $total = @($r.severities.PSObject.Properties | ForEach-Object { [int]$_.Value }) | Measure-Object -Sum
            $result = if ($r.kind -eq 'hardening') { "$($r.score)% compliant, $($total.Sum) failed" } else { "$($total.Sum) findings" }
            if ($r.errors) { $result += ' (incomplete)' }
            $cells = foreach ($s in $SeverityOrder.Keys) {
                $n = [int]$r.severities.$s
                '<td' + $(if ($n) { ' class="c-' + $s.ToLower() + '"' } else { '' }) + '>' + $n + '</td>'
            }
            $out.Add('<tr><td>' + (Format-Html (Format-When $r.generated)) + '</td><td>' + $label + '</td><td>' + (Format-Html $result) + '</td>' +
                     ($cells -join '') + '<td>' + $(if ($null -ne $r.new) { $r.new } else { '-' }) + '</td><td>' + $(if ($null -ne $r.fixed) { $r.fixed } else { '-' }) + '</td></tr>')
        }
        $out.Add('</tbody></table></div>')
    } else {
        $out.Add('<p class="none">No reports yet.</p>')
    }
    Write-TextFile (Join-Path $dir 'index.html') ($out -join "`n")
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

function Save-Backup([string]$Path, $Backup) {
    Write-JsonFile $Path $Backup
}

function Invoke-Undo([string]$Which, $All, $Errs) {
    $file = $Which
    if ($Which -eq 'last') {
        $file = Get-ChildItem -Path $BackupDir -Filter 'backup-*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1 |
            ForEach-Object { $_.FullName }
    }
    if (-not $file -or -not (Test-Path $file)) { throw "no backup to undo ($Which): backups are in $BackupDir" }
    $b = Get-Content -Path $file -Raw | ConvertFrom-Json
    $byId = @{}
    foreach ($c in $All) { $byId[$c.id] = $c }
    $items = @($b.changes)
    [array]::Reverse($items)
    $done = @()
    Write-Log "undo: $($items.Count) changes from $file"
    foreach ($x in $items) {
        $c = $byId[$x.id]
        if (-not $c) { $Errs.Add("undo $($x.id): unknown check"); continue }
        if ($DryRun) { Write-Log "  would undo $($x.id) $($c.title)"; continue }
        try {
            Invoke-Restore $c $x.state
            $done += $x.id
            Write-Log "  undone $($x.id) $($c.title)"
        } catch { $Errs.Add("undo $($x.id): $($_.Exception.Message)") }
    }
    if (-not $DryRun) { Move-Item $file ($file -replace 'backup-', 'undone-') -Force }
    $done
}

function Invoke-Main {
    try {
        Assert-Admin
        Initialize-DataDir
        if ($Apply -and $Undo) { throw 'use either -Apply or -Undo, not both' }
        $cfg = Read-Config $ConfigPath
        $hi = Get-HostInfo
        $ctx = New-Context
        $all = @(Get-Catalog $hi)
        if ($cfg.cis_checks) { $all += @(Get-CisCatalog) }
        $all += @(Get-AppCatalog $hi $cfg)
        $bench = Get-CisBenchmark $hi
        $cisName = if ($bench) { $CisBenchmarks[$bench] } else { $null }
        $stigBench = Get-StigBenchmark $hi
        $stigName = if ($stigBench) { $CisBenchmarks[$stigBench] } else { $null }
        foreach ($c in $all) {
            if ($c.app) { $c.cis = @(); $c.def = @(); continue }
            $c.cisName = $cisName; $c.cis = @(Get-CisRefs $c.id $bench ([bool]$hi.dc))
            $c.def = @(Get-CisRefs $c.id 'defender' ([bool]$hi.dc))
            $c.stigName = $stigName; $c.stig = @(Get-CisRefs $c.id $stigBench ([bool]$hi.dc))
        }
        $catalog = @($all | Where-Object { Test-Scope $_ $hi $ctx })
        $accepted = @($cfg.hardening_exclude | Where-Object { $_ })
        $nIis = @($catalog | Where-Object { $_.area -eq 'IIS' }).Count
        $nSql = @($catalog | Where-Object { $_.area -eq 'SQL Server' }).Count
        $alsoChecked = @()
        if ($nIis) { $alsoChecked += "IIS $($hi.iis), $nIis checks (STIG IDs from DISA STIG Microsoft IIS 10.0 Server V3R7 and Site V2R16)" }
        if ($nSql) { $alsoChecked += "SQL Server instances $((@($hi.sql) | ForEach-Object { "$($_.name) $($_.version)" }) -join ', '), $nSql checks (STIG IDs from DISA STIG Microsoft SQL Server 2022 Instance V1R4)" }

        if ($List) {
            $catalog | ForEach-Object { [pscustomobject]@{ ID = $_.id; Severity = $_.sev; Fix = $_.fix; Area = $_.area; Check = $_.title
                                                           CIS = ((@($_.cis) + @($_.def | ForEach-Object { "AV $_" })) -join ', '); STIG = ($_.stig -join ', ') } } |
                Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
            Write-Host "$($catalog.Count) checks apply to this $($hi.role) (of $($all.Count))."
            Write-Host $(if ($cisName) { "CIS numbers: $cisName" } else { 'No CIS numbers for this Windows version.' })
            Write-Host "AV: $($CisBenchmarks.defender)"
            if ($stigName) { Write-Host "STIG IDs: $stigName" }
            foreach ($a in $alsoChecked) { Write-Host "Also checked: $a" }
            return 0
        }

        Write-Log "vulnagent-local-harden $VERSION on $($hi.host): $($hi.os) build $($hi.build), $($hi.role)"
        $nCis = @($catalog | Where-Object { $_.cisOnly }).Count
        Write-Log ("compared with {0}: {1} checks{2}" -f (Get-BaselineName $hi), ($catalog.Count - $nCis - $nIis - $nSql), $(if ($nCis) { ", plus $nCis CIS Level 1 checks" } else { '' }))
        foreach ($a in $alsoChecked) { Write-Log "also checked: $a" }
        Write-Log $(if ($cisName) { "CIS numbers from $cisName" } else { 'no CIS numbers for this Windows version' })
        if ($stigName) { Write-Log "STIG IDs from $stigName" }
        $errs = New-Object Collections.Generic.List[string]
        $undone = @()
        if ($Undo) {
            $undone = @(Invoke-Undo $Undo $all $errs)
            $ctx = New-Context
        }

        $results = @(Invoke-Audit $catalog $ctx $accepted)
        $changes = New-Object Collections.Generic.List[object]
        $restart = $false
        if ($Apply) {
            $levels = switch ($Apply) { 'all' { @('safe', 'review') } 'cis' { @('cis') } default { @('safe') } }
            $todo = @($results | Where-Object { $_.status -eq 'fail' -and $levels -contains $_.fix -and
                (-not $Only -or (Test-IdMatch $_.id $_.area $Only)) -and -not (Test-IdMatch $_.id $_.area $Exclude) })
            $left = @($results | Where-Object { $_.status -eq 'fail' -and $_.fix -eq 'review' -and $Apply -eq 'safe' -and
                (-not $Only -or (Test-IdMatch $_.id $_.area $Only)) })
            Write-Log ("{0}: {1} checks to fix" -f $(if ($DryRun) { '-Apply -DryRun, changing nothing' } else { "-Apply $Apply" }), $todo.Count)
            $backupFile = Join-Path $BackupDir ('backup-{0}.json' -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
            $backup = [ordered]@{ created = (Get-Date).ToString('s'); host = $hi.host; agent = "vulnagent-local-harden $VERSION"; changes = @() }
            foreach ($r in $todo) {
                if ($DryRun) {
                    Write-Log "  would fix $($r.id) $($r.title)"
                    $changes.Add([pscustomobject]@{ id = $r.id; title = $r.title })
                    continue
                }
                try {
                    # the backup is written before each change, so it is complete even if the run stops
                    $backup.changes += [pscustomobject]@{ id = $r.id; title = $r.title; state = $r.state }
                    Save-Backup $backupFile $backup
                    Invoke-Fix $r.check $r
                    $changes.Add([pscustomobject]@{ id = $r.id; title = $r.title })
                    if ($r.check.reboot) { $restart = $true }
                    Write-Log "  fixed $($r.id) $($r.title)"
                } catch {
                    $errs.Add("$($r.id): $($_.Exception.Message)")
                }
            }
            if ($left.Count) {
                Write-Log ("  {0} failed checks are marked 'review' and need -Apply all: {1}" -f $left.Count, (($left | ForEach-Object { $_.id }) -join ', '))
            }
            if ($changes.Count -and -not $DryRun) {
                Write-Log "  backup of the old values: $backupFile (undo: vulnagent-local-harden.ps1 -Undo last)"
                $ctx = New-Context
                $results = @(Invoke-Audit $catalog $ctx $accepted)
                $ids = @($changes | ForEach-Object { $_.id })
                foreach ($r in $results) {
                    if ($ids -contains $r.id) {
                        $r.changed = $true
                        if ($r.status -eq 'fail') {
                            $msg = if ($r.check.reboot) { 'takes effect after a restart' } else { 'a Group Policy may set it back' }
                            Write-Log "  $($r.id) still fails after the change ($msg)"
                        }
                    }
                }
                if ($restart) { Write-Log 'RESTART NEEDED to finish some of the changes (not restarting automatically)' }
            }
        }
        foreach ($r in $results | Where-Object { $_.status -eq 'error' }) { $errs.Add("$($r.id): $($r.error)") }
        foreach ($e in $errs) { Write-Log "ERROR $e" }

        # reports
        $applicable = @($results | Where-Object { $_.status -ne 'exception' -and $_.status -ne 'error' })
        $passed = @($applicable | Where-Object { $_.status -eq 'pass' }).Count
        $failed = @($results | Where-Object { $_.status -eq 'fail' })
        $score = if ($applicable.Count) { [int][Math]::Floor(100 * $passed / $applicable.Count) } else { 100 }
        $findings = New-Object Collections.Generic.List[object]
        foreach ($r in $failed) { $findings.Add((ConvertTo-HardeningFinding $r $false)) }
        if ($cfg.hardening_include_passed) {
            foreach ($r in $results | Where-Object { $_.status -eq 'pass' }) { $findings.Add((ConvertTo-HardeningFinding $r $true)) }
        }
        $since = Compare-Findings (Join-Path $DataDir 'reports\hardening-findings.json') $findings 'harden-ok|*' (@($results | Where-Object { $_.status -eq 'error' }).Count -gt 0)
        $doc = [ordered]@{
            name = 'vulnagent-local-harden'; type = $SCAN_TYPE; version = $VERSION
            description = '{0} - {1}: {2} of {3} checks pass ({4}%), {5} fail' -f $hi.host, (Get-BaselineName $hi), $passed, $applicable.Count, $score, $failed.Count
            findings = $findings.ToArray()
        }
        $report = [ordered]@{
            agent = "vulnagent-local-harden $VERSION"; generated = (Get-Date).ToString('s'); host = $hi.host; system = $hi
            baseline = (Get-BaselineName $hi); cis_benchmark = $cisName; cis_defender_benchmark = $CisBenchmarks.defender; stig_benchmark = $stigName; also_checked = $alsoChecked; errors = $errs.ToArray(); since_last = $since; restart_needed = $restart
            changes = $changes.ToArray(); undone = $undone
            summary = [ordered]@{ checks = $applicable.Count; passed = $passed; failed = $failed.Count; score = $score
                                  exceptions = @($results | Where-Object { $_.status -eq 'exception' }).Count
                                  errors = @($results | Where-Object { $_.status -eq 'error' }).Count
                                  cis_checks = @($applicable | Where-Object { $_.check.cisOnly }).Count
                                  cis_passed = @($applicable | Where-Object { $_.check.cisOnly -and $_.status -eq 'pass' }).Count
                                  iis_checks = $nIis; sql_checks = $nSql }
            results = @($results | Select-Object id, area, title, severity, fix, status, changed, error, @{ n = 'cis'; e = { ,@($_.check.cis) } }, @{ n = 'cis_note'; e = { if ($_.check.cis) { $CisNotes[$_.id] } } },
                                                     @{ n = 'cis_defender'; e = { ,@($_.check.def) } }, @{ n = 'stig'; e = { ,@($_.check.stig) } }, items)
        }
        if ($Output) { Write-JsonFile $Output $doc; Write-Log "wrote $Output" }
        $page = $null
        try { $page = ConvertTo-HardeningHtml $report $results } catch { Write-Log "ERROR HTML report: $($_.Exception.Message)" }
        $counts = [ordered]@{}
        foreach ($s in $SeverityOrder.Keys) { $counts[$s] = @($failed | Where-Object { $_.severity -eq $s }).Count }
        Save-Reports 'hardening' $report $doc $page $cfg $counts
        if ($Html -and $page) {
            $Html = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Html)
            Write-TextFile $Html $page
            Write-Log "HTML report: $Html"
        }
        $bySev = foreach ($s in $counts.Keys) { if ($counts[$s]) { "$s $($counts[$s])" } }
        Write-Log ("{0} of {1} checks pass ({2}%); failed: {3}" -f $passed, $applicable.Count, $score, $(if ($bySev) { $bySev -join ', ' } else { 'none' }))
        if ($since) { Write-Log ("since the last run: {0} newly failing, {1} {2}" -f @($since.new).Count, @($since.fixed).Count, $(if ($since.incomplete) { 'gone (some checks failed)' } else { 'fixed' })) }
        Write-Log "report: $(Join-Path $DataDir 'reports\hardening.html')"
        if ($errs.Count) { return 2 }
        return 0
    } catch {
        Write-Log "ERROR $($_.Exception.Message)"
        return 3
    }
}

if ($MyInvocation.InvocationName -ne '.') { exit [int]@(Invoke-Main)[-1] }
