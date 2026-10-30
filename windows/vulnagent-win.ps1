<#
.SYNOPSIS
    vulnagent for Windows: finds missing Windows security updates, end-of-life
    Windows versions and outdated runtimes and applications, and sends them to
    DefectDojo.

.DESCRIPTION
    install.ps1 sets this up as the nightly "vulnagent" scheduled task (runs as
    SYSTEM). Each run:

      * optionally installs updates first (install_updates in the config, off
        by default),
      * asks Windows Update, or the machine's WSUS server, which updates are
        missing,
      * checks the Windows version, SQL Server, .NET, Java, Python, Node.js and
        PowerShell 7 against endoflife.date,
      * lists applications that winget can upgrade (when winget is present),
      * uploads the result to DefectDojo: one product per machine, fixed
        findings are closed, new ones are added.

    Needs only Windows PowerShell 5.1 (built into Windows Server 2016 and
    later; install WMF 5.1 on 2012 R2).

    Exit codes: 0 done, 2 uploaded but part of the scan failed (old findings
    were not closed), 3 failed (nothing uploaded).

.EXAMPLE
    vulnagent-win.ps1
    Scan and upload, using C:\ProgramData\vulnagent\defectdojo.json.

.EXAMPLE
    vulnagent-win.ps1 -DryRun -Output C:\Temp\findings.json
    Scan only and write the findings that would be uploaded.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$Url,
    [string]$Token,
    [switch]$Insecure,
    [switch]$DryRun,
    [string]$Output,
    [switch]$NoPatch
)

$ErrorActionPreference = 'Stop'
$VERSION = '1.0.0'
$SCAN_TYPE = 'Generic Findings Import'
$EOL_API = 'https://endoflife.date/api/'
$DataDir = Join-Path $env:ProgramData 'vulnagent'
if (-not $ConfigPath) { $ConfigPath = Join-Path $DataDir 'defectdojo.json' }
$LogFile = Join-Path $DataDir 'vulnagent.log'

$DefaultConfig = [ordered]@{
    url                          = ''                 # http://dojo.example.local:8080
    api_token                    = ''                 # DefectDojo API v2 key (or env DD_API_TOKEN)
    product_type                 = 'Windows servers'
    product_name                 = '{host}'           # {host} = FQDN, {short} = computer name
    engagement_name              = 'vulnagent'
    test_title                   = 'vulnagent'
    close_old_findings           = $true
    minimum_severity             = 'Info'
    windows_update_source        = 'default'          # default (WSUS if configured) | windows_update | microsoft_update
    include_non_security_updates = $false
    include_runtimes             = $true
    include_winget               = $true
    eol_warning_days             = 90
    install_updates              = 'none'             # none | security | all
    winget_upgrade               = $false
    reboot_after_updates         = $false
    verify_tls                   = $true
    timeout                      = 600
}

# Windows Update classification IDs (the names can be localised)
$UpdateClasses = @{
    '0fa1201d-4330-4fa8-8ae9-b877473b6441' = 'Security Updates'
    'e6cf1350-c01b-414d-a61f-263d14d133b4' = 'Critical Updates'
    'e0789628-ce08-4437-be74-2495b842f43b' = 'Definition Updates'
    '28bc880e-0592-4cbf-8f95-c79b17911d5f' = 'Update Rollups'
    'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83' = 'Updates'
    'b54e7d24-7add-428f-8b75-90a396fa584f' = 'Feature Packs'
    '68c5b0a3-d1a6-4553-ae49-01d3a7827828' = 'Service Packs'
    '3689bdc8-b205-4af4-8d4a-a63924c5e9d5' = 'Upgrades'
    'b4832bd8-e735-4761-8daf-37f882276dab' = 'Tools'
    'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0' = 'Drivers'
}
$MsrcSeverity = @{ Critical = 'Critical'; Important = 'High'; Moderate = 'Medium'; Low = 'Low' }
$MicrosoftUpdateService = '7971f918-a847-4430-9279-4a52d1efe18d'

$WUErrors = @{
    '0x8024402C' = 'cannot reach the update server: check DNS, the proxy or the WSUS address'
    '0x80072EE2' = 'the connection to the update server timed out'
    '0x80072EFD' = 'cannot connect to the update server'
    '0x8024401C' = 'the update server timed out'
    '0x80244022' = 'the update server returned HTTP 503'
    '0x80244019' = 'the update server returned HTTP 404: check the WSUS address'
    '0x80240438' = 'Windows Update is blocked (policy or proxy)'
    '0x8024002E' = 'access to Windows Update is disabled by policy'
    '0x80070005' = 'access denied: run as administrator or SYSTEM'
    '0x80248014' = 'Microsoft Update is not registered on this machine: use windows_update_source "default" or "windows_update"'
}

# Installed programs (Uninstall registry) that are checked against endoflife.date.
# Version: group v from the name, or m + u for Java 8 style "8u401", else DisplayVersion.
$RuntimeRules = @(
    @{ product = 'python';          label = 'Python';               cycle = 'minor';  re = '^Python (?<v>\d+\.\d+\.\d+)( \((32|64)-bit\))?$' }
    @{ product = 'nodejs';          label = 'Node.js';              cycle = 'major';  re = '^Node\.js$' }
    @{ product = 'dotnet';          label = '.NET Runtime';         cycle = 'dotnet'; re = '^Microsoft \.NET (Core )?Runtime - (?<v>\d+\.\d+\.\d+)' }
    @{ product = 'dotnet';          label = 'ASP.NET Core Runtime'; cycle = 'dotnet'; re = '^Microsoft ASP\.NET Core (?<v>\d+\.\d+\.\d+) (- )?Shared Framework' }
    @{ product = 'dotnet';          label = '.NET Desktop Runtime'; cycle = 'dotnet'; re = '^Microsoft Windows Desktop Runtime - (?<v>\d+\.\d+\.\d+)' }
    @{ product = 'powershell';      label = 'PowerShell';           cycle = 'minor';  re = '^PowerShell 7-(x64|x86|arm64)$' }
    @{ product = 'oracle-jdk';      label = 'Oracle Java';          cycle = 'major';  re = '^Java(\(TM\))? (SE Development Kit )?(?<m>\d+) Update (?<u>\d+)' }
    @{ product = 'oracle-jdk';      label = 'Oracle Java';          cycle = 'major';  re = '^Java(\(TM\))? SE Development Kit (?<v>\d+(\.\d+)*)' }
    @{ product = 'eclipse-temurin'; label = 'Eclipse Temurin';      cycle = 'major';  re = '^Eclipse Temurin (JDK|JRE) with Hotspot (?<v>\d+[0-9u.+-]*)' }
)

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

function Write-JsonFile([string]$Path, $Object) {
    $json = ConvertTo-Json -InputObject $Object -Depth 8
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding $false))
}

function Get-Clip([string]$Text, [int]$Max) {
    if ($Text.Length -le $Max) { return $Text }
    $Text.Substring(0, $Max - 3) + '...'
}

# -1, 0 or 1. Compares the numbers in two version strings ("8u401" < "8u511b33").
function Compare-Version([string]$A, [string]$B) {
    $x = @([regex]::Matches($A, '\d+') | ForEach-Object { [long]$_.Value })
    $y = @([regex]::Matches($B, '\d+') | ForEach-Object { [long]$_.Value })
    $n = [Math]::Max($x.Count, $y.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $p = if ($i -lt $x.Count) { $x[$i] } else { 0 }
        $q = if ($i -lt $y.Count) { $y[$i] } else { 0 }
        if ($p -ne $q) { return [Math]::Sign($p - $q) }
    }
    0
}

function Get-CycleName([string]$Kind, [string]$Version) {
    $p = @([regex]::Matches($Version, '\d+') | ForEach-Object { $_.Value })
    switch ($Kind) {
        'major'  { return $p[0] }
        'minor'  { return '{0}.{1}' -f $p[0], $p[1] }
        'dotnet' { if ([int]$p[0] -ge 5) { return $p[0] } else { return '{0}.{1}' -f $p[0], $p[1] } }
    }
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
    [pscustomobject]@{
        host      = $fqdn.ToLower()
        short     = $name.ToLower()
        os        = "$($os.Caption)".Trim()
        version   = "$($os.Version)"
        ubr       = "$($cv.UBR)"
        release   = "$release"
        edition   = "$($cv.EditionID)"
        server    = ($os.ProductType -ne 1)
        last_boot = $os.LastBootUpTime.ToString('s')
    }
}

function Get-InstalledSoftware {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $seen = @{}
    foreach ($e in (Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue)) {
        if (-not $e.DisplayName) { continue }
        $name = "$($e.DisplayName)".Trim()
        $ver = "$($e.DisplayVersion)".Trim()
        if ($seen.ContainsKey("$name|$ver")) { continue }
        $seen["$name|$ver"] = $true
        [pscustomobject]@{
            name = $name; version = $ver
            publisher = "$($e.Publisher)".Trim(); location = "$($e.InstallLocation)".Trim()
        }
    }
}

function Test-PendingReboot {
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
                   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        if (Test-Path $k) { return $true }
    }
    try { return [bool](New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch { return $false }
}

# --------------------------------------------------------------------------
# Windows Update
# --------------------------------------------------------------------------

function Get-WUSession {
    if (-not $script:WUSession) {
        $script:WUSession = New-Object -ComObject Microsoft.Update.Session
        $script:WUSession.ClientApplicationID = 'vulnagent'
    }
    $script:WUSession
}

function Get-WUErrorText($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }   # COM errors arrive wrapped
    $hr = '0x{0:X8}' -f $ex.HResult
    $hint = $WUErrors[$hr]
    if ($hint) { return "$hr, $hint" }
    "$hr, $($ex.Message)"
}

function Get-MissingUpdates($Cfg) {
    $searcher = (Get-WUSession).CreateUpdateSearcher()
    switch ("$($Cfg.windows_update_source)".ToLower()) {
        'windows_update'   { $searcher.ServerSelection = 2 }
        'microsoft_update' { $searcher.ServerSelection = 3; $searcher.ServiceID = $MicrosoftUpdateService }
    }
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    if ($result.ResultCode -ne 2 -and $result.ResultCode -ne 3) {
        throw "Windows Update search failed (result code $($result.ResultCode))"
    }
    foreach ($u in $result.Updates) {
        $class = ''
        $products = @()
        foreach ($c in $u.Categories) {
            if ($c.Type -eq 'UpdateClassification') {
                $class = if ($UpdateClasses[$c.CategoryID]) { $UpdateClasses[$c.CategoryID] } else { $c.Name }
            } elseif ($c.Type -eq 'Product') {
                $products += $c.Name
            }
        }
        $kbs = @(foreach ($k in $u.KBArticleIDs) { 'KB' + $k })
        $cves = @(foreach ($c in $u.CveIDs) { "$c" })
        $published = try { ([datetime]$u.LastDeploymentChangeTime).ToString('yyyy-MM-dd') } catch { '' }
        [pscustomobject]@{
            title          = "$($u.Title)"
            kb             = $kbs
            classification = $class
            msrc_severity  = "$($u.MsrcSeverity)"
            security       = ($class -eq 'Security Updates' -or "$($u.MsrcSeverity)" -ne '')
            cves           = $cves
            products       = $products
            published      = $published
            support_url    = "$($u.SupportUrl)"
            update_id      = "$($u.Identity.UpdateID)"
            com            = $u
        }
    }
}

function Install-WindowsUpdates($Cfg) {
    $mode = "$($Cfg.install_updates)".ToLower()
    $todo = @(Get-MissingUpdates $Cfg | Where-Object {
        ($mode -eq 'all' -or $_.security) -and $_.classification -ne 'Upgrades'
    })
    $done = [pscustomobject]@{ installed = @(); failed = @(); skipped = @(); reboot_required = $false }
    if (-not $todo) { Write-Log 'patch: no updates to install'; return $done }
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $todo) {
        if (-not $u.com.EulaAccepted) {
            $done.skipped += "$($u.title) (has a licence agreement: install it by hand)"
        } elseif ($u.com.InstallationBehavior.CanRequestUserInput) {
            $done.skipped += "$($u.title) (needs user input)"
        } else {
            [void]$coll.Add($u.com)
        }
    }
    foreach ($s in $done.skipped) { Write-Log "patch: skipped $s" }
    if ($coll.Count -eq 0) { return $done }
    Write-Log "patch: downloading and installing $($coll.Count) update(s)"
    $session = Get-WUSession
    $dl = $session.CreateUpdateDownloader()
    $dl.Updates = $coll
    [void]$dl.Download()
    $inst = $session.CreateUpdateInstaller()
    $inst.Updates = $coll
    $res = $inst.Install()
    for ($i = 0; $i -lt $coll.Count; $i++) {
        $rc = $res.GetUpdateResult($i).ResultCode
        $t = $coll.Item($i).Title
        if ($rc -eq 2 -or $rc -eq 3) { $done.installed += $t } else { $done.failed += "$t (result code $rc)" }
    }
    $done.reboot_required = [bool]$res.RebootRequired
    Write-Log ("patch: {0} installed, {1} failed{2}" -f $done.installed.Count, $done.failed.Count,
               $(if ($done.reboot_required) { ', restart required' } else { '' }))
    $done
}

# --------------------------------------------------------------------------
# end-of-life checks
# --------------------------------------------------------------------------

$script:EolCache = @{}

function Get-EolData([string]$Product) {
    if ($script:EolCache.ContainsKey($Product)) { return $script:EolCache[$Product] }
    $dir = Join-Path $DataDir 'cache'
    $file = Join-Path $dir "eol-$Product.json"
    try {
        $r = Invoke-WebRequest -Uri ($EOL_API + $Product + '.json') -UseBasicParsing -TimeoutSec 30 `
                               -UserAgent "vulnagent-win/$VERSION"
        $raw = $r.Content
        if ($raw -is [byte[]]) { $raw = [Text.Encoding]::UTF8.GetString($raw) }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        [IO.File]::WriteAllText($file, $raw)
    } catch {
        if ((Test-Path $file) -and (Get-Item $file).LastWriteTime -gt (Get-Date).AddDays(-30)) {
            Write-Log "endoflife.date unreachable ($($_.Exception.Message)): using cached $Product data"
            $raw = [IO.File]::ReadAllText($file)
        } else {
            throw "cannot download end-of-life data for ${Product}: $($_.Exception.Message)"
        }
    }
    $parsed = ConvertFrom-Json $raw
    $data = @(foreach ($x in $parsed) { $x })   # PowerShell 5.1 returns a JSON array as one object
    $script:EolCache[$Product] = $data
    $data
}

function Get-EolState($Cycle, [datetime]$Today) {
    $e = $Cycle.eol
    if ($e -is [bool]) { return @{ eol = $e; date = ''; days = $null } }
    if (-not $e) { return @{ eol = $false; date = ''; days = $null } }
    $d = if ($e -is [datetime]) { $e } else {
        [datetime]::ParseExact("$e", 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
    @{ eol = ($d.Date -lt $Today.Date); date = $d.ToString('yyyy-MM-dd'); days = [int]($d.Date - $Today.Date).TotalDays }
}

function Get-OsStatus($HostInfo, [datetime]$Today) {
    $product = if ($HostInfo.server) { 'windows-server' } else { 'windows' }
    $cands = @(Get-EolData $product | Where-Object { "$($_.latest)" -eq $HostInfo.version })
    if (-not $cands) { return $null }
    if ($HostInfo.server) {
        $pick = @($cands | Where-Object { $_.lts -eq $true })[0]
    } else {
        $ed = $HostInfo.edition
        $suffix = if ($ed -match '^(IoT)?Enterprise(S|SN)$') { if ($ed -like 'IoT*') { '-iot-lts' } else { '-e-lts' } }
                  elseif ($ed -match 'Enterprise|Education') { '-e' } else { '-w' }
        $pick = @($cands | Where-Object { "$($_.cycle)".EndsWith($suffix) })[0]
        if (-not $pick) { $pick = @($cands | Where-Object { "$($_.cycle)" -notmatch '-(e|w|lts|iot)$' })[0] }
    }
    if (-not $pick) { $pick = $cands[0] }
    $label = if ($pick.releaseLabel) { "$($pick.releaseLabel)" } else { "$($pick.cycle)" }
    if ($HostInfo.server) {
        if ($label -notlike 'Windows Server*') { $label = 'Windows Server ' + $label }
    } elseif ($label -notlike 'Windows*') { $label = 'Windows ' + $label }
    $st = Get-EolState $pick $Today
    [pscustomobject]@{
        product = $product; cycle = "$($pick.cycle)"; label = $label
        eol = $st.eol; eol_date = $st.date; days_left = $st.days
    }
}

function Get-Runtimes($Software) {
    $found = [ordered]@{}
    foreach ($s in $Software) {
        foreach ($r in $RuntimeRules) {
            if ($s.name -notmatch $r.re) { continue }
            if ($Matches['u']) { $v = '{0}u{1}' -f $Matches['m'], $Matches['u'] }
            elseif ($Matches['v']) { $v = $Matches['v'] }
            else { $v = $s.version }
            $v = ($v -replace '\+.*$', '').Trim()
            if ($v -notmatch '^\d') { break }
            $cycle = Get-CycleName $r.cycle $v
            $key = '{0}|{1}|{2}' -f $r.product, $r.label, $cycle
            # side-by-side installs: the newest patch of a release line counts
            if (-not $found.Contains($key) -or (Compare-Version $v $found[$key].version) -gt 0) {
                $found[$key] = [pscustomobject]@{
                    product = $r.product; name = $r.label; version = $v; cycle = $cycle
                    label = '{0} {1}' -f $r.label, $cycle
                    path = $(if ($s.location) { $s.location } else { $s.name })
                }
            }
            break
        }
    }
    @($found.Values)
}

function Get-SqlInstances {
    $base = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
    $names = Get-ItemProperty "$base\Instance Names\SQL" -ErrorAction SilentlyContinue
    if (-not $names) { return }
    foreach ($p in $names.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $setup = Get-ItemProperty "$base\$($p.Value)\Setup" -ErrorAction SilentlyContinue
        if (-not $setup) { continue }
        $ver = if ($setup.PatchLevel) { $setup.PatchLevel } else { $setup.Version }
        [pscustomobject]@{ instance = $p.Name; version = "$ver"; edition = "$($setup.Edition)" }
    }
}

# A SQL Server version maps to one service-pack line; GDR-branch builds are
# compared with the latest GDR, CU-branch builds with the latest CU.
function Get-SqlRuntime($Instance) {
    $iv = @([regex]::Matches($Instance.version, '\d+') | ForEach-Object { [int]$_.Value })
    $cands = @(Get-EolData 'mssqlserver' | Where-Object {
        $c = "$($_.cycle)" -split '[.-]'
        "$($_.cycle)" -notlike '*-acp' -and [int]$c[0] -eq $iv[0] -and [int]$c[1] -eq $iv[1]
    })
    if (-not $cands) { return $null }
    $pick = $null
    foreach ($c in $cands) {
        $lat = ("$($c.latest)" -split ' ')[0]
        if ((Compare-Version $Instance.version $lat) -le 0 -and
            (-not $pick -or (Compare-Version $lat ("$($pick.latest)" -split ' ')[0]) -lt 0)) { $pick = $c }
    }
    if (-not $pick) {
        foreach ($c in $cands) {
            if (-not $pick -or (Compare-Version ("$($c.latest)" -split ' ')[0] ("$($pick.latest)" -split ' ')[0]) -gt 0) { $pick = $c }
        }
    }
    $latest = ("$($pick.latest)" -split ' ')[0]
    if ($pick.latestGdr) {
        $gdr = @([regex]::Matches("$($pick.latestGdr)", '\d+') | ForEach-Object { [int]$_.Value })
        if ($iv.Count -gt 2 -and $gdr.Count -gt 2 -and [Math]::Floor($iv[2] / 1000) -eq [Math]::Floor($gdr[2] / 1000)) {
            $latest = "$($pick.latestGdr)"
        }
    }
    $rel = ("$($pick.releaseLabel)" -replace " ?'__CODENAME__'", '').Trim()
    if (-not $rel) { $rel = "$($pick.cycle)" }
    [pscustomobject]@{
        product = 'mssqlserver'; name = "SQL Server $rel ($($Instance.instance))"; version = $Instance.version
        cycle = "$($pick.cycle)"; label = "SQL Server $rel ($($Instance.instance))"
        path = "SQL Server instance $($Instance.instance)"; cycle_data = $pick; latest_override = $latest
    }
}

function Add-RuntimeStatus($Runtime, [datetime]$Today) {
    $c = $Runtime.cycle_data
    if (-not $c) { $c = @(Get-EolData $Runtime.product | Where-Object { "$($_.cycle)" -eq $Runtime.cycle })[0] }
    $status = 'unknown'; $eolDate = ''; $latest = ''
    if ($c) {
        $st = Get-EolState $c $Today
        $eolDate = $st.date
        $latest = if ($Runtime.latest_override) { $Runtime.latest_override } else { ("$($c.latest)" -split ' ')[0] }
        if ($st.eol) { $status = 'eol' }
        elseif ($latest -and (Compare-Version $Runtime.version $latest) -lt 0) { $status = 'outdated' }
        else { $status = 'ok' }
    }
    [pscustomobject]@{
        product = $Runtime.product; name = $Runtime.name; version = $Runtime.version; cycle = $Runtime.cycle
        label = $Runtime.label; path = $Runtime.path; status = $status; eol_date = $eolDate; latest = $latest
    }
}

# --------------------------------------------------------------------------
# winget
# --------------------------------------------------------------------------

function Find-Winget {
    $c = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    # SYSTEM has no per-user App Execution Alias; use the package folder directly
    $pattern = Join-Path $env:ProgramFiles 'WindowsApps\Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe\winget.exe'
    $f = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($f) { return $f.FullName }
    $null
}

function Invoke-WingetList([string]$Exe) {
    try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { }
    $out = @(& $Exe upgrade --include-unknown --source winget --accept-source-agreements --disable-interactivity 2>&1 |
             ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0 -and -not ($out -match '^-{10,}')) {
        # older winget without --include-unknown / --disable-interactivity
        $out = @(& $Exe upgrade --source winget --accept-source-agreements 2>&1 | ForEach-Object { "$_" })
    }
    if ($LASTEXITCODE -ne 0 -and -not ($out -match '^-{10,}') -and -not ($out -match 'No (installed )?(package|applicable)')) {
        throw "winget upgrade failed (exit $LASTEXITCODE): $((($out | Where-Object { $_.Trim() }) | Select-Object -Last 2) -join ' ')"
    }
    $out
}

# winget prints fixed-width tables (Name Id Version Available [Source]) under a
# line of dashes. Column positions come from the header, whatever its language.
function ConvertFrom-WingetTable([string[]]$Lines) {
    $Lines = @(foreach ($l in $Lines) { ($l -split "`r")[-1].TrimEnd() })
    for ($i = 1; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -notmatch '^-{10,}$') { continue }
        $hdr = $Lines[$i - 1]
        $starts = @()
        for ($k = 0; $k -lt $hdr.Length; $k++) {
            if ($hdr[$k] -ne ' ' -and ($k -eq 0 -or $hdr[$k - 1] -eq ' ')) { $starts += $k }
        }
        if ($starts.Count -lt 4) { continue }
        for ($j = $i + 1; $j -lt $Lines.Count; $j++) {
            $row = $Lines[$j]
            if ($row.Length -le $starts[3]) { break }
            $cols = @()
            for ($k = 0; $k -lt 4; $k++) {
                $end = if ($k + 1 -lt $starts.Count) { [Math]::Min($starts[$k + 1], $row.Length) } else { $row.Length }
                $cols += $row.Substring($starts[$k], [Math]::Max(0, $end - $starts[$k])).Trim()
            }
            if ($cols[1] -notmatch '^\S+$' -or -not $cols[2] -or $cols[3] -notmatch '^\S+$') { break }
            [pscustomobject]@{ name = $cols[0]; id = $cols[1]; version = $cols[2]; available = $cols[3] }
        }
    }
}

# --------------------------------------------------------------------------
# findings (DefectDojo "Generic Findings Import")
# --------------------------------------------------------------------------

function New-Finding([hashtable]$F) {
    $out = [ordered]@{}
    foreach ($k in 'title', 'severity', 'description', 'mitigation', 'references', 'component_name',
                   'component_version', 'file_path', 'vuln_id_from_tool', 'unique_id_from_tool', 'vulnerability_ids') {
        $v = $F[$k]
        if ($null -eq $v -or ($v -is [string] -and $v -eq '') -or ($v -is [array] -and $v.Count -eq 0)) { continue }
        $out[$k] = $v
    }
    $out['title'] = Get-Clip $out['title'] 500
    $out['static_finding'] = $true
    $out['dynamic_finding'] = $false
    $out['tags'] = $F['tags']
    $out
}

function ConvertTo-UpdateFinding($U, $HostInfo) {
    $sev = $MsrcSeverity[$U.msrc_severity]
    if (-not $sev) { $sev = if ($U.security) { 'High' } else { 'Info' } }
    $kb = if ($U.kb) { $U.kb[0] } else { '' }
    $desc = @("**Missing update:** $($U.title)")
    if ($U.kb) { $desc += '**KB:** ' + ($U.kb -join ', ') }
    $desc += '**Classification:** ' + $(if ($U.classification) { $U.classification } else { 'unknown' })
    $desc += '**Microsoft severity:** ' + $(if ($U.msrc_severity) { $U.msrc_severity } else { 'not rated' })
    if ($U.products) { $desc += '**Product:** ' + ($U.products -join ', ') }
    if ($U.cves) {
        $shown = @($U.cves | Select-Object -First 40)
        $desc += '**CVEs:** ' + ($shown -join ', ') + $(if ($U.cves.Count -gt 40) { " and $($U.cves.Count - 40) more" } else { '' })
    }
    $mit = 'Install {0} with Windows Update, WSUS or your patch tool, then restart if Windows asks for it.' -f $(if ($kb) { $kb } else { 'the update' })
    if ($U.published) { $mit += " Released $($U.published)." }
    $refs = @()
    if ($kb) { $refs += 'https://support.microsoft.com/help/' + $kb.Substring(2) }
    if ($U.support_url -and $refs -notcontains $U.support_url) { $refs += $U.support_url }
    New-Finding @{
        title = $U.title; severity = $sev; description = ($desc -join "`n"); mitigation = $mit
        references = ($refs -join "`n")
        component_name = $(if ($U.products) { $U.products[0] } else { 'Windows' })
        vuln_id_from_tool = $kb; unique_id_from_tool = 'wu|' + $U.update_id
        vulnerability_ids = @(@($U.cves) + @($U.kb))
        tags = @('vulnagent', 'windows', 'os', 'windows-update', $(if ($U.security) { 'security' } else { 'non-security' }))
    }
}

function ConvertTo-RuntimeFinding($R) {
    if ($R.status -eq 'eol') {
        $title = "$($R.label) is end-of-life"
        $sev = 'High'
        $mit = 'Upgrade to a supported release (end of support: {0}).' -f $(if ($R.eol_date) { $R.eol_date } else { 'unknown' })
    } else {
        $title = "$($R.name) $($R.version) is missing patch releases"
        $sev = 'Medium'
        $mit = "Update $($R.name) to $($R.latest) or later."
    }
    New-Finding @{
        title = $title; severity = $sev; mitigation = $mit
        description = ("**Software:** {0} {1}`n**Path:** {2}" -f $R.name, $R.version, $R.path)
        references = 'https://endoflife.date/' + $R.product
        component_name = $R.name; component_version = $R.version; file_path = $R.path
        vuln_id_from_tool = 'runtime-' + $R.status
        unique_id_from_tool = 'runtime|{0}|{1}|{2}' -f $R.name, $R.version, $R.path
        tags = @('vulnagent', 'windows', 'runtime', $R.status)
    }
}

function ConvertTo-OsFinding($Os, $HostInfo, [int]$WarnDays) {
    $build = '{0}.{1}' -f $HostInfo.version, $HostInfo.ubr
    if ($Os.eol) {
        $title = "$($Os.label) is end-of-life"; $sev = 'High'
        $mit = "Upgrade to a supported Windows version. Microsoft stopped security updates on $($Os.eol_date) (or buy Extended Security Updates)."
    } elseif ($null -ne $Os.days_left -and $Os.days_left -le $WarnDays) {
        $title = "$($Os.label) reaches end of support on $($Os.eol_date)"; $sev = 'Low'
        $mit = 'Plan the upgrade to a supported Windows version before that date.'
    } else {
        return $null
    }
    New-Finding @{
        title = $title; severity = $sev; mitigation = $mit
        description = ("**Operating system:** {0}`n**Edition:** {1}`n**Release:** {2}" -f $HostInfo.os, $HostInfo.edition, $Os.label)
        references = 'https://endoflife.date/' + $Os.product
        component_name = 'Windows'; component_version = $build
        vuln_id_from_tool = 'os-eol'; unique_id_from_tool = 'os-eol|' + $Os.cycle
        tags = @('vulnagent', 'windows', 'os', 'eol')
    }
}

function ConvertTo-AppFinding($A) {
    New-Finding @{
        title = "$($A.name) $($A.version) is outdated"; severity = 'Low'
        description = ("**Application:** {0}`n**winget ID:** {1}`n**Installed version:** {2}" -f $A.name, $A.id, $A.version)
        mitigation = "Update to $($A.available) or later (winget upgrade --id $($A.id))."
        component_name = $A.name; component_version = $A.version
        vuln_id_from_tool = 'app-outdated'; unique_id_from_tool = 'winget|{0}|{1}' -f $A.id, $A.version
        tags = @('vulnagent', 'windows', 'application', 'outdated')
    }
}

# --------------------------------------------------------------------------
# upload
# --------------------------------------------------------------------------

function New-Multipart($Fields, [string]$FileName, [byte[]]$Content) {
    $b = [guid]::NewGuid().ToString('N')
    $enc = New-Object Text.UTF8Encoding $false
    $ms = New-Object IO.MemoryStream
    $parts = @()
    foreach ($k in $Fields.Keys) {
        $parts += "--$b`r`nContent-Disposition: form-data; name=`"$k`"`r`n`r`n$($Fields[$k])`r`n"
    }
    $parts += "--$b`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$FileName`"`r`nContent-Type: application/json`r`n`r`n"
    foreach ($p in $parts) { $x = $enc.GetBytes($p); $ms.Write($x, 0, $x.Length) }
    $ms.Write($Content, 0, $Content.Length)
    $x = $enc.GetBytes("`r`n--$b--`r`n"); $ms.Write($x, 0, $x.Length)
    @{ body = $ms.ToArray(); type = "multipart/form-data; boundary=$b" }
}

function Enable-TrustAllCertificates {
    if (-not ('VulnagentTrustAll' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Net;
public static class VulnagentTrustAll {
    public static void Enable() { ServicePointManager.ServerCertificateValidationCallback = delegate { return true; }; }
}
'@
    }
    [VulnagentTrustAll]::Enable()
}

function Send-ToDefectDojo($Cfg, $HostInfo, $Doc, [bool]$Incomplete) {
    $base = "$($Cfg.url)".TrimEnd('/')
    if (-not $base) { throw "DefectDojo url is not set (config 'url' or -Url)" }
    $tok = if ($Cfg.api_token) { $Cfg.api_token } else { $env:DD_API_TOKEN }
    if (-not $tok) { throw "DefectDojo API token is not set (config 'api_token', -Token or env DD_API_TOKEN)" }
    $product = "$($Cfg.product_name)".Replace('{host}', $HostInfo.host).Replace('{short}', $HostInfo.short)
    $closeOld = [bool]$Cfg.close_old_findings
    if ($closeOld -and $Incomplete) {
        Write-Log 'part of the scan failed: not closing old findings this time'
        $closeOld = $false
    }
    $fields = [ordered]@{
        scan_type                   = $SCAN_TYPE
        product_type_name           = $Cfg.product_type
        product_name                = $product
        engagement_name             = $Cfg.engagement_name
        test_title                  = $Cfg.test_title
        auto_create_context         = 'true'
        close_old_findings          = $(if ($closeOld) { 'true' } else { 'false' })
        deduplication_on_engagement = 'true'
        minimum_severity            = $Cfg.minimum_severity
        active                      = 'true'
        verified                    = 'false'
        scan_date                   = (Get-Date).ToString('yyyy-MM-dd')
        version                     = $VERSION
    }
    $json = ConvertTo-Json -InputObject $Doc -Depth 8 -Compress
    $mp = New-Multipart $fields "vulnagent-$($HostInfo.host).json" ([Text.Encoding]::UTF8.GetBytes($json))
    $req = @{
        Uri = "$base/api/v2/reimport-scan/"; Method = 'Post'; Body = $mp.body; ContentType = $mp.type
        Headers = @{ Authorization = "Token $tok"; Accept = 'application/json' }
        UseBasicParsing = $true; TimeoutSec = [int]$Cfg.timeout; UserAgent = "vulnagent-win/$VERSION"
    }
    if (-not $Cfg.verify_tls) {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $req.SkipCertificateCheck = $true } else { Enable-TrustAllCertificates }
    }
    try {
        $r = Invoke-WebRequest @req
    } catch {
        $resp = $_.Exception.Response
        if ($resp) {
            $code = [int]$resp.StatusCode
            $detail = $_.ErrorDetails.Message
            if (-not $detail -and $resp -is [Net.HttpWebResponse]) {
                try { $detail = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch { }
            }
            $hint = @{ 401 = ' (wrong API token?)'; 403 = ' (the token user may not import into this product type)'
                       400 = ' (check that the user may create products)' }[$code]
            throw "DefectDojo returned HTTP $code$hint`n$(Get-Clip "$detail" 2000)"
        }
        throw "cannot reach DefectDojo at ${base}: $($_.Exception.Message)"
    }
    $content = $r.Content
    if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
    $res = if ($content) { $content | ConvertFrom-Json } else { $null }
    $stats = @()
    if ($res -and $res.statistics -and $res.statistics.delta) {
        foreach ($k in 'created', 'closed', 'reactivated', 'untouched') {
            $t = $res.statistics.delta.$k.total.total
            if ($null -ne $t) { $stats += "$k $t" }
        }
    }
    $testId = if ($res -and $res.test_id) { $res.test_id } elseif ($res) { $res.test } else { '?' }
    Write-Log ("uploaded to DefectDojo product '{0}' (test {1}){2}" -f $product, $testId,
               $(if ($stats) { ': ' + ($stats -join ', ') } else { '' }))
}

# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

function Invoke-Main {
    try {
        New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'reports') | Out-Null
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072  # TLS 1.2
        $cfg = Read-Config $ConfigPath
        if ($Url) { $cfg.url = $Url }
        if ($Token) { $cfg.api_token = $Token }
        if ($Insecure) { $cfg.verify_tls = $false }
        $today = Get-Date
        $errs = New-Object Collections.Generic.List[string]
        $hi = Get-HostInfo
        Write-Log "vulnagent-win $VERSION on $($hi.host): $($hi.os) $($hi.version).$($hi.ubr)"

        # 1. patching (off unless enabled in the config)
        $patch = $null
        $patchMode = "$($cfg.install_updates)".ToLower()
        if (-not $DryRun -and -not $NoPatch -and ($patchMode -eq 'security' -or $patchMode -eq 'all')) {
            try { $patch = Install-WindowsUpdates $cfg } catch { $errs.Add('patch: ' + (Get-WUErrorText $_)) }
        }
        $winget = if ($cfg.include_winget -or $cfg.winget_upgrade) { Find-Winget } else { $null }
        if (-not $DryRun -and -not $NoPatch -and $cfg.winget_upgrade -and $winget) {
            Write-Log 'patch: winget upgrade --all'
            & $winget upgrade --all --silent --source winget --accept-source-agreements --accept-package-agreements --disable-interactivity 2>&1 |
                ForEach-Object { "$_" } | Where-Object { $_ -match '\S' -and $_ -notmatch '^[\s\\|/-]+$' } |
                Select-Object -Last 20 | ForEach-Object { Write-Log "  $_" }
        }

        # 2. scan
        $findings = New-Object Collections.Generic.List[object]
        Write-Log 'searching for missing updates (this can take a few minutes)'
        $updates = @()
        try { $updates = @(Get-MissingUpdates $cfg) } catch { $errs.Add('Windows Update: ' + (Get-WUErrorText $_)) }
        $relevant = @($updates | Where-Object { $_.classification -ne 'Definition Updates' -and
                                                ($_.security -or $cfg.include_non_security_updates) })
        foreach ($u in $relevant) { $findings.Add((ConvertTo-UpdateFinding $u $hi)) }
        $secCount = @($updates | Where-Object { $_.security }).Count
        Write-Log "  $($updates.Count) updates missing, $secCount security"

        $reboot = Test-PendingReboot
        if ($reboot) {
            $findings.Add((New-Finding @{
                title = 'Restart pending to finish installing updates'; severity = 'Low'
                description = 'Updates were installed but are not active until Windows restarts.'
                mitigation = 'Restart the machine in the next maintenance window.'
                component_name = 'Windows'; vuln_id_from_tool = 'reboot-pending'; unique_id_from_tool = 'reboot-pending'
                tags = @('vulnagent', 'windows', 'os', 'reboot')
            }))
        }

        $osStatus = $null
        try {
            $osStatus = Get-OsStatus $hi $today
            if ($osStatus) {
                $f = ConvertTo-OsFinding $osStatus $hi ([int]$cfg.eol_warning_days)
                if ($f) { $findings.Add($f) }
                Write-Log "  $($osStatus.label): support until $($osStatus.eol_date)"
            }
        } catch { $errs.Add('OS end-of-life: ' + $_.Exception.Message) }

        $software = @()
        try { $software = @(Get-InstalledSoftware) } catch { $errs.Add('installed programs: ' + $_.Exception.Message) }
        $runtimes = @()
        if ($cfg.include_runtimes) {
            $list = @(Get-Runtimes $software)
            try { $list += @(Get-SqlInstances | ForEach-Object { Get-SqlRuntime $_ } | Where-Object { $_ }) }
            catch { $errs.Add('SQL Server: ' + $_.Exception.Message) }
            foreach ($r in $list) {
                try { $runtimes += Add-RuntimeStatus $r $today } catch { $errs.Add("$($r.name): $($_.Exception.Message)") }
            }
            foreach ($r in $runtimes) {
                if ($r.status -eq 'eol' -or $r.status -eq 'outdated') { $findings.Add((ConvertTo-RuntimeFinding $r)) }
                Write-Log "  $($r.name) $($r.version): $($r.status)"
            }
        }

        $apps = @()
        if ($cfg.include_winget -and $winget) {
            try {
                $apps = @(ConvertFrom-WingetTable @(Invoke-WingetList $winget))
                foreach ($a in $apps) { $findings.Add((ConvertTo-AppFinding $a)) }
                Write-Log "  winget: $($apps.Count) applications can be updated"
            } catch { $errs.Add('winget: ' + $_.Exception.Message) }
        }
        foreach ($e in $errs) { Write-Log "ERROR $e" }

        # 3. report + upload
        $doc = [ordered]@{
            name = 'vulnagent'; type = $SCAN_TYPE; version = $VERSION
            description = '{0} - {1} {2}.{3}, {4} updates missing ({5} security), {6} programs installed' -f `
                $hi.host, $hi.os, $hi.version, $hi.ubr, $updates.Count, $secCount, $software.Count
            findings = $findings.ToArray()
        }
        $report = [ordered]@{
            agent = "vulnagent-win $VERSION"; generated = $today.ToString('s'); host = $hi.host; system = $hi
            errors = $errs.ToArray(); patch = $patch; reboot_pending = $reboot; os_support = $osStatus
            missing_updates = @($updates | Select-Object -Property * -ExcludeProperty com)
            runtimes = $runtimes; outdated_apps = $apps; software = $software
            summary = [ordered]@{ findings = $findings.Count; updates_missing = $updates.Count; security_updates_missing = $secCount }
        }
        Write-JsonFile (Join-Path $DataDir 'reports\latest.json') $report
        Write-JsonFile (Join-Path $DataDir 'reports\findings.json') $doc
        if ($Output) { Write-JsonFile $Output $doc; Write-Log "wrote $Output" }
        $bySev = foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
            $n = @($findings | Where-Object { $_.severity -eq $s }).Count
            if ($n) { "$s $n" }
        }
        Write-Log ("{0} findings: {1}" -f $findings.Count, $(if ($bySev) { $bySev -join ', ' } else { 'none' }))
        if ($DryRun) { return 0 }

        Send-ToDefectDojo $cfg $hi $doc ($errs.Count -gt 0)

        if ($patch -and $patch.reboot_required -and $cfg.reboot_after_updates) {
            Write-Log 'restarting in 10 minutes to finish installing updates'
            & shutdown.exe /r /t 600 /d p:2:17 /c 'vulnagent: restarting to finish installing Windows updates' | Out-Null
        }
        if ($errs.Count) { return 2 }
        return 0
    } catch {
        Write-Log "ERROR $($_.Exception.Message)"
        return 3
    }
}

if ($MyInvocation.InvocationName -ne '.') { exit [int]@(Invoke-Main)[-1] }
