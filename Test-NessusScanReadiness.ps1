#Requires -Version 5.1
<#
.SYNOPSIS
    Nessus Windows Credentialed (Authenticated) Scan Readiness Checker + CIS Benchmark identifier.

.DESCRIPTION
    Run locally on a Windows target (as Administrator) BEFORE launching a Nessus
    authenticated/credentialed scan. It validates the prerequisites Nessus needs to
    authenticate and collect data over SMB / WMI / Remote Registry, and identifies the
    correct CIS Benchmark family for the detected operating system.

    Checks performed:
      - Administrative privilege of the running context
      - OS version detection + CIS Benchmark mapping
      - Required services (Server, Workstation, WMI, Remote Registry)
      - Administrative shares (ADMIN$, C$, IPC$) and AutoShare policy
      - UAC remote token policy (LocalAccountTokenFilterPolicy / FilterAdministratorToken)
      - Windows Firewall profiles + File/Printer Sharing and WMI inbound rules
      - SMB listener / RPC / NetBIOS ports
      - SMB server configuration (signing, SMBv1/2/3)
      - Live WMI/CIM query test

.PARAMETER ScanAccountType
    Account type Nessus will authenticate with. Affects the UAC token verdict.
      Domain       - A domain account that is a local admin on this host (recommended).
      BuiltinAdmin - The built-in local Administrator (RID 500).
      LocalAdmin   - A NON-builtin local administrator account.
    Default: Domain

.PARAMETER JsonReport
    Optional path to write machine-readable JSON results (e.g. for Abriska/import pipelines).

.PARAMETER HtmlReport
    Optional path to write a dark-themed HTML report.

.EXAMPLE
    .\Test-NessusScanReadiness.ps1

.EXAMPLE
    .\Test-NessusScanReadiness.ps1 -ScanAccountType LocalAdmin -HtmlReport .\readiness.html -JsonReport .\readiness.json

.NOTES
    Author  : Dan (Mr-Whiskerss)
    Version : 1.0.0
    Run elevated (Administrator) for complete and accurate results.
    Note: this validates host-side readiness. From the scanner side, an SMB auth/admin
    test can be done with NetExec, e.g.  nxc smb <target> -u <user> -p <pass>
#>

[CmdletBinding()]
param(
    [ValidateSet('Domain', 'BuiltinAdmin', 'LocalAdmin')]
    [string]$ScanAccountType = 'Domain',

    [string]$JsonReport,

    [string]$HtmlReport
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Results = New-Object System.Collections.Generic.List[object]
$script:ToolVersion = '1.0.0'

# ----------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------
function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')]
        [string]$Status,
        [string]$Detail,
        [string]$Recommendation = ''
    )
    $script:Results.Add([pscustomobject]@{
        Category       = $Category
        Check          = $Check
        Status         = $Status
        Detail         = $Detail
        Recommendation = $Recommendation
    })

    $colour = switch ($Status) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        'INFO' { 'Cyan' }
    }
    Write-Host ('  [{0}] ' -f $Status) -ForegroundColor $colour -NoNewline
    Write-Host ('{0,-34} ' -f $Check) -ForegroundColor White -NoNewline
    Write-Host $Detail -ForegroundColor Gray
    if ($Recommendation -and $Status -in 'WARN', 'FAIL') {
        Write-Host ('         -> {0}' -f $Recommendation) -ForegroundColor DarkYellow
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=== {0} ' -f $Title).PadRight(74, '=') -ForegroundColor Magenta
}

# ----------------------------------------------------------------------------------
# CIS Benchmark mapping
# ----------------------------------------------------------------------------------
function Get-CisBenchmark {
    param([int]$Build, [int]$ProductType, [string]$DisplayVersion)

    # ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server
    $isServer = ($ProductType -ne 1)
    $rel = if ($DisplayVersion) { " ($DisplayVersion)" } else { '' }

    if ($isServer) {
        switch ($Build) {
            { $_ -ge 26100 } { return [pscustomobject]@{ OS = "Windows Server 2025$rel"; Benchmark = 'CIS Microsoft Windows Server 2025 Benchmark' }; break }
            20348           { return [pscustomobject]@{ OS = "Windows Server 2022$rel"; Benchmark = 'CIS Microsoft Windows Server 2022 Benchmark' }; break }
            17763           { return [pscustomobject]@{ OS = 'Windows Server 2019';      Benchmark = 'CIS Microsoft Windows Server 2019 Benchmark' }; break }
            14393           { return [pscustomobject]@{ OS = 'Windows Server 2016';      Benchmark = 'CIS Microsoft Windows Server 2016 Benchmark' }; break }
            9600            { return [pscustomobject]@{ OS = 'Windows Server 2012 R2';   Benchmark = 'CIS Microsoft Windows Server 2012 R2 Benchmark' }; break }
            9200            { return [pscustomobject]@{ OS = 'Windows Server 2012';      Benchmark = 'CIS Microsoft Windows Server 2012 (non-R2) Benchmark' }; break }
            7601            { return [pscustomobject]@{ OS = 'Windows Server 2008 R2';   Benchmark = 'CIS Microsoft Windows Server 2008 R2 Benchmark (legacy)' }; break }
            default         { return [pscustomobject]@{ OS = "Windows Server (build $Build)"; Benchmark = 'No exact match - select nearest CIS Windows Server Benchmark' } }
        }
    }
    else {
        if ($Build -ge 22000) {
            return [pscustomobject]@{ OS = "Windows 11$rel"; Benchmark = 'CIS Microsoft Windows 11 Enterprise Benchmark' }
        }
        switch ($Build) {
            19045   { return [pscustomobject]@{ OS = 'Windows 10 (22H2)'; Benchmark = 'CIS Microsoft Windows 10 Enterprise Benchmark' }; break }
            19044   { return [pscustomobject]@{ OS = 'Windows 10 (21H2)'; Benchmark = 'CIS Microsoft Windows 10 Enterprise Benchmark' }; break }
            9600    { return [pscustomobject]@{ OS = 'Windows 8.1';       Benchmark = 'CIS Microsoft Windows 8.1 Benchmark (legacy)' }; break }
            7601    { return [pscustomobject]@{ OS = 'Windows 7';         Benchmark = 'CIS Microsoft Windows 7 Benchmark (legacy)' }; break }
            default {
                if ($Build -ge 10240 -and $Build -lt 22000) {
                    return [pscustomobject]@{ OS = "Windows 10$rel"; Benchmark = 'CIS Microsoft Windows 10 Enterprise Benchmark' }
                }
                return [pscustomobject]@{ OS = "Windows (build $Build)"; Benchmark = 'No exact match - select nearest CIS Windows Benchmark' }
            }
        }
    }
}

# ----------------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------------
Clear-Host
Write-Host ''
Write-Host '  Nessus Windows Credentialed Scan - Readiness Checker' -ForegroundColor Cyan
Write-Host ('  Version {0}   |   Host: {1}   |   {2}' -f $script:ToolVersion, $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray
Write-Host ('  Scan account type assumed: {0}' -f $ScanAccountType) -ForegroundColor DarkGray

# ----------------------------------------------------------------------------------
# 0. Privilege context
# ----------------------------------------------------------------------------------
Write-Section 'Execution Context'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Add-Result 'Context' 'Running elevated' 'PASS' 'Script is running with Administrator privileges.'
}
else {
    Add-Result 'Context' 'Running elevated' 'WARN' 'NOT elevated - some checks (firewall/registry/services) may be incomplete.' 'Re-run this script from an elevated PowerShell prompt for full accuracy.'
}

# ----------------------------------------------------------------------------------
# 1. OS detection + CIS
# ----------------------------------------------------------------------------------
Write-Section 'Operating System / CIS Benchmark'
$os  = Get-CimInstance -ClassName Win32_OperatingSystem
$cs  = Get-CimInstance -ClassName Win32_ComputerSystem
$cv  = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

$buildNumber   = [int]$os.BuildNumber
$ubr           = $cv.UBR
$displayVer    = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
$productType   = [int]$os.ProductType
$fullBuild     = if ($ubr) { "$buildNumber.$ubr" } else { "$buildNumber" }
$cis           = Get-CisBenchmark -Build $buildNumber -ProductType $productType -DisplayVersion $displayVer

$ptName = switch ($productType) { 1 { 'Workstation' } 2 { 'Domain Controller' } 3 { 'Server' } default { 'Unknown' } }

Add-Result 'OS' 'Caption'           'INFO' $os.Caption
Add-Result 'OS' 'Version / Build'   'INFO' ("{0}  (build {1})" -f $os.Version, $fullBuild)
Add-Result 'OS' 'Feature update'    'INFO' ($(if ($displayVer) { $displayVer } else { 'n/a' }))
Add-Result 'OS' 'Edition / Role'    'INFO' ("{0}  -  {1}  -  {2}" -f $cv.EditionID, $os.OSArchitecture, $ptName)
Add-Result 'OS' 'Domain membership' 'INFO' $(if ($cs.PartOfDomain) { "Domain-joined: $($cs.Domain)" } else { "Workgroup: $($cs.Workgroup)" })
Add-Result 'CIS' 'Mapped OS'        'INFO' $cis.OS
Add-Result 'CIS' 'Recommended Benchmark' 'INFO' $cis.Benchmark

# ----------------------------------------------------------------------------------
# 2. Required services
# ----------------------------------------------------------------------------------
Write-Section 'Required Services'
function Test-ServiceState {
    param([string]$Name, [string]$Friendly, [bool]$MustRun, [string]$Reco)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Add-Result 'Service' $Friendly 'FAIL' 'Service not present on this host.' $Reco
        return
    }
    $startType = (Get-CimInstance Win32_Service -Filter "Name='$Name'").StartMode
    $detail = "Status: $($svc.Status); StartType: $startType"

    if ($Name -eq 'RemoteRegistry') {
        if ($startType -eq 'Disabled') {
            Add-Result 'Service' $Friendly 'FAIL' "$detail (Disabled - cannot be auto-started by Nessus)." 'Set startup to Manual. Nessus can then start it during the scan if "Start the Remote Registry service during the scan" is enabled.'
        }
        elseif ($svc.Status -ne 'Running') {
            Add-Result 'Service' $Friendly 'WARN' "$detail (not running)." 'OK if Nessus is configured to start Remote Registry during the scan; otherwise set it running.'
        }
        else {
            Add-Result 'Service' $Friendly 'PASS' $detail
        }
        return
    }

    if ($MustRun) {
        if ($svc.Status -eq 'Running') { Add-Result 'Service' $Friendly 'PASS' $detail }
        else { Add-Result 'Service' $Friendly 'FAIL' "$detail (required, not running)." $Reco }
    }
    else {
        if ($svc.Status -eq 'Running') { Add-Result 'Service' $Friendly 'PASS' $detail }
        else { Add-Result 'Service' $Friendly 'WARN' "$detail (recommended running)." $Reco }
    }
}

Test-ServiceState -Name 'LanmanServer'      -Friendly 'Server (admin shares)'   -MustRun $true  -Reco 'Start the Server service; required for ADMIN$/C$ and SMB collection.'
Test-ServiceState -Name 'Winmgmt'           -Friendly 'Windows Mgmt Instr (WMI)' -MustRun $true  -Reco 'Start the WMI service; Nessus uses WMI for much of its data collection.'
Test-ServiceState -Name 'LanmanWorkstation' -Friendly 'Workstation'             -MustRun $false -Reco 'Start the Workstation service for full SMB client functionality.'
Test-ServiceState -Name 'RemoteRegistry'    -Friendly 'Remote Registry'         -MustRun $false -Reco ''

# ----------------------------------------------------------------------------------
# 3. Administrative shares
# ----------------------------------------------------------------------------------
Write-Section 'Administrative Shares'
$shares = $null
try { $shares = Get-SmbShare -ErrorAction Stop | Select-Object -ExpandProperty Name }
catch { $shares = Get-CimInstance Win32_Share | Select-Object -ExpandProperty Name }

foreach ($req in 'ADMIN$', 'C$', 'IPC$') {
    if ($shares -contains $req) {
        Add-Result 'Shares' "$req share" 'PASS' 'Present.'
    }
    else {
        $sev = if ($req -eq 'IPC$') { 'WARN' } else { 'FAIL' }
        Add-Result 'Shares' "$req share" $sev "Not present - Nessus relies on this share for credentialed access." 'Ensure default administrative shares are enabled (see AutoShare policy below).'
    }
}

$lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$autoKey = if ($productType -eq 1) { 'AutoShareWks' } else { 'AutoShareServer' }
$autoVal = $lsa.$autoKey
if ($null -eq $autoVal) {
    Add-Result 'Shares' "$autoKey policy" 'PASS' 'Not set (admin shares enabled by default).'
}
elseif ($autoVal -eq 0) {
    Add-Result 'Shares' "$autoKey policy" 'FAIL' "$autoKey = 0 (administrative shares are DISABLED)." "Delete or set $autoKey = 1 under LanmanServer\Parameters, then restart the Server service."
}
else {
    Add-Result 'Shares' "$autoKey policy" 'PASS' "$autoKey = $autoVal (admin shares enabled)."
}

# ----------------------------------------------------------------------------------
# 4. UAC remote token policy
# ----------------------------------------------------------------------------------
Write-Section 'UAC Remote Token Policy'
$polPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$pol     = Get-ItemProperty -Path $polPath
$latfp   = $pol.LocalAccountTokenFilterPolicy
$fat     = $pol.FilterAdministratorToken

switch ($ScanAccountType) {
    'Domain' {
        Add-Result 'UAC' 'Account strategy' 'PASS' 'Domain admin account selected - remote UAC token filtering does not apply to domain accounts.'
    }
    'BuiltinAdmin' {
        if ($fat -eq 1) {
            Add-Result 'UAC' 'FilterAdministratorToken' 'WARN' 'FilterAdministratorToken = 1 - even the built-in Administrator receives a filtered token remotely.' 'Set FilterAdministratorToken = 0, or use a domain account, or set LocalAccountTokenFilterPolicy = 1.'
        }
        else {
            Add-Result 'UAC' 'Account strategy' 'PASS' 'Built-in Administrator (RID 500) is exempt from remote UAC filtering by default.'
        }
    }
    'LocalAdmin' {
        if ($latfp -eq 1) {
            Add-Result 'UAC' 'LocalAccountTokenFilterPolicy' 'PASS' 'LocalAccountTokenFilterPolicy = 1 - non-builtin local admins receive a full token remotely.'
        }
        else {
            Add-Result 'UAC' 'LocalAccountTokenFilterPolicy' 'FAIL' ("Value is '{0}' - non-builtin local admin accounts get a FILTERED token remotely; the scan will fail to authenticate properly." -f $(if ($null -eq $latfp) { 'not set' } else { $latfp })) 'Set HKLM\...\Policies\System\LocalAccountTokenFilterPolicy = 1 (DWORD), OR scan with the built-in Administrator / a domain account instead. (Note: enabling LATFP weakens UAC remote restrictions - scope it appropriately.)'
        }
    }
}

# ----------------------------------------------------------------------------------
# 5. Firewall
# ----------------------------------------------------------------------------------
Write-Section 'Windows Firewall'
$fwOK = $true
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    foreach ($p in $profiles) {
        $state = if ($p.Enabled) { 'ON' } else { 'OFF' }
        Add-Result 'Firewall' "$($p.Name) profile" 'INFO' "Firewall: $state"
    }
    $activeProfileOn = ($profiles | Where-Object { $_.Enabled }).Count -gt 0

    if ($activeProfileOn) {
        $smbRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' -and ($_.DisplayGroup -like '*File and Printer Sharing*') }
        if ($smbRules) {
            Add-Result 'Firewall' 'File & Printer Sharing (in)' 'PASS' ("{0} inbound rule(s) enabled (SMB/445, NetBIOS/139)." -f $smbRules.Count)
        }
        else {
            Add-Result 'Firewall' 'File & Printer Sharing (in)' 'FAIL' 'No enabled inbound File and Printer Sharing rules found on an active firewall profile.' 'Enable the "File and Printer Sharing" inbound group (or scope the scanner source) so SMB/445 is reachable.'
            $fwOK = $false
        }

        $wmiRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' -and ($_.DisplayGroup -like '*Windows Management Instrumentation*') }
        if ($wmiRules) {
            Add-Result 'Firewall' 'WMI inbound rules' 'PASS' ("{0} inbound WMI rule(s) enabled." -f $wmiRules.Count)
        }
        else {
            Add-Result 'Firewall' 'WMI inbound rules' 'WARN' 'No enabled inbound WMI rules found; some WMI-based plugins may fail.' 'Enable the "Windows Management Instrumentation (WMI)" inbound group if WMI collection is required.'
        }
    }
    else {
        Add-Result 'Firewall' 'Profile state' 'INFO' 'All firewall profiles are OFF - no host firewall obstruction.'
    }
}
catch {
    # Fallback for hosts without the NetSecurity module
    $fw = netsh advfirewall show allprofiles state 2>$null
    Add-Result 'Firewall' 'Profile state (netsh)' 'INFO' ($fw -join ' ')
    Add-Result 'Firewall' 'Rule inspection' 'WARN' 'NetSecurity module unavailable; could not enumerate individual rules.' 'Manually confirm File and Printer Sharing and WMI inbound rules.'
}

# ----------------------------------------------------------------------------------
# 6. Listening ports
# ----------------------------------------------------------------------------------
Write-Section 'Listening Ports (SMB / RPC / NetBIOS)'
function Test-Listener {
    param([int]$Port, [string]$Name, [bool]$Critical)
    $listening = $false
    try {
        $listening = [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
    }
    catch {
        $listening = [bool]((netstat -ano | Select-String -Pattern (":{0}\s" -f $Port)) -match 'LISTENING')
    }
    if ($listening) {
        Add-Result 'Ports' ("TCP {0} ({1})" -f $Port, $Name) 'PASS' 'Listening locally.'
    }
    else {
        $sev = if ($Critical) { 'FAIL' } else { 'WARN' }
        Add-Result 'Ports' ("TCP {0} ({1})" -f $Port, $Name) $sev 'Not listening locally.' 'Confirm the relevant service is running and reachable from the scanner.'
    }
}
Test-Listener -Port 445 -Name 'SMB'      -Critical $true
Test-Listener -Port 135 -Name 'RPC/WMI'  -Critical $true
Test-Listener -Port 139 -Name 'NetBIOS'  -Critical $false

# ----------------------------------------------------------------------------------
# 7. SMB server configuration (informative)
# ----------------------------------------------------------------------------------
Write-Section 'SMB Server Configuration'
try {
    $smbCfg = Get-SmbServerConfiguration -ErrorAction Stop
    Add-Result 'SMB' 'SMBv1 enabled'        $(if ($smbCfg.EnableSMB1Protocol) { 'WARN' } else { 'PASS' }) ("EnableSMB1Protocol = {0}" -f $smbCfg.EnableSMB1Protocol) $(if ($smbCfg.EnableSMB1Protocol) { 'SMBv1 is deprecated/insecure - note as a finding; not required for scanning.' } else { '' })
    Add-Result 'SMB' 'SMBv2/3 enabled'      $(if ($smbCfg.EnableSMB2Protocol) { 'PASS' } else { 'FAIL' }) ("EnableSMB2Protocol = {0}" -f $smbCfg.EnableSMB2Protocol) $(if (-not $smbCfg.EnableSMB2Protocol) { 'Enable SMB2/3 - required for modern SMB collection.' } else { '' })
    Add-Result 'SMB' 'Server signing required' 'INFO' ("RequireSecuritySignature = {0}" -f $smbCfg.RequireSecuritySignature)
}
catch {
    Add-Result 'SMB' 'SMB configuration' 'INFO' 'Get-SmbServerConfiguration unavailable on this host.'
}

# ----------------------------------------------------------------------------------
# 8. Live WMI/CIM test
# ----------------------------------------------------------------------------------
Write-Section 'WMI / CIM Functional Test'
try {
    $null = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    Add-Result 'WMI' 'Local CIM query' 'PASS' 'WMI repository responded to a Win32_ComputerSystem query.'
}
catch {
    Add-Result 'WMI' 'Local CIM query' 'FAIL' 'WMI query failed - repository may be corrupt or the service is impaired.' 'Investigate the WMI repository (winmgmt /verifyrepository) before scanning.'
}

# ----------------------------------------------------------------------------------
# Summary + verdict
# ----------------------------------------------------------------------------------
$pass = ($script:Results | Where-Object Status -eq 'PASS').Count
$warn = ($script:Results | Where-Object Status -eq 'WARN').Count
$fail = ($script:Results | Where-Object Status -eq 'FAIL').Count

Write-Host ''
Write-Host ('=' * 74) -ForegroundColor Magenta
Write-Host '  SUMMARY' -ForegroundColor Magenta
Write-Host ('=' * 74) -ForegroundColor Magenta
Write-Host ('  PASS: {0}    WARN: {1}    FAIL: {2}' -f $pass, $warn, $fail) -ForegroundColor White

if ($fail -gt 0) {
    $verdict = 'NOT READY - credentialed scan is likely to FAIL until the FAIL items above are resolved.'
    $vColour = 'Red'
}
elseif ($warn -gt 0) {
    $verdict = 'READY WITH CAVEATS - the scan should authenticate, but review the WARN items.'
    $vColour = 'Yellow'
}
else {
    $verdict = 'READY - all prerequisites for a Nessus credentialed scan are satisfied.'
    $vColour = 'Green'
}
Write-Host ''
Write-Host "  VERDICT: $verdict" -ForegroundColor $vColour
Write-Host ''
Write-Host ("  CIS Benchmark: {0}" -f $cis.Benchmark) -ForegroundColor Cyan
Write-Host ("  Detected OS  : {0}  (build {1})" -f $cis.OS, $fullBuild) -ForegroundColor Cyan
Write-Host '  (Download the latest revision of this benchmark from workbench.cisecurity.org)' -ForegroundColor DarkGray
Write-Host ''

# ----------------------------------------------------------------------------------
# JSON report
# ----------------------------------------------------------------------------------
if ($JsonReport) {
    $payload = [pscustomobject]@{
        tool          = 'Nessus Windows Scan Readiness Checker'
        version       = $script:ToolVersion
        generated     = (Get-Date).ToString('s')
        host          = $env:COMPUTERNAME
        scanAccount   = $ScanAccountType
        os            = $os.Caption
        build         = $fullBuild
        featureUpdate = $displayVer
        cisOS         = $cis.OS
        cisBenchmark  = $cis.Benchmark
        verdict       = $verdict
        counts        = @{ pass = $pass; warn = $warn; fail = $fail }
        results       = $script:Results
    }
    $payload | ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonReport -Encoding UTF8
    Write-Host "  JSON report written to: $JsonReport" -ForegroundColor DarkGray
}

# ----------------------------------------------------------------------------------
# HTML report (dark theme)
# ----------------------------------------------------------------------------------
if ($HtmlReport) {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $rows = foreach ($r in $script:Results) {
        $badge = switch ($r.Status) {
            'PASS' { 'background:#15803d' }
            'WARN' { 'background:#b45309' }
            'FAIL' { 'background:#b91c1c' }
            'INFO' { 'background:#1d4ed8' }
        }
        $reco = if ($r.Recommendation) { "<div class='reco'>$([System.Web.HttpUtility]::HtmlEncode($r.Recommendation))</div>" } else { '' }
        @"
<tr>
  <td class='cat'>$([System.Web.HttpUtility]::HtmlEncode($r.Category))</td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($r.Check))</td>
  <td><span class='badge' style='$badge'>$($r.Status)</span></td>
  <td>$([System.Web.HttpUtility]::HtmlEncode($r.Detail))$reco</td>
</tr>
"@
    }
    $vClass = if ($fail -gt 0) { 'fail' } elseif ($warn -gt 0) { 'warn' } else { 'pass' }
    $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>Nessus Scan Readiness - $env:COMPUTERNAME</title>
<style>
 body{background:#0b0f17;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:32px;}
 h1{font-size:20px;margin:0 0 4px;} .sub{color:#94a3b8;font-size:13px;margin-bottom:24px;}
 .cards{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;}
 .card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px 18px;min-width:120px;}
 .card .n{font-size:24px;font-weight:700;} .pass .n{color:#22c55e;} .warn .n{color:#f59e0b;} .fail .n{color:#ef4444;}
 .verdict{padding:14px 18px;border-radius:10px;margin-bottom:24px;font-weight:600;}
 .verdict.pass{background:#052e16;border:1px solid #15803d;} .verdict.warn{background:#3a2a06;border:1px solid #b45309;} .verdict.fail{background:#3b0a0a;border:1px solid #b91c1c;}
 .cis{background:#0e1a2b;border:1px solid #1e3a5f;border-radius:10px;padding:14px 18px;margin-bottom:24px;}
 table{width:100%;border-collapse:collapse;font-size:13px;} th{text-align:left;color:#94a3b8;border-bottom:1px solid #1f2937;padding:8px;}
 td{border-bottom:1px solid #161e2e;padding:8px;vertical-align:top;} td.cat{color:#64748b;width:90px;}
 .badge{padding:2px 9px;border-radius:6px;color:#fff;font-size:11px;font-weight:700;letter-spacing:.5px;}
 .reco{color:#facc15;font-size:12px;margin-top:4px;}
</style></head><body>
<h1>Nessus Windows Credentialed Scan - Readiness Report</h1>
<div class='sub'>Host: $env:COMPUTERNAME &nbsp;|&nbsp; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; Scan account: $ScanAccountType &nbsp;|&nbsp; v$($script:ToolVersion)</div>
<div class='cards'>
 <div class='card pass'><div class='n'>$pass</div><div>PASS</div></div>
 <div class='card warn'><div class='n'>$warn</div><div>WARN</div></div>
 <div class='card fail'><div class='n'>$fail</div><div>FAIL</div></div>
</div>
<div class='verdict $vClass'>$([System.Web.HttpUtility]::HtmlEncode($verdict))</div>
<div class='cis'><strong>CIS Benchmark:</strong> $([System.Web.HttpUtility]::HtmlEncode($cis.Benchmark))<br>
<strong>Detected OS:</strong> $([System.Web.HttpUtility]::HtmlEncode($cis.OS)) (build $fullBuild) &nbsp;-&nbsp; download the latest revision from workbench.cisecurity.org</div>
<table><thead><tr><th>Category</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table>
</body></html>
"@
    $html | Out-File -FilePath $HtmlReport -Encoding UTF8
    Write-Host "  HTML report written to: $HtmlReport" -ForegroundColor DarkGray
}
