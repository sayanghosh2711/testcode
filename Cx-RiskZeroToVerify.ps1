   .\CxAutoclose.ps1 -StartsWith 177674 -Resume "C:\Users\SG39673\Downloads\cx_riskzero_toverify_20261031_1717.csv"
<#
.SYNOPSIS
  Checkmarx CxSAST 9.7 - for every project whose LATEST scan has Risk Level Score 0:
    1. lock the latest scan if it is unlocked
    2. check whether it has results in "To Verify" state
  Writes a CSV report, and also an .xlsx if Microsoft Excel is installed.

  Runs on built-in Windows PowerShell 5.1. Nothing to install.

.EXAMPLE
  # Safe test - 3 projects, locks nothing. Copy the token first (see -Help).
  .\Cx-RiskZeroToVerify.ps1 -NameFilter 171532 -Limit 3 -DryRun

.EXAMPLE
  # Real run
  .\Cx-RiskZeroToVerify.ps1 -NameFilter 171532
#>
[CmdletBinding()]
param(
    [string]$BaseUrl    = "https://securecodeanalysis02.citigroup.net",
    [string]$NameFilter = "",        # part of the project name, e.g. 171532
    [string]$StartsWith = "",        # project name must START with this, e.g. 123278
    [int]   $RiskScore  = 0,         # only open projects whose latest scan has this score
    [switch]$AnyRisk,                # ignore the risk score and open every project
    [int]   $Limit      = 0,         # only process the first N projects (testing)
    [switch]$DryRun,                 # report only, never lock anything
    [int]   $ReportTimeoutMinutes = 5,  # how long to wait for each XML report
    [string[]]$Resume = @(),         # previous report CSV(s): skip projects already done, merge into one report
    [int]   $DelayMs = 500,          # pause before every API call so we don't overload the shared server
    [switch]$Diagnose,               # print what the API returns for ONE project, change nothing
    [string]$Token      = $env:CX_TOKEN,    # bearer token OR the full Cookie value - auto-detected
    [string]$OutDir     = ".",
    [switch]$SkipCertCheck,          # only if you get SSL/TLS trust errors
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$script:TokenExpired = $false
$script:RateLimited  = $false

$HelpText = @"

HOW TO GIVE THE SCRIPT YOUR LOGIN (SSO users)
---------------------------------------------
The script accepts either of two things from your logged-in Edge session.
It works out which one you gave it.

OPTION 1 - Session cookie (use this if you see no "Authorization" header)
1. Log in to Checkmarx in Edge as usual.
2. Press F12 -> Network tab -> tick "Preserve log" -> type cxrestapi in the
   filter box.
3. Click around Checkmarx (e.g. Projects & Scans) so requests appear.
4. Click a request named "Latest" or "scansQueue?projectId=..."
   (NOT "openid-configuration").
5. Headers -> Request Headers -> find the line called "Cookie".
   Right-click its value -> Copy value. It is long and contains
   ASP.NET_SessionId=...; ... CXCSRFToken=...  - copy all of it.

OPTION 2 - Bearer token
   Same steps, but copy the value of an "Authorization: Bearer eyJ..." line,
   or the access_token from Application -> Session storage -> 'oidc.user:...'.

Then run the script. When it asks, make sure the value is on your clipboard
and press Enter. The script reads it from the clipboard, then clears it.

Both are LIVE LOGIN CREDENTIALS carrying YOUR permissions. Never paste them
into chats, tickets, emails or screenshots. Keep Edge logged in while the
script runs; log out of Checkmarx when you are finished to end the session.

"@
if ($Help) { Write-Host $HelpText; return }

# --------------------------------------------------------------------------- #
# environment checks
# --------------------------------------------------------------------------- #
$langMode = $ExecutionContext.SessionState.LanguageMode
if ($langMode -ne 'FullLanguage') {
    Write-Warning "PowerShell is running in $langMode mode. The core checks should still work, but the Excel (.xlsx) step and -SkipCertCheck may be blocked; you will still get the CSV."
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

if ($SkipCertCheck) {
    Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class CxTrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
    [Net.ServicePointManager]::CertificatePolicy = New-Object CxTrustAllCerts
}

$BaseUrl = $BaseUrl.TrimEnd('/')
if ($BaseUrl -match '/cxwebclient$') { $BaseUrl = $BaseUrl -replace '/cxwebclient$', '' }

# --------------------------------------------------------------------------- #
# token
# --------------------------------------------------------------------------- #
if (-not $Token) {
    Write-Host "No login supplied." -ForegroundColor Yellow
    Write-Host "Copy the Cookie value (or a Bearer token) from Edge DevTools - run with -Help for steps - then press Enter here..."
    [void](Read-Host)
    $Token = Get-Clipboard -Raw
    try { Set-Clipboard -Value ' ' } catch { }   # don't leave the credential sitting on the clipboard
}
$cred = ("" + $Token).Trim().Trim('"')
$cred = $cred -replace '^\s*Cookie:\s*', ''
$cred = $cred -replace '[\r\n]+', ''

$script:AuthMode = $null
$script:CxToken  = $null
$script:CxCookie = $null
$script:CxCsrf   = $null

if ($cred -match '(^|;\s*)(ASP\.NET_SessionId|idsrv\.session|CXCSRFToken|\.AspNetCore\.)[^=]*=') {
    $script:AuthMode = 'cookie'
    $script:CxCookie = $cred
    if ($cred -match 'CXCSRFToken=([^;\s]+)') { $script:CxCsrf = $Matches[1] }
    else { Write-Warning "No CXCSRFToken found in the cookie - some calls may be refused. Copy the Cookie value from a 'Latest' request." }
    Write-Host "Login type: session cookie" -ForegroundColor Cyan
}
else {
    $t = ($cred -replace '^\s*(Authorization:\s*)?Bearer\s+', '').Trim()
    if ($t.Length -lt 200 -or $t -notmatch '^eyJ') {
        throw "That doesn't look like a Checkmarx Cookie value or bearer token. Run with -Help for how to copy it."
    }
    $script:AuthMode = 'bearer'
    $script:CxToken  = $t
    Write-Host "Login type: bearer token" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
function Invoke-Cx {
    param(
        [string]$Method = 'GET',
        [string]$Url,
        [hashtable]$Headers = @{},
        $Body = $null,
        [string]$ContentType = $null,
        [switch]$Raw,
        [string]$OutFile = $null
    )
    if ($script:AuthMode -eq 'cookie') {
        $h = @{ Cookie = $script:CxCookie; 'X-Requested-With' = 'XMLHttpRequest' }
        if ($script:CxCsrf) { $h['CXCSRFToken'] = $script:CxCsrf }
    } else {
        $h = @{ Authorization = "Bearer $script:CxToken" }
    }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }

    $rateWaits = 0
    for ($attempt = 1; $attempt -le 8; $attempt++) {
        if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
        try {
            $p = @{ Method = $Method; Uri = $Url; Headers = $h; UseBasicParsing = $true; TimeoutSec = 180 }
            if ($null -ne $Body)  { $p.Body = $Body }
            if ($ContentType)     { $p.ContentType = $ContentType }
            if ($OutFile) { Invoke-WebRequest @p -OutFile $OutFile; return }
            if ($Raw) {
                $resp = Invoke-WebRequest @p
                if ($resp.Content -match '<html' -and $resp.Content -notmatch 'soap:Envelope') {
                    throw (New-Object System.Exception 'LOGIN_PAGE')
                }
                return $resp
            }
            $out = Invoke-RestMethod @p
            if ($out -is [string] -and $out -match '<html') { throw (New-Object System.Exception 'LOGIN_PAGE') }
            return $out
        }
        catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -eq 401 -or $_.Exception.Message -eq 'LOGIN_PAGE') {
                throw "HTTP 401 - your login has expired or was not accepted. Log in again in Edge, copy a fresh value and re-run (see -Help). [failed call: $Method $Url]"
            }
            if ($code -eq 429) {
                # Checkmarx is throttling us (Too Many Requests). Back off politely:
                # wait as long as the server asks (or 30s, then longer), slow down
                # every later call, and give up after a few waits instead of hammering.
                $rateWaits++
                if ($rateWaits -gt 4) {
                    throw "RATE_LIMITED - Checkmarx kept refusing with HTTP 429 (too many requests) for $Url"
                }
                $wait = 30 * $rateWaits
                try {
                    $ra = $_.Exception.Response.Headers['Retry-After']
                    if ($ra -match '^\d+$' -and [int]$ra -gt $wait) { $wait = [int]$ra }
                } catch { }
                $script:DelayMs = [math]::Min([math]::Max($script:DelayMs * 2, 1000), 5000)
                Write-Host "   Checkmarx says 'too many requests' - waiting $wait s, then slowing down to one call every $($script:DelayMs) ms..." -ForegroundColor Yellow
                Start-Sleep -Seconds $wait
                continue
            }
            if ($attempt -lt 3 -and ($code -eq 0 -or $code -ge 500)) {
                Start-Sleep -Seconds ([math]::Pow(2, $attempt))
                continue
            }
            $e = New-Object System.Exception("HTTP $code from $Url : $($_.Exception.Message)")
            $e.Data['StatusCode'] = $code
            throw $e
        }
    }
}

function Get-CxRest  ([string]$Path) { Invoke-Cx -Url "$BaseUrl/cxrestapi$Path" -Headers @{ Accept = 'application/json;v=1.0' } }
function Get-CxOData ([string]$Path) { Invoke-Cx -Url "$BaseUrl/Cxwebinterface/odata/v1$Path" -Headers @{ Accept = 'application/json' } }

# --------------------------------------------------------------------------- #
# Checkmarx operations
# --------------------------------------------------------------------------- #
function Get-NumericProp($obj, [string[]]$PreferredNames, [string]$Pattern, [string]$ExcludePattern = '') {
    if ($null -eq $obj) { return $null }
    foreach ($n in $PreferredNames) {
        $prop = $obj.PSObject.Properties[$n]
        if ($prop -and $null -ne $prop.Value -and $prop.Value -is [ValueType] -and $prop.Value -isnot [bool]) {
            return [int]$prop.Value
        }
    }
    foreach ($prop in $obj.PSObject.Properties) {
        if ($prop.Name -match $Pattern -and (-not $ExcludePattern -or $prop.Name -notmatch $ExcludePattern) -and
            $null -ne $prop.Value -and $prop.Value -is [ValueType] -and $prop.Value -isnot [bool]) {
            return [int]$prop.Value
        }
    }
    return $null
}

$script:ODataScanCache = @{}
function Get-ODataScan([int]$ScanId) {
    if (-not $script:ODataScanCache.ContainsKey($ScanId)) {
        try   { $script:ODataScanCache[$ScanId] = Get-CxOData "/Scans($ScanId)" }
        catch { Write-Verbose "OData Scans($ScanId) failed: $_"; $script:ODataScanCache[$ScanId] = $null }
    }
    return $script:ODataScanCache[$ScanId]
}

function Get-LatestScan([int]$ProjectId) {
    $scans = @(Get-CxRest "/sast/scans?projectId=$ProjectId&scanStatus=Finished&last=1" | ForEach-Object { $_ })
    if ($scans.Count -eq 0) { return $null }
    return ($scans | Sort-Object { $_.dateAndTime.startedOn } -Descending | Select-Object -First 1)
}

$script:StatsCache = @{}
function Get-ScanStats([int]$ScanId) {
    if (-not $script:StatsCache.ContainsKey($ScanId)) {
        $script:StatsCache[$ScanId] = Get-CxRest "/sast/scans/$ScanId/resultsStatistics"
    }
    return $script:StatsCache[$ScanId]
}
function Get-StatTotal($st) {
    $t = 0
    foreach ($n in 'criticalSeverity', 'highSeverity', 'mediumSeverity', 'lowSeverity', 'infoSeverity') {
        if ($st.PSObject.Properties[$n] -and $null -ne $st.$n) { $t += [int]$st.$n }
    }
    return $t
}

$script:RiskNote = ''
function Get-ScanRiskScore($Scan) {
    # Risk Level Score = the number in brackets next to the coloured bar in the UI.
    # The REST scan object carries it as 'scanRisk'. Checkmarx returns -1 when it
    # did not calculate a score; the website then shows (0). In that case we check
    # the scan's result counts: no Critical/High/Medium results = score 0.
    $script:RiskNote = ''
    $names = @('scanRisk', 'riskScore', 'RiskScore', 'ScanRisk', 'riskLevelScore', 'RiskLevelScore')
    $v = Get-NumericProp $Scan $names 'risk' 'severity'
    if ($null -eq $v -or $v -ge 0) { return $v }

    try   { $st = Get-ScanStats $Scan.id }
    catch {
        if ("$_" -match 'HTTP 401') { throw }      # login expired - must not be mistaken for "no score"
        $script:RiskNote = "scanRisk=$v and result counts unavailable"; return $null
    }
    $crit = 0; if ($st.PSObject.Properties['criticalSeverity']) { $crit = [int]$st.criticalSeverity }
    $chm  = $crit + [int]$st.highSeverity + [int]$st.mediumSeverity
    if ($chm -eq 0) {
        $script:RiskNote = "Checkmarx did not calculate a risk score (scanRisk=$v); treated as 0 because there are no Critical/High/Medium results"
        return 0
    }
    $script:RiskNote = "Checkmarx did not calculate a risk score (scanRisk=$v); not 0 because there are $chm Critical/High/Medium results"
    return $v
}

function Test-ScanLocked($Scan) {
    foreach ($n in 'isLocked', 'IsLocked') {
        $prop = $Scan.PSObject.Properties[$n]
        if ($prop -and $null -ne $prop.Value) { return [bool]$prop.Value }
    }
    $o = Get-ODataScan $Scan.id
    if ($o -and $o.PSObject.Properties['IsLocked']) { return [bool]$o.IsLocked }
    return $null
}

function Lock-CxScan([int]$ScanId) {
    # 9.7 has no REST endpoint for locking - this is the portal SOAP service the UI uses.
    $soap = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <LockScan xmlns="http://Checkmarx.com">
      <i_SessionID></i_SessionID>
      <i_ScanID>$ScanId</i_ScanID>
    </LockScan>
  </soap:Body>
</soap:Envelope>
"@
    try {
        $r = Invoke-Cx -Method POST -Url "$BaseUrl/cxwebinterface/Portal/CxWebService.asmx" `
                       -Headers @{ SOAPAction = '"http://Checkmarx.com/LockScan"' } `
                       -Body $soap -ContentType 'text/xml; charset=utf-8' -Raw
    } catch { return @{ Ok = $false; Msg = "$_" } }

    if ($r.Content -match '<IsSuccesfull>\s*true\s*</IsSuccesfull>') { return @{ Ok = $true; Msg = 'Locked' } }
    $msg = 'LockScan returned false'
    if ($r.Content -match '<ErrorMessage>([^<]+)</ErrorMessage>') { $msg = $Matches[1] }
    return @{ Ok = $false; Msg = $msg }
}

function Get-ToVerifyResults([int]$ScanId) {
    # To Verify = result state 0 (same as the Result State = "To Verify" filter in
    # the viewer). The OData API needs extra permissions most users don't have, so
    # this asks Checkmarx for the scan's XML report - the same report you can
    # create from the website - and counts results with state="0" in it.
    $body = (@{ reportType = 'XML'; scanId = $ScanId } | ConvertTo-Json)
    $req  = Invoke-Cx -Method POST -Url "$BaseUrl/cxrestapi/reports/sastScan" `
                      -Headers @{ Accept = 'application/json;v=1.0' } `
                      -Body $body -ContentType 'application/json;v=1.0'
    $reportId = $req.reportId
    if (-not $reportId) { throw "Checkmarx did not return a report id for scan $ScanId" }

    $deadline = (Get-Date).AddMinutes($ReportTimeoutMinutes)
    do {
        Start-Sleep -Seconds 3
        $st = Get-CxRest "/reports/sastScan/$reportId/status"
        $state = "$($st.status.value)"
        if ($state -eq 'Failed') { throw "Checkmarx failed to create the XML report for scan $ScanId" }
        if ((Get-Date) -gt $deadline) { throw "XML report for scan $ScanId not ready after $ReportTimeoutMinutes min (try -ReportTimeoutMinutes 15)" }
    } while ($state -ne 'Created')

    $tmp = Join-Path $env:TEMP ("cx_scan_{0}_{1}.xml" -f $ScanId, $reportId)
    try {
        Invoke-Cx -Url "$BaseUrl/cxrestapi/reports/sastScan/$reportId" -Headers @{ Accept = '*/*' } -OutFile $tmp
        $text = Get-Content -Path $tmp -Raw -Encoding UTF8
        if ($text -match '<html' -and $text -notmatch '<CxXMLResults') { throw "HTTP 401 - your login has expired or was not accepted (report download returned the login page)." }
        [xml]$doc = $text
    } finally {
        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
    }

    $out = @()
    foreach ($q in @($doc.SelectNodes('//Query'))) {
        foreach ($r in @($q.SelectNodes("Result[@state='0']"))) {
            $sev = $r.GetAttribute('Severity')
            if (-not $sev) { $sev = $q.GetAttribute('Severity') }
            $out += [pscustomobject]@{ Severity = $sev; Query = $q.GetAttribute('name') }
        }
    }
    return ,$out
}

function ConvertTo-SeverityName($v) {
    if ($v -is [ValueType]) {
        switch ([int]$v) { 0 { return 'Information' } 1 { return 'Low' } 2 { return 'Medium' } 3 { return 'High' } 4 { return 'Critical' } default { return "$v" } }
    }
    $s = ("" + $v).Trim()
    if ($s -eq 'Info') { return 'Information' }
    if (-not $s) { return 'Unknown' }
    return $s
}

# --------------------------------------------------------------------------- #
# per project
# --------------------------------------------------------------------------- #
function Invoke-CxProject($Project) {
    $row = [ordered]@{
        'Project ID'        = $Project.id
        'Project Name'      = $Project.name
        'Latest Scan ID'    = ''
        'Risk Score'        = ''
        'Scan Date'         = ''
        'Was Locked'        = ''
        'Lock Action'       = ''
        'To Verify - Total' = 0
        'Critical'          = 0
        'High'              = 0
        'Medium'            = 0
        'Low'               = 0
        'Information'       = 0
        'Needs Triage'      = ''
        'Scan URL'          = ''
        'Note'              = ''
        'Error'             = ''
    }
    try {
        $scan = Get-LatestScan $Project.id
        if (-not $scan) {
            $row['Needs Triage'] = 'N/A'; $row['Error'] = 'No finished scan'
            return [pscustomobject]$row
        }
        $sid = [int]$scan.id
        $row['Latest Scan ID'] = $sid
        if ($scan.dateAndTime) { $row['Scan Date'] = $scan.dateAndTime.finishedOn }
        $row['Scan URL'] = "$BaseUrl/cxwebclient/ViewerMain.aspx?scanId=$sid"

        # ---- risk score gate: only score-0 projects are opened ------------- #
        $risk = Get-ScanRiskScore $scan
        $row['Risk Score'] = $risk
        $row['Note'] = $script:RiskNote
        if (-not $AnyRisk) {
            if ($null -eq $risk) {
                $row['Needs Triage'] = 'SKIPPED'; $row['Lock Action'] = 'Not touched'
                $row['Error'] = 'Risk score not found in API response - skipped'
                Write-Host "   risk score unavailable - skipped" -ForegroundColor Yellow
                return [pscustomobject]$row
            }
            if ($risk -ne $RiskScore) {
                $row['Needs Triage'] = 'SKIPPED'; $row['Lock Action'] = 'Not touched'
                Write-Host "   risk score $risk - skipped" -ForegroundColor DarkGray
                return [pscustomobject]$row
            }
        }

        # ---- lock ---------------------------------------------------------- #
        $locked = Test-ScanLocked $scan
        if ($null -eq $locked) { $row['Was Locked'] = 'Unknown' } elseif ($locked) { $row['Was Locked'] = 'Yes' } else { $row['Was Locked'] = 'No' }
        if ($locked -eq $true)  { $row['Lock Action'] = 'Already locked' }
        elseif ($DryRun)        { $row['Lock Action'] = 'Would lock (dry-run)' }
        else {
            $lr = Lock-CxScan $sid
            if ($lr.Ok) { $row['Lock Action'] = 'Locked' } else { $row['Lock Action'] = "Lock FAILED: $($lr.Msg)" }
        }

        # ---- to verify ----------------------------------------------------- #
        # A scan with zero results of any severity cannot have To Verify results,
        # so the (slow) XML report is only requested when there is something in it.
        $total = $null
        try { $total = Get-StatTotal (Get-ScanStats $sid) } catch { if ("$_" -match 'HTTP 401') { throw } }
        if ($total -eq 0) {
            $tv = @()
            if ($row['Note']) { $row['Note'] += '; ' }
            $row['Note'] += 'scan has no results - XML report not needed'
        } else {
            $tv = Get-ToVerifyResults $sid
        }
        $row['To Verify - Total'] = $tv.Count
        foreach ($r in $tv) {
            $sev = ConvertTo-SeverityName $r.Severity
            if ($row.Contains($sev)) { $row[$sev] = [int]$row[$sev] + 1 }
        }
        if ($tv.Count -gt 0) { $row['Needs Triage'] = 'YES' } else { $row['Needs Triage'] = 'NO' }

        $color = 'Green'; if ($tv.Count -gt 0) { $color = 'Red' }
        Write-Host ("   risk {0} | {1} | To Verify: {2}  (C:{3} H:{4} M:{5} L:{6} I:{7})" -f `
            $risk, $row['Lock Action'], $tv.Count, $row['Critical'], $row['High'], $row['Medium'], $row['Low'], $row['Information']) -ForegroundColor $color
    }
    catch {
        $row['Error'] = "$_"
        if (-not $row['Needs Triage']) { $row['Needs Triage'] = 'ERROR' }
        Write-Host "   ERROR: $_" -ForegroundColor Red
        if ("$_" -match 'HTTP 401') { $script:TokenExpired = $true }   # token gone - stop after this project
        if ("$_" -match 'RATE_LIMITED') { $script:RateLimited = $true } # server overloaded - stop, don't hammer it
    }
    return [pscustomobject]$row
}

# --------------------------------------------------------------------------- #
# Excel (optional - needs Microsoft Excel installed)
# --------------------------------------------------------------------------- #
function Convert-CsvToXlsx([string]$CsvPath, [string]$XlsxPath) {
    $xl = $null
    try { $xl = New-Object -ComObject Excel.Application }
    catch { Write-Host "Excel not available - CSV only (it opens in Excel anyway)."; return $false }
    try {
        $xl.Visible = $false; $xl.DisplayAlerts = $false
        $wb = $xl.Workbooks.Open($CsvPath)
        $ws = $wb.Worksheets.Item(1)
        $ws.Name = 'Triage Status'
        $used = $ws.UsedRange
        $rows = $used.Rows.Count; $cols = $used.Columns.Count

        $hdr = $ws.Range($ws.Cells.Item(1, 1), $ws.Cells.Item(1, $cols))
        $hdr.Font.Bold = $true
        $hdr.Font.Color = 0xFFFFFF
        $hdr.Interior.Color = 0x784E1F          # dark blue (Excel colours are BGR)

        $triageCol = 0
        for ($c = 1; $c -le $cols; $c++) { if ($ws.Cells.Item(1, $c).Text -eq 'Needs Triage') { $triageCol = $c } }
        if ($triageCol -gt 0) {
            for ($r = 2; $r -le $rows; $r++) {
                $cell = $ws.Cells.Item($r, $triageCol)
                switch ($cell.Text) {
                    'YES'     { $cell.Interior.Color = 0xCEC7FF }   # light red
                    'NO'      { $cell.Interior.Color = 0xCEEFC6 }   # light green
                    'SKIPPED' { $cell.Interior.Color = 0xD9D9D9 }   # grey
                    default   { $cell.Interior.Color = 0x9CEBFF }   # light yellow
                }
            }
        }
        [void]$used.AutoFilter()
        [void]$used.Columns.AutoFit()
        $wb.SaveAs($XlsxPath, 51)                # 51 = .xlsx
        $wb.Close($false)
        return $true
    }
    catch { Write-Warning "Excel formatting failed ($_). The CSV is still there."; return $false }
    finally {
        try { $xl.Quit() } catch { }
        try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($xl) } catch { }
    }
}

# --------------------------------------------------------------------------- #
# diagnose mode: show raw API answers for one project, change nothing
# --------------------------------------------------------------------------- #
function Invoke-CxDiagnose($Project) {
    $lines = New-Object System.Collections.ArrayList
    function Add-Line([string]$t) { [void]$lines.Add($t); Write-Host $t }

    Add-Line "=== DIAGNOSE: $($Project.name)  (project id $($Project.id)) ==="
    Add-Line "Login type: $script:AuthMode"

    $scan = $null
    try {
        $scan = Get-LatestScan $Project.id
        if ($scan) {
            Add-Line "`n--- [1] REST latest scan: OK ---"
            Add-Line ($scan | ConvertTo-Json -Depth 4)
        } else { Add-Line "`n--- [1] REST latest scan: OK but no finished scan returned ---" }
    } catch { Add-Line "`n--- [1] REST latest scan: FAILED ---`n$_" }

    if ($scan) {
        $sid = [int]$scan.id
        try {
            Add-Line "`n--- [2] To Verify via XML report: requesting (can take a minute) ---"
            $tv = Get-ToVerifyResults $sid
            Add-Line "--- [2] To Verify via XML report: OK, To Verify results = $($tv.Count) ---"
            if ($tv.Count -gt 0) { Add-Line ($tv | Group-Object Severity | ForEach-Object { "   $($_.Name): $($_.Count)" } | Out-String) }
        } catch { Add-Line "--- [2] To Verify via XML report: FAILED ---`n$_" }

        try {
            $st = Get-CxRest "/sast/scans/$sid/resultsStatistics"
            Add-Line "`n--- [3] REST results statistics: OK ---"
            Add-Line ($st | ConvertTo-Json -Depth 3)
        } catch { Add-Line "`n--- [3] REST results statistics: FAILED ---`n$_" }

        $rs = Get-ScanRiskScore $scan
        Add-Line "`nRisk score the script would use: $rs"
        if ($script:RiskNote) { Add-Line "   ($script:RiskNote)" }
        Add-Line "Locked right now: $(Test-ScanLocked $scan)"
    }

    $file = Join-Path (Resolve-Path $OutDir).Path ("cx_diagnose_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmm'))
    $lines | Out-File -FilePath $file -Encoding UTF8
    Write-Host "`nSaved to: $file" -ForegroundColor Cyan
    Write-Host "This file contains no login details. Send it (or paste its text) to whoever is helping you." -ForegroundColor Cyan
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
Write-Host "Checkmarx: $BaseUrl"
try {
    $me = Get-CxRest '/auth/MyProfile'
    Write-Host "Acting as: $($me.userName)" -ForegroundColor Cyan
} catch {
    if ("$_" -match 'HTTP 401') { throw }
    Write-Warning "Could not read profile ($_) - continuing."
}

$projects = @(Get-CxRest '/projects' | ForEach-Object { $_ } |
              Where-Object { -not $NameFilter -or $_.name -like "*$NameFilter*" } |
              Where-Object { -not $StartsWith -or $_.name -like "$StartsWith*" } |
              Sort-Object name)
if ($Limit -gt 0) { $projects = @($projects | Select-Object -First $Limit) }
if ($Diagnose -and $projects.Count -gt 0) { Invoke-CxDiagnose $projects[0]; return }
if ($projects.Count -eq 0) { Write-Warning "No projects matched (NameFilter '$NameFilter', StartsWith '$StartsWith')."; return }

if ($AnyRisk) { Write-Host "$($projects.Count) project(s) matched. Risk filter OFF." }
else          { Write-Host "$($projects.Count) project(s) matched. Only opening those with risk score $RiskScore." }
if ($DryRun)  { Write-Host "DRY RUN - nothing will be locked." -ForegroundColor Yellow }

$results = @()
$previous = @()
if ($Resume.Count -gt 0) {
    $done = @{}
    foreach ($f in $Resume) {
        if (-not (Test-Path $f)) { throw "Resume file not found: $f" }
        foreach ($r in (Import-Csv -Path $f)) {
            $finished = ($r.'Needs Triage' -in @('YES', 'NO', 'N/A')) -or
                        ($r.'Needs Triage' -eq 'SKIPPED' -and "$($r.'Risk Score')" -ne '')
            if ($finished) { $done["$($r.'Project ID')"] = $r }
        }
    }
    $previous = @($done.Values)
    $before = $projects.Count
    $projects = @($projects | Where-Object { -not $done.ContainsKey("$($_.id)") })
    Write-Host "Resume: $($before - $projects.Count) project(s) already done in earlier report(s), $($projects.Count) left." -ForegroundColor Cyan
}

$i = 0
foreach ($p in $projects) {
    $i++
    Write-Host ("({0}/{1}) {2}" -f $i, $projects.Count, $p.name)
    $results += Invoke-CxProject $p
    if ($script:TokenExpired) {
        Write-Warning "Login expired after $i of $($projects.Count) projects. Writing a partial report."
        break
    }
    if ($script:RateLimited) {
        Write-Warning "Checkmarx is rate-limiting this account after $i of $($projects.Count) projects. Stopping so we don't overload it - wait 10-15 minutes, then resume."
        break
    }
}

# ---- report ---------------------------------------------------------------- #
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$outFull = (Resolve-Path $OutDir).Path
$stamp   = Get-Date -Format 'yyyyMMdd_HHmm'
$csv     = Join-Path $outFull "cx_riskzero_toverify_$stamp.csv"
$xlsx    = Join-Path $outFull "cx_riskzero_toverify_$stamp.xlsx"

$order = @{ 'YES' = 0; 'ERROR' = 1; 'NO' = 2; 'N/A' = 3; 'SKIPPED' = 4 }
$columns = @('Project ID','Project Name','Latest Scan ID','Risk Score','Scan Date','Was Locked','Lock Action',
             'To Verify - Total','Critical','High','Medium','Low','Information','Needs Triage','Scan URL','Note','Error')
$all = @($previous | Select-Object $columns) + @($results | Select-Object $columns)
$results = $all
$sorted = $all | Sort-Object @{ Expression = { $order["$($_.'Needs Triage')"] } }, @{ Expression = { [int]("0" + $_.'To Verify - Total') }; Descending = $true }, 'Project Name'
$sorted | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV written: $csv" -ForegroundColor Cyan
if (Convert-CsvToXlsx $csv $xlsx) { Write-Host "Excel written: $xlsx" -ForegroundColor Cyan }

if ($script:TokenExpired -or $script:RateLimited) {
    $me2 = Split-Path -Leaf $PSCommandPath
    $flt = ''
    if ($StartsWith) { $flt += " -StartsWith $StartsWith" }
    if ($NameFilter) { $flt += " -NameFilter $NameFilter" }
    if ($DryRun)     { $flt += " -DryRun" }
    $wait = ''; if ($script:RateLimited) { $wait = 'wait 10-15 minutes, ' }
    Write-Host "`nTo carry on where it stopped: $($wait)copy a fresh token in Edge, then run:" -ForegroundColor Yellow
    Write-Host "   .\$me2$flt -Resume `"$csv`"" -ForegroundColor Yellow
}

# ---- console summary ------------------------------------------------------- #
$yes     = @($results | Where-Object { $_.'Needs Triage' -eq 'YES' })
$no      = @($results | Where-Object { $_.'Needs Triage' -eq 'NO' })
$skipped = @($results | Where-Object { $_.'Needs Triage' -eq 'SKIPPED' })
$errors  = @($results | Where-Object { $_.'Needs Triage' -eq 'ERROR' -or "$($_.'Lock Action')" -like 'Lock FAILED*' })

Write-Host ""
Write-Host ("=" * 70)
Write-Host "Projects checked (risk score $RiskScore): $($yes.Count + $no.Count)"
Write-Host "  HAVE To Verify results : $($yes.Count)" -ForegroundColor Red
Write-Host "  Nothing to mark        : $($no.Count)"  -ForegroundColor Green
Write-Host "  Skipped (other score)  : $($skipped.Count)"
Write-Host "  Errors / lock failures : $($errors.Count)" -ForegroundColor Yellow
if ($yes.Count -gt 0) {
    Write-Host "`nThere are results to mark in these projects:"
    foreach ($r in ($yes | Sort-Object { $_.'To Verify - Total' } -Descending)) {
        Write-Host ("  {0,5} To Verify  |  {1}" -f $r.'To Verify - Total', $r.'Project Name')
    }
}
Write-Host ("=" * 70)
