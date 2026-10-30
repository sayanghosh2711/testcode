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
    [int]   $RiskScore  = 0,         # only open projects whose latest scan has this score
    [switch]$AnyRisk,                # ignore the risk score and open every project
    [int]   $Limit      = 0,         # only process the first N projects (testing)
    [switch]$DryRun,                 # report only, never lock anything
    [string]$Token      = $env:CX_TOKEN,
    [string]$OutDir     = ".",
    [switch]$SkipCertCheck,          # only if you get SSL/TLS trust errors
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$script:TokenExpired = $false

$HelpText = @"

HOW TO GET THE TOKEN (SSO users)
--------------------------------
1. Log in to Checkmarx in Edge as usual.
2. Press F12 -> Network tab -> tick "Preserve log".
3. Click around Checkmarx (e.g. Projects & Scans) until requests with
   'cxrestapi' in the name appear.
4. Click one -> Headers -> Request Headers -> find
       Authorization: Bearer eyJhbGciOi...
   Right-click the value -> Copy value  (it is very long - copy all of it).
   If there is no Authorization header, use Application -> Session storage ->
   key starting 'oidc.user:' and copy the access_token value instead.
5. Run this script. When it asks, make sure the token is on your clipboard and
   press Enter. The script reads it from the clipboard, then clears the clipboard.

The token lasts about an hour and carries YOUR permissions. Treat it like a
password: do not paste it into chats, tickets or files.

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
    Write-Host "No token supplied." -ForegroundColor Yellow
    Write-Host "Copy the bearer token from Edge DevTools (run with -Help for steps), then press Enter here..."
    [void](Read-Host)
    $Token = Get-Clipboard -Raw
    try { Set-Clipboard -Value ' ' } catch { }   # don't leave the token sitting on the clipboard
}
$Token = ("" + $Token) -replace '^\s*(Authorization:\s*)?Bearer\s+', ''
$Token = $Token.Trim().Trim('"')
if ($Token.Length -lt 200 -or $Token -notmatch '^eyJ') {
    throw "That does not look like a Checkmarx bearer token (expected a long string starting with 'eyJ'). Run with -Help."
}
$script:CxToken = $Token

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
        [switch]$Raw
    )
    $h = @{ Authorization = "Bearer $script:CxToken" }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $p = @{ Method = $Method; Uri = $Url; Headers = $h; UseBasicParsing = $true; TimeoutSec = 180 }
            if ($null -ne $Body)  { $p.Body = $Body }
            if ($ContentType)     { $p.ContentType = $ContentType }
            if ($Raw) { return Invoke-WebRequest @p }
            return Invoke-RestMethod @p
        }
        catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code -eq 401) {
                throw "HTTP 401 - the token has expired or is invalid. Copy a fresh one from the browser and re-run (see -Help)."
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

function Get-ScanRiskScore($Scan) {
    # Risk Level Score = the number in brackets next to the coloured bar in the UI.
    $names = @('scanRisk', 'riskScore', 'RiskScore', 'ScanRisk', 'riskLevelScore', 'RiskLevelScore')
    $v = Get-NumericProp $Scan $names 'risk' 'severity'
    if ($null -ne $v) { return $v }
    return (Get-NumericProp (Get-ODataScan $Scan.id) $names 'risk' 'severity')
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
      <sessionID></sessionID>
      <scanId>$ScanId</scanId>
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

$script:StateField = $null   # discovered on first use: 'StateId' or 'State'
function Get-ToVerifyResults([int]$ScanId) {
    # To Verify = result state 0 (same as the Result State = "To Verify" filter in the viewer).
    $fields = @('StateId', 'State')
    if ($script:StateField) { $fields = @($script:StateField) }
    $lastErr = $null
    foreach ($f in $fields) {
        try {
            $all = @(); $skip = 0; $page = 1000
            do {
                $resp = Get-CxOData "/Scans($ScanId)/Results?`$filter=$f%20eq%200&`$select=Id,Severity&`$top=$page&`$skip=$skip"
                $vals = @($resp.value)
                $all += $vals
                $skip += $page
            } while ($vals.Count -eq $page)
            $script:StateField = $f
            return ,$all
        } catch {
            $lastErr = $_
            if ($_.Exception.Data['StatusCode'] -ne 400) { throw }
        }
    }
    throw "Could not query To Verify results: $lastErr"
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
        $tv = Get-ToVerifyResults $sid
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
              Sort-Object name)
if ($Limit -gt 0) { $projects = @($projects | Select-Object -First $Limit) }
if ($projects.Count -eq 0) { Write-Warning "No projects matched '$NameFilter'."; return }

if ($AnyRisk) { Write-Host "$($projects.Count) project(s) matched. Risk filter OFF." }
else          { Write-Host "$($projects.Count) project(s) matched. Only opening those with risk score $RiskScore." }
if ($DryRun)  { Write-Host "DRY RUN - nothing will be locked." -ForegroundColor Yellow }

$results = @()
$i = 0
foreach ($p in $projects) {
    $i++
    Write-Host ("({0}/{1}) {2}" -f $i, $projects.Count, $p.name)
    $results += Invoke-CxProject $p
    if ($script:TokenExpired) {
        Write-Warning "Token expired after $i of $($projects.Count) projects. Writing a partial report - copy a fresh token and re-run (use -NameFilter to target the rest)."
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
$sorted = $results | Sort-Object @{ Expression = { $order["$($_.'Needs Triage')"] } }, @{ Expression = { $_.'To Verify - Total' }; Descending = $true }, 'Project Name'
$sorted | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-Host "`nCSV written: $csv" -ForegroundColor Cyan
if (Convert-CsvToXlsx $csv $xlsx) { Write-Host "Excel written: $xlsx" -ForegroundColor Cyan }

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
