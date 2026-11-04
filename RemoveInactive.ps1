<#
.SYNOPSIS
    Marks and removes inactive projects (replaces the manual COUNTIF workflow).

.DESCRIPTION
    1. Reads file 1 (e.g. "177674 scans.csv") -> "Tracking ID" column,
       converts "177674:xxxx" -> "177674_xxxx".
    2. Reads file 2 (e.g. "ProjectState (19).csv") -> "Project Name" column,
       strips the trailing "_ICG" / "_EB" suffix.
    3. Marks every project Active / Inactive (same as the COUNTIF formula,
       case-insensitive).
    4. Writes:
         <name>_all.csv          - all projects + Status column
         <name>_active_only.csv  - inactive projects removed   <-- final result
         <name>_inactive.csv     - converted Tracking IDs + "Found in Project List"
       If the ImportExcel module is installed, also writes <name>_processed.xlsx
       with the three sheets: "All Projects", "Active Only", "Inactive".

    Works on Windows PowerShell 5.1 and PowerShell 7+. No Excel install needed.

.EXAMPLE
    .\Remove-Inactive.ps1 -InactiveFile "177674 scans.csv" -ProjectFile "ProjectState (19).csv"

.EXAMPLE
    .\Remove-Inactive.ps1 "177674 scans.csv" "ProjectState (19).csv" -Suffixes "_ICG","_EB","_XYZ"

.EXAMPLE
    # If scripts are blocked by execution policy:
    powershell -ExecutionPolicy Bypass -File .\Remove-Inactive.ps1 "177674 scans.csv" "ProjectState (19).csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$InactiveFile,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$ProjectFile,

    [string]$OutputDir,

    [string[]]$Suffixes = @('_ICG', '_EB'),

    [string]$TrackingColumn = 'Tracking ID',
    [string]$ProjectColumn  = 'Project Name',
    [string]$StatusColumn   = 'Status'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------ helpers -------
function Get-ColumnName {
    # Case- and space-insensitive header lookup with a clear error.
    param($Rows, [string]$Wanted, [string]$FileLabel)

    if (-not $Rows -or @($Rows).Count -eq 0) {
        throw "No data rows found in '$FileLabel'."
    }
    $headers = @($Rows)[0].PSObject.Properties.Name
    $match = $headers | Where-Object { $_.Trim() -ieq $Wanted.Trim() } | Select-Object -First 1
    if (-not $match) {
        throw "Column '$Wanted' not found in '$FileLabel'. Columns present: $($headers -join ', ')"
    }
    return $match
}

function Import-Table {
    param([string]$Path)
    $ext = [IO.Path]::GetExtension($Path).ToLower()
    if ($ext -in '.xlsx', '.xlsm', '.xls') {
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            throw "'$Path' is an Excel file. Save it as CSV, or run: Install-Module ImportExcel -Scope CurrentUser"
        }
        Import-Module ImportExcel
        return @(Import-Excel -Path $Path)
    }
    return @(Import-Csv -Path $Path)
}

# ------------------------------------------------------------ validate ------
foreach ($f in $InactiveFile, $ProjectFile) {
    if (-not (Test-Path -LiteralPath $f)) { throw "File not found: $f" }
}
$InactiveFile = (Resolve-Path -LiteralPath $InactiveFile).Path
$ProjectFile  = (Resolve-Path -LiteralPath $ProjectFile).Path

if (-not $OutputDir) { $OutputDir = Split-Path -Parent $ProjectFile }
if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
$baseName = [IO.Path]::GetFileNameWithoutExtension($ProjectFile)

# ------------------------------------------------- step 1: inactive list ----
$inactiveRows = Import-Table $InactiveFile
$tCol = Get-ColumnName $inactiveRows $TrackingColumn (Split-Path -Leaf $InactiveFile)

$inactiveNames = [System.Collections.Generic.List[string]]::new()
$inactiveSet   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

foreach ($row in $inactiveRows) {
    $id = [string]$row.$tCol
    if ([string]::IsNullOrWhiteSpace($id)) { continue }
    $name = $id.Trim().Replace(':', '_')          # 177674:xxx -> 177674_xxx
    if ($inactiveSet.Add($name)) { $inactiveNames.Add($name) }   # de-duplicate, keep order
}

# -------------------------------------------------- step 2: project list ----
$projects = Import-Table $ProjectFile
$pCol = Get-ColumnName $projects $ProjectColumn (Split-Path -Leaf $ProjectFile)

# Regex like  (?:_ICG|_EB)$   (case-insensitive by default in -replace)
$suffixPattern = '(?:' + (($Suffixes | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')$'

$projectSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

# ------------------------------------------- step 3: Active / Inactive -------
$allProjects = foreach ($row in $projects) {
    $clean = ([string]$row.$pCol).Trim() -replace $suffixPattern, ''
    $row.$pCol = $clean
    [void]$projectSet.Add($clean)

    $status = if ($inactiveSet.Contains($clean)) { 'Inactive' } else { 'Active' }
    # Add/overwrite the Status column
    $row | Add-Member -NotePropertyName $StatusColumn -NotePropertyValue $status -Force
    $row
}
$allProjects = @($allProjects)
$activeOnly  = @($allProjects | Where-Object { $_.$StatusColumn -eq 'Active' })

$inactiveReport = @(foreach ($n in $inactiveNames) {
    [pscustomobject]@{
        $TrackingColumn         = $n
        'Found in Project List' = if ($projectSet.Contains($n)) { 'Yes' } else { 'No' }
    }
})

# --------------------------------------------------------- step 4: output ---
$allCsv      = Join-Path $OutputDir "$($baseName)_all.csv"
$activeCsv   = Join-Path $OutputDir "$($baseName)_active_only.csv"
$inactiveCsv = Join-Path $OutputDir "$($baseName)_inactive.csv"

$allProjects    | Export-Csv -LiteralPath $allCsv      -NoTypeInformation -Encoding UTF8
$activeOnly     | Export-Csv -LiteralPath $activeCsv   -NoTypeInformation -Encoding UTF8
$inactiveReport | Export-Csv -LiteralPath $inactiveCsv -NoTypeInformation -Encoding UTF8

$written = @($allCsv, $activeCsv, $inactiveCsv)

if (Get-Module -ListAvailable -Name ImportExcel) {
    Import-Module ImportExcel
    $xlsx = Join-Path $OutputDir "$($baseName)_processed.xlsx"
    if (Test-Path -LiteralPath $xlsx) { Remove-Item -LiteralPath $xlsx }
    $allProjects    | Export-Excel -Path $xlsx -WorksheetName 'All Projects' -AutoSize -FreezeTopRow -BoldTopRow
    $activeOnly     | Export-Excel -Path $xlsx -WorksheetName 'Active Only'  -AutoSize -FreezeTopRow -BoldTopRow
    $inactiveReport | Export-Excel -Path $xlsx -WorksheetName 'Inactive'     -AutoSize -FreezeTopRow -BoldTopRow
    $written += $xlsx
}

# --------------------------------------------------------------- summary ----
$unmatched = @($inactiveReport | Where-Object { $_.'Found in Project List' -eq 'No' })

Write-Host ''
Write-Host ("Inactive IDs in file 1     : {0}" -f $inactiveNames.Count)
Write-Host ("Projects in file 2         : {0}" -f $allProjects.Count)
Write-Host ("Marked Inactive (removed)  : {0}" -f ($allProjects.Count - $activeOnly.Count)) -ForegroundColor Yellow
Write-Host ("Remaining Active           : {0}" -f $activeOnly.Count) -ForegroundColor Green
Write-Host ("Inactive IDs with no match : {0}" -f $unmatched.Count)
if ($unmatched.Count -gt 0) {
    $sample = ($unmatched | Select-Object -First 5 | ForEach-Object { $_.$TrackingColumn }) -join ', '
    Write-Host "  e.g. $sample" -ForegroundColor DarkYellow
    Write-Host "  -> check $([IO.Path]::GetFileName($inactiveCsv)); these didn't match any project." -ForegroundColor DarkYellow
}
Write-Host ''
$written | ForEach-Object { Write-Host "Wrote: $_" }
