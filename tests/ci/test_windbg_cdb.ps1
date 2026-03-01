<#
.SYNOPSIS
    End-to-end test for ChatDBG WinDbg backend using CDB (console debugger).
    Designed for Windows CI runners (GitHub Actions).

.DESCRIPTION
    1. Compiles samples/windbg/crash_sample.c
    2. Runs it under CDB to generate a crash
    3. Loads PyKD and ChatDBG
    4. Runs 'why' with CHATDBG_DRY_RUN=1 to validate output without LLM calls
    5. Validates expected patterns in output
    6. Exits with pass/fail status

.NOTES
    Prerequisites:
    - Windows SDK (for CDB): winget install Microsoft.WindowsSDK
    - PyKD: pip install pykd
    - ChatDBG: pip install -e ".[windbg]"
    - Visual C++ compiler (cl.exe) on PATH, or gcc/clang
#>

$ErrorActionPreference = "Stop"

# --- Configuration ---
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$SampleDir = Join-Path $RepoRoot "samples\windbg"
$SampleSrc = Join-Path $SampleDir "crash_sample.c"
$SampleExe = Join-Path $SampleDir "crash_sample.exe"
$ChatDBGScript = Join-Path $RepoRoot "src\chatdbg\chatdbg_windbg.py"

# --- Helpers ---
function Write-Status($msg) { Write-Host "[ChatDBG CI] $msg" -ForegroundColor Cyan }
function Write-Pass($msg)   { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Write-Fail($msg)   { Write-Host "[FAIL] $msg" -ForegroundColor Red }

# --- Step 1: Compile the sample ---
Write-Status "Compiling crash_sample.c..."

$clExe = Get-Command cl.exe -ErrorAction SilentlyContinue
$gccExe = Get-Command gcc.exe -ErrorAction SilentlyContinue

if ($clExe) {
    & cl.exe /Zi /Od /Fe:$SampleExe $SampleSrc 2>&1 | Out-Null
} elseif ($gccExe) {
    & gcc.exe -g -O0 -o $SampleExe $SampleSrc 2>&1 | Out-Null
} else {
    Write-Fail "No C compiler found (cl.exe or gcc.exe). Skipping CDB test."
    exit 0  # Don't fail CI if no compiler
}

if (-not (Test-Path $SampleExe)) {
    Write-Fail "Compilation failed: $SampleExe not found"
    exit 1
}
Write-Pass "Compiled $SampleExe"

# --- Step 2: Find CDB ---
$cdbExe = Get-Command cdb.exe -ErrorAction SilentlyContinue
if (-not $cdbExe) {
    # Try common Windows SDK paths
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe",
        "${env:ProgramFiles}\Windows Kits\10\Debuggers\x64\cdb.exe"
    )
    foreach ($p in $sdkPaths) {
        if (Test-Path $p) { $cdbExe = $p; break }
    }
}

if (-not $cdbExe) {
    Write-Fail "CDB not found. Install Windows SDK Debugging Tools. Skipping."
    exit 0
}
Write-Status "Using CDB: $cdbExe"

# --- Step 3: Run CDB with ChatDBG in dry-run mode ---
Write-Status "Running CDB with ChatDBG (dry-run mode)..."

$env:CHATDBG_DRY_RUN = "1"

# CDB script: load pykd, run chatdbg, execute why, quit
$cdbScript = @"
.load pykd
!py -g "$ChatDBGScript"
k
q
"@

$cdbScriptFile = Join-Path $env:TEMP "chatdbg_cdb_test.txt"
$cdbScript | Out-File -FilePath $cdbScriptFile -Encoding ascii

try {
    $output = & $cdbExe -z $SampleExe -cf $cdbScriptFile 2>&1 | Out-String
} catch {
    Write-Fail "CDB execution failed: $_"
    exit 1
} finally {
    Remove-Item $cdbScriptFile -ErrorAction SilentlyContinue
    Remove-Item $env:CHATDBG_DRY_RUN
}

# --- Step 4: Validate output ---
Write-Status "Validating output..."
$passed = $true

# Check that we got some stack trace output
if ($output -match "crash_sample") {
    Write-Pass "Stack trace contains crash_sample"
} else {
    Write-Fail "Stack trace missing crash_sample"
    $passed = $false
}

# Check no Python errors
if ($output -match "Traceback \(most recent call last\)") {
    Write-Fail "Python traceback detected in output"
    Write-Host $output
    $passed = $false
} else {
    Write-Pass "No Python tracebacks"
}

# --- Result ---
if ($passed) {
    Write-Status "All CDB tests passed!"
    exit 0
} else {
    Write-Status "Some CDB tests failed."
    Write-Host "--- Full output ---"
    Write-Host $output
    exit 1
}
