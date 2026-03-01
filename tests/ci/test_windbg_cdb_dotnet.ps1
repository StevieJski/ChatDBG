<#
.SYNOPSIS
    End-to-end test for ChatDBG WinDbg backend with .NET/SOS using CDB.
    Designed for Windows CI runners (GitHub Actions).

.DESCRIPTION
    1. Checks for dotnet CLI and CDB — skips gracefully if either missing
    2. Builds samples/windbg/dotnet/ with dotnet build -c Debug
    3. Runs the built exe under CDB with CHATDBG_DRY_RUN=1
    4. Validates output contains CLR-related patterns and no Python tracebacks

.NOTES
    Prerequisites:
    - .NET 8 SDK: winget install Microsoft.DotNet.SDK.8
    - Windows SDK (for CDB): winget install Microsoft.WindowsSDK
    - PyKD: pip install pykd
    - ChatDBG: pip install -e ".[windbg]"
#>

$ErrorActionPreference = "Stop"

# --- Configuration ---
$RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$SampleDir = Join-Path $RepoRoot "samples\windbg\dotnet"
$ChatDBGScript = Join-Path $RepoRoot "src\chatdbg\chatdbg_windbg.py"

# --- Helpers ---
function Write-Status($msg) { Write-Host "[ChatDBG CI .NET] $msg" -ForegroundColor Cyan }
function Write-Pass($msg)   { Write-Host "[PASS] $msg" -ForegroundColor Green }
function Write-Fail($msg)   { Write-Host "[FAIL] $msg" -ForegroundColor Red }

# --- Step 1: Check prerequisites ---
$dotnetExe = Get-Command dotnet.exe -ErrorAction SilentlyContinue
if (-not $dotnetExe) {
    Write-Fail "dotnet CLI not found. Install .NET 8 SDK. Skipping."
    exit 0  # Don't fail CI if no .NET SDK
}
Write-Status "Using dotnet: $($dotnetExe.Source)"

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

# --- Step 2: Build the .NET sample ---
Write-Status "Building .NET sample project..."

try {
    & dotnet.exe build $SampleDir -c Debug 2>&1 | Out-Null
} catch {
    Write-Fail "dotnet build failed: $_"
    exit 1
}

# Find the built executable
$SampleExe = Join-Path $SampleDir "bin\Debug\net8.0\DotnetCrashSample.exe"
if (-not (Test-Path $SampleExe)) {
    Write-Fail "Build succeeded but $SampleExe not found"
    exit 1
}
Write-Pass "Built $SampleExe"

# --- Step 3: Run CDB with ChatDBG in dry-run mode ---
Write-Status "Running CDB with ChatDBG (dry-run mode)..."

$env:CHATDBG_DRY_RUN = "1"

# CDB script: load pykd, run chatdbg, show stack, quit
$cdbScript = @"
.load pykd
!py -g "$ChatDBGScript"
k
q
"@

$cdbScriptFile = Join-Path $env:TEMP "chatdbg_cdb_dotnet_test.txt"
$cdbScript | Out-File -FilePath $cdbScriptFile -Encoding ascii

try {
    $output = & $cdbExe $SampleExe "nullref" -cf $cdbScriptFile 2>&1 | Out-String
} catch {
    Write-Fail "CDB execution failed: $_"
    exit 1
} finally {
    Remove-Item $cdbScriptFile -ErrorAction SilentlyContinue
    Remove-Item env:CHATDBG_DRY_RUN -ErrorAction SilentlyContinue
}

# --- Step 4: Validate output ---
Write-Status "Validating output..."
$passed = $true

# Check for CLR-related module
if ($output -match "coreclr") {
    Write-Pass "Output contains coreclr module reference"
} else {
    Write-Fail "Output missing coreclr module reference"
    $passed = $false
}

# Check for sample namespace in stack trace
if ($output -match "DotnetCrash") {
    Write-Pass "Stack trace contains DotnetCrash namespace"
} else {
    Write-Fail "Stack trace missing DotnetCrash namespace"
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
    Write-Status "All CDB .NET tests passed!"
    exit 0
} else {
    Write-Status "Some CDB .NET tests failed."
    Write-Host "--- Full output ---"
    Write-Host $output
    exit 1
}
