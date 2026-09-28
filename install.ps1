$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host ""
Write-Host "======================================"
Write-Host "          VULPHEX Installer"
Write-Host "======================================"
Write-Host ""

# --------------------------------------------------
# Find a real system Python installation
# --------------------------------------------------

$PythonCandidates = @(
    "C:\Users\$env:USERNAME\AppData\Local\Programs\Python\Python313\python.exe",
    "C:\Program Files\Python313\python.exe"
)

$Python = $null

foreach ($Candidate in $PythonCandidates) {
    if (Test-Path $Candidate) {
        $Python = $Candidate
        break
    }
}

# Fall back to py launcher if available
if (-not $Python) {
    $PyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue

    if ($PyLauncher) {
        $Python = "py.exe"
    }
}

if (-not $Python) {
    Write-Host "Error: Python 3.13 or newer was not found."
    Write-Host ""
    Write-Host "Install Python 3.13 or newer and run this installer again."
    exit 1
}

# --------------------------------------------------
# Check Python version
# --------------------------------------------------

if ($Python -eq "py.exe") {
    $Version = & $Python -3.13 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
    $Major = & $Python -3.13 -c "import sys; print(sys.version_info.major)"
    $Minor = & $Python -3.13 -c "import sys; print(sys.version_info.minor)"
}
else {
    $Version = & $Python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
    $Major = & $Python -c "import sys; print(sys.version_info.major)"
    $Minor = & $Python -c "import sys; print(sys.version_info.minor)"
}

if (($Major -lt 3) -or (($Major -eq 3) -and ($Minor -lt 13))) {
    Write-Host "Error: VULPHEX requires Python 3.13 or newer."
    Write-Host "Detected Python: $Version"
    exit 1
}

Write-Host "[+] Python $Version detected."

# --------------------------------------------------
# Create private VULPHEX environment
# --------------------------------------------------

$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[+] Creating VULPHEX runtime..."

    if ($Python -eq "py.exe") {
        & $Python -3.13 -m venv ".venv"
    }
    else {
        & $Python -m venv ".venv"
    }
}
else {
    Write-Host "[+] VULPHEX runtime already exists."
}

# --------------------------------------------------
# Install VULPHEX
# --------------------------------------------------

Write-Host "[+] Preparing package installer..."

& $VenvPython -m pip install --upgrade pip setuptools wheel

Write-Host "[+] Installing VULPHEX dependencies..."

& $VenvPython -m pip install -r (Join-Path $ScriptDir "requirements.txt")

Write-Host "[+] Installing VULPHEX..."

& $VenvPython -m pip install .

# --------------------------------------------------
# Complete
# --------------------------------------------------

Write-Host ""
Write-Host "======================================"
Write-Host "       VULPHEX installation complete"
Write-Host "======================================"
Write-Host ""
Write-Host "Start VULPHEX with:"
Write-Host ""
Write-Host "    .\vulphex.ps1"
Write-Host ""
Write-Host "No Python environment activation is required."
Write-Host ""