$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VulphexPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $VulphexPython)) {
    Write-Host ""
    Write-Host "VULPHEX runtime is not installed."
    Write-Host ""
    Write-Host "Run the VULPHEX installer first:"
    Write-Host ""
    Write-Host "    .\install.ps1"
    Write-Host ""
    exit 1
}

& $VulphexPython -m vulphex @args
exit $LASTEXITCODE