param(
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot

try {
    $venvPath = Join-Path $PSScriptRoot ".venv"
    $pythonPath = Join-Path $venvPath "Scripts\python.exe"
    $activatePath = Join-Path $venvPath "Scripts\Activate.ps1"

    if (-not (Test-Path $pythonPath)) {
        Write-Host "Creating virtual environment at .venv..."
        python -m venv $venvPath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create .venv. Confirm Python is installed and available as 'python'."
        }
    }

    . $activatePath
    Write-Host "Using Python: $(Get-Command python | Select-Object -ExpandProperty Source)"

    if (-not $SkipInstall) {
        Write-Host "Installing requirements..."
        python -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            throw "Dependency installation failed. See pip output above."
        }
    }

    Write-Host "Starting NetGuard-Agent dashboard..."
    python -m streamlit run src\netguard\dashboard.py
    if ($LASTEXITCODE -ne 0) {
        throw "Streamlit dashboard exited with an error. See output above."
    }
}
finally {
    Pop-Location
}
