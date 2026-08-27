param(
    [switch]$Installer
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "No se encontro .venv. Crea el entorno e instala las dependencias primero."
}

Push-Location $projectRoot
try {
    & $python -m PyInstaller --noconfirm --clean neural_compressor.spec
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller no pudo generar el ejecutable." }

    Write-Host "Ejecutable creado en: dist\CompresorArchivos.exe"
    if ($Installer) {
        $iscc = Get-Command iscc -ErrorAction SilentlyContinue
        if (-not $iscc) {
            throw "Inno Setup no esta instalado. Instala Inno Setup y vuelve a ejecutar: .\build_windows.ps1 -Installer"
        }
        & $iscc.Source "installer\CompresorArchivos.iss"
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup no pudo generar el instalador." }
        Write-Host "Instalador creado en: installer\output"
    }
}
finally {
    Pop-Location
}
