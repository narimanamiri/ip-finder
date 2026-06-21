<#
build.ps1 -- build standalone Windows executables for the ip-finder toolkit.

Usage:
    .\build.ps1                # build every tool into dist\windows\
    .\build.ps1 -OneDir        # build folder bundles instead of single files

Requires PyInstaller in the active Python:
    pip install -r requirements.txt pyinstaller
#>
param(
    [switch]$OneDir
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# Prefer the project venv if present, otherwise fall back to PATH python.
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$dist = Join-Path $root "dist\windows"
$work = Join-Path $root "build\windows"
$mode = if ($OneDir) { "--onedir" } else { "--onefile" }

# name, script, windowed(GUI -> no console)
$targets = @(
    @{ name = "finder";            script = "finder.py";            windowed = $false },
    @{ name = "scan-devices";      script = "scan-devices.py";      windowed = $false },
    @{ name = "scannet-fast";      script = "scannet-fast.py";      windowed = $false },
    @{ name = "scannet-fastV2";    script = "scannet-fastV2.py";    windowed = $false },
    @{ name = "passive-finder";    script = "passive-finder.py";    windowed = $false },
    @{ name = "oui-lookup";        script = "oui_lookup.py";        windowed = $false },
    @{ name = "lan-multitool-gui"; script = "lan_multitool_gui.py"; windowed = $true  }
)

Write-Host "Python : $py"
Write-Host "Output : $dist`n"

foreach ($t in $targets) {
    Write-Host "==> Building $($t.name) ($($t.script))"
    $pyiArgs = @(
        "-m", "PyInstaller", "--noconfirm", "--clean", $mode,
        "--name", $t.name,
        "--distpath", $dist,
        "--workpath", $work,
        "--specpath", $work
    )
    if ($t.windowed) { $pyiArgs += "--windowed" } else { $pyiArgs += "--console" }
    $pyiArgs += $t.script
    & $py @pyiArgs
    if ($LASTEXITCODE -ne 0) { throw "Build failed for $($t.name)" }
}

Write-Host "`nDone. Executables are in $dist"
Get-ChildItem $dist
