# make-package.ps1 - assemble a versioned ZIP of the Windows installer.
#
# Run on a host that has just built edr.sys (kernel-windows) and
# edr-agent.exe (cargo build -p agent-windows --release). Drops the ZIP
# under target\windows-package\.

[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    [string]$Repo
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if (-not $Repo) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not $here) { $here = Split-Path -Parent (Get-Location).Path }
    $Repo = (Resolve-Path (Join-Path $here '..\..')).Path
}
$here = Join-Path $Repo 'packaging\windows'

$out = Join-Path $Repo "target\windows-package"
$staging = Join-Path $out "edr-windows-$Version"
$zip = Join-Path $out "edr-windows-$Version.zip"

if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
if (Test-Path $zip) { Remove-Item -Force $zip }
New-Item -Path $staging -ItemType Directory -Force | Out-Null

# Required artefacts.
$agent  = Join-Path $Repo 'target\release\edr-agent.exe'
$driver = Join-Path $Repo 'kernel-windows\edr.sys'
$missing = @()
if (-not (Test-Path $agent))  { $missing += $agent }
if (-not (Test-Path $driver)) { $missing += $driver }
if ($missing.Count) { throw "missing artefacts: $($missing -join ', ')" }

Copy-Item $agent  (Join-Path $staging 'edr-agent.exe')
Copy-Item $driver (Join-Path $staging 'edr.sys')

# PS scripts + docs.
Copy-Item (Join-Path $here 'install-edr.ps1')   $staging
Copy-Item (Join-Path $here 'uninstall-edr.ps1') $staging
Copy-Item (Join-Path $here 'README.md')         $staging
Copy-Item (Join-Path $here 'agent.env.example') $staging

# Optional: bundled test cert.
$cer = 'C:\toolchain\edr-cert.cer'
if (Test-Path $cer) {
    Copy-Item $cer (Join-Path $staging 'edr-cert.cer')
} else {
    Write-Host "  no test cert at $cer; ZIP will rely on a system-trusted production cert." -ForegroundColor Yellow
}

Compress-Archive -Path $staging -DestinationPath $zip -Force
Write-Host "wrote: $zip"
Write-Host ("  size: " + ((Get-Item $zip).Length / 1KB) + " KB")
