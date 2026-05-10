# uninstall-vigil.ps1 - reverses install-vigil.ps1.
#
# Run elevated. Stops + unregisters the agent task and the driver service,
# removes %ProgramFiles%\Vigil\, and (with -Purge) the state at
# %ProgramData%\Vigil\. The test cert is left in the trust stores by default;
# pass -RemoveCert to clear it too.

[CmdletBinding()]
param(
    [switch]$Purge,        # also remove %ProgramData%\Vigil (state, identity, spool)
    [switch]$RemoveCert    # also remove the bundled test cert from trust stores
)

$ErrorActionPreference = 'Continue'  # keep going past missing-component errors
Set-StrictMode -Version 3.0

$AgentTaskName = 'VigilAgent'
$DriverServiceName = 'edr'
$ProductName = 'EDR'
$InstallDir = Join-Path $env:ProgramFiles $ProductName
$DataDir = Join-Path $env:ProgramData $ProductName
$DriverTarget = Join-Path $env:windir 'system32\drivers\vigil.sys'

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "uninstall-vigil.ps1 must be run as Administrator."
    }
}

Assert-Admin
Write-Host "EDR uninstall starting..."

# Stop + delete the scheduled task (and stop any running instance).
Write-Host "[1/4] Stopping agent task..."
$proc = Get-Process vigil-agent -EA SilentlyContinue
if ($proc) {
    # The task runs as SYSTEM via /RL HIGHEST; the M7.2 ObCallback strips
    # PROCESS_TERMINATE from non-self user-mode handles, but the Task
    # Scheduler itself uses kernel-mode handles which pass through. End
    # the task, then poll for exit.
    & schtasks.exe /End /TN $AgentTaskName 2>&1 | Out-Null
    for ($i = 0; $i -lt 10 -and (Get-Process vigil-agent -EA SilentlyContinue); $i++) {
        Start-Sleep -Milliseconds 500
    }
    if (Get-Process vigil-agent -EA SilentlyContinue) {
        Write-Host "  agent still running after 5s; will continue but inspect manually" -ForegroundColor Yellow
    }
}
& schtasks.exe /Delete /TN $AgentTaskName /F 2>&1 | Out-Null

# Stop + delete the driver service.
Write-Host "[2/4] Stopping driver..."
& sc.exe stop $DriverServiceName 2>&1 | Out-Null
Start-Sleep -Seconds 1
& sc.exe delete $DriverServiceName 2>&1 | Out-Null
if (Test-Path $DriverTarget) { Remove-Item -Force $DriverTarget }

# Remove the install dir.
Write-Host "[3/4] Removing $InstallDir..."
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }

# Optional: clear state.
Write-Host "[4/4] State + cert..."
if ($Purge) {
    if (Test-Path $DataDir) {
        Remove-Item -Recurse -Force $DataDir
        Write-Host "  removed $DataDir (purge)"
    }
} else {
    Write-Host "  $DataDir kept (use -Purge to remove)"
}

if ($RemoveCert) {
    # Best-effort: the cert subject is hard-coded in the build cert, so we
    # match by subject name.
    foreach ($store in 'Root','TrustedPublisher') {
        $found = Get-ChildItem "Cert:\LocalMachine\$store" -EA SilentlyContinue | Where-Object { $_.Subject -match 'EDR' }
        foreach ($c in $found) {
            $c | Remove-Item
            Write-Host ("  removed cert: " + $c.Thumbprint + " from " + $store)
        }
    }
} else {
    Write-Host "  test certs kept in trust stores (use -RemoveCert to clear)"
}

Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
