# install-edr.ps1 - top-level installer for the EDR agent + driver on Windows.
#
# Run elevated. Idempotent: re-running over an existing install reuses
# enrollment + state, only refreshing binaries.
#
# What this does:
#   1. Pre-flight: admin check, OS version, testsigning hint.
#   2. Install the test cert into LocalMachine\Root + TrustedPublisher.
#      (Skipped if a system-trusted production cert was used to sign edr.sys.)
#   3. Copy edr.sys to %windir%\system32\drivers and register the driver
#      service via SCM (file system filter, demand start).
#   4. Copy edr-agent.exe to %ProgramFiles%\EDR\.
#   5. Stage %ProgramData%\EDR\ (state dir) with mode-restricted ACL.
#   6. Stage agent.env from agent.env.example unless one already exists.
#   7. Register a scheduled task "EDRAgent" that runs at startup as SYSTEM
#      with auto-restart on failure. (A real Windows service would be
#      cleaner; documented as future polish in packaging/windows/README.md.)
#
# What this does NOT do:
#   - Auto-start the agent. The operator must edit %ProgramData%\EDR\agent.env
#     to set EDR_MANAGER_ENDPOINT and EDR_ENROLLMENT_TOKEN, then run
#     `Start-ScheduledTask -TaskName EDRAgent` (or reboot).
#   - Sign the MSI. There's no MSI here yet (M7.4 ships a ZIP-based
#     installer; WiX MSI is documented as future polish).

[CmdletBinding()]
param(
    [switch]$NoInstallCert,        # skip cert install (production cert assumed trusted)
    [switch]$AutoStart             # also start the task immediately (requires agent.env to be configured)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProductName = 'EDR'
$AgentTaskName = 'EDRAgent'
$DriverServiceName = 'edr'
$DriverAltitude = '385100'
$InstallDir = Join-Path $env:ProgramFiles $ProductName
$DataDir = Join-Path $env:ProgramData $ProductName
$DriverTarget = Join-Path $env:windir 'system32\drivers\edr.sys'

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "install-edr.ps1 must be run as Administrator. Right-click PowerShell -> Run as administrator."
    }
}

function Get-TestSigningState {
    $out = & bcdedit /enum '{current}' 2>&1
    if ($out -match 'testsigning\s+Yes') { return 'on' }
    if ($out -match 'testsigning\s+No') { return 'off' }
    return 'unknown'
}

function Install-TestCert {
    $cer = Join-Path $here 'edr-cert.cer'
    if (-not (Test-Path $cer)) {
        Write-Host "  cert not bundled at $cer; skipping cert install" -ForegroundColor Yellow
        return
    }
    foreach ($store in 'Root','TrustedPublisher') {
        & certutil.exe -addstore -f $store $cer | Out-Null
        Write-Host "  cert installed: LocalMachine\$store"
    }
}

function Install-Driver {
    $src = Join-Path $here 'edr.sys'
    if (-not (Test-Path $src)) { throw "edr.sys not found at $src" }
    Copy-Item -Force $src $DriverTarget
    Write-Host "  copied -> $DriverTarget"

    # Idempotent: only create the service if missing.
    & sc.exe query $DriverServiceName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        & sc.exe create $DriverServiceName type= filesys start= demand error= normal `
            binPath= $DriverTarget depend= FltMgr group= "FSFilter Activity Monitor" | Out-Host
        & sc.exe description $DriverServiceName "EDR endpoint kernel driver" | Out-Host
    } else {
        Write-Host "  driver service already registered"
    }

    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverServiceName"
    $defKey  = "$svcKey\Instances\EDR Default"
    New-Item -Path "$svcKey\Instances" -Force | Out-Null
    Set-ItemProperty -Path "$svcKey\Instances" -Name 'DefaultInstance' -Value 'EDR Default'
    New-Item -Path $defKey -Force | Out-Null
    Set-ItemProperty -Path $defKey -Name 'Altitude' -Value $DriverAltitude
    Set-ItemProperty -Path $defKey -Name 'Flags' -Type DWord -Value 0x0
}

function Install-Agent {
    if (-not (Test-Path $InstallDir)) { New-Item -Path $InstallDir -ItemType Directory | Out-Null }
    $src = Join-Path $here 'edr-agent.exe'
    if (-not (Test-Path $src)) { throw "edr-agent.exe not found at $src" }
    Copy-Item -Force $src (Join-Path $InstallDir 'edr-agent.exe')
    Write-Host "  copied -> $InstallDir\edr-agent.exe"
}

function Stage-DataDir {
    if (-not (Test-Path $DataDir)) { New-Item -Path $DataDir -ItemType Directory | Out-Null }
    foreach ($sub in 'identity','spool') {
        $p = Join-Path $DataDir $sub
        if (-not (Test-Path $p)) { New-Item -Path $p -ItemType Directory | Out-Null }
    }
    # Restrict to SYSTEM + Administrators. Identity material lives here.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)  # disable inheritance, drop existing
    $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $admRule = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($sysRule)
    $acl.AddAccessRule($admRule)
    Set-Acl -Path $DataDir -AclObject $acl
    Write-Host "  staged $DataDir (SYSTEM + Admins only)"

    $envFile = Join-Path $DataDir 'agent.env'
    if (-not (Test-Path $envFile)) {
        $template = Join-Path $here 'agent.env.example'
        if (Test-Path $template) {
            Copy-Item -Force $template $envFile
            Write-Host "  staged $envFile from template"
        }
    } else {
        Write-Host "  $envFile already present (kept)"
    }
}

function Register-AgentTask {
    # Reuse: delete existing task to refresh the binPath. schtasks emits
    # to stderr when the task isn't found, which under our ErrorActionPreference
    # would terminate the script - swallow output and ignore the exit code.
    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & schtasks.exe /Delete /TN $AgentTaskName /F 2>&1 | Out-Null
    $ErrorActionPreference = $oldEAP

    $exe = Join-Path $InstallDir 'edr-agent.exe'
    $envFile = Join-Path $DataDir 'agent.env'
    # PowerShell launcher: parses agent.env (KEY=VALUE, # comments OK,
    # blank lines OK) into the process environment, then execs the agent
    # binary. We use a .ps1 launcher rather than .cmd because batch's
    # variable scoping and quoting around paths-with-spaces are too
    # fragile to reproduce reliably across Windows versions.
    $launcher = Join-Path $InstallDir 'edr-agent-launcher.ps1'
    $launcherScript = @"
`$ErrorActionPreference = 'Continue'
`$envFile = '$envFile'
`$exe = '$exe'
if (Test-Path `$envFile) {
    Get-Content `$envFile | ForEach-Object {
        `$line = `$_.Trim()
        if (-not `$line) { return }
        if (`$line.StartsWith('#')) { return }
        `$idx = `$line.IndexOf('=')
        if (`$idx -lt 1) { return }
        `$k = `$line.Substring(0, `$idx).Trim()
        `$v = `$line.Substring(`$idx + 1).Trim()
        [Environment]::SetEnvironmentVariable(`$k, `$v, 'Process')
    }
}
& `$exe
"@
    Set-Content -Path $launcher -Value $launcherScript -Encoding ASCII

    # schtasks /TR doesn't tolerate spaces in argument strings even when
    # quoted (the parser splits on the first space and treats the rest
    # as separate switches). Use the XML import path instead, which lets
    # us specify Command + Arguments cleanly. Path-with-space (`Program
    # Files`) is therefore safe.
    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-NoProfile -ExecutionPolicy Bypass -File "$launcher"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
    $xmlPath = Join-Path $env:TEMP "edr-agent-task.xml"
    # Encode UTF-16 to satisfy schtasks /XML's requirement.
    [IO.File]::WriteAllText($xmlPath, $taskXml, [Text.Encoding]::Unicode)
    & schtasks.exe /Create /TN $AgentTaskName /XML $xmlPath /F | Out-Null
    Remove-Item -Force $xmlPath
    Write-Host "  registered scheduled task '$AgentTaskName' (boot, SYSTEM, highest, restart-on-failure)"
}

# ---- main ------------------------------------------------------------------
Assert-Admin
Write-Host "EDR install starting..."

$signing = Get-TestSigningState
Write-Host ("  bcdedit testsigning = " + $signing)
if ($signing -ne 'on' -and -not $NoInstallCert) {
    Write-Host "  hint: drivers signed with a test cert require 'bcdedit /set testsigning on' + reboot." -ForegroundColor Yellow
}

if (-not $NoInstallCert) {
    Write-Host "[1/5] Installing test cert..."
    Install-TestCert
}

Write-Host "[2/5] Installing driver..."
Install-Driver

Write-Host "[3/5] Installing agent binary..."
Install-Agent

Write-Host "[4/5] Staging $DataDir..."
Stage-DataDir

Write-Host "[5/5] Registering agent task..."
Register-AgentTask

Write-Host ""
Write-Host "Install complete." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. notepad $DataDir\agent.env"
Write-Host "       set EDR_MANAGER_ENDPOINT and EDR_ENROLLMENT_TOKEN"
Write-Host "  2. sc.exe start $DriverServiceName"
Write-Host "  3. Start-ScheduledTask -TaskName $AgentTaskName"
Write-Host "       (or reboot to start automatically)"
Write-Host ""
Write-Host "Verify:"
Write-Host "  fltmc instances -f $DriverServiceName"
Write-Host "  Get-Process edr-agent"
Write-Host "  Get-ScheduledTask -TaskName $AgentTaskName | Get-ScheduledTaskInfo"

if ($AutoStart) {
    Write-Host ""
    Write-Host "Starting driver + agent (--AutoStart)..."
    & sc.exe start $DriverServiceName | Out-Host
    Start-ScheduledTask -TaskName $AgentTaskName
}
