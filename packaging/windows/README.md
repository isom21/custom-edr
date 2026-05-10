# Windows packaging

The Windows installer ships as a versioned ZIP containing the agent
binary, the driver `vigil.sys`, the test cert, and PowerShell scripts
that handle install / uninstall.

## Layout of the ZIP

```
vigil-windows-<version>/
├── README.md                  this file
├── install-vigil.ps1            top-level installer
├── uninstall-vigil.ps1          uninstaller
├── vigil-agent.exe              user-mode agent
├── vigil.sys                    minifilter + KMDF callback driver (signed)
├── edr-cert.cer               test cert for trust stores (optional)
└── agent.env.example          template for %ProgramData%\Vigil\agent.env
```

## Install on a Windows endpoint

Run an elevated PowerShell:

```powershell
# Test-signed drivers need this once before first install.
bcdedit /set testsigning on
# Reboot now if testsigning was off.

cd <path-to-extracted-zip>
.\install-vigil.ps1
```

What the installer does:

1. Installs the bundled test cert into `LocalMachine\Root` and
   `LocalMachine\TrustedPublisher` (skip with `-NoInstallCert`).
2. Copies `vigil.sys` to `%windir%\system32\drivers\` and registers the
   `edr` filter driver service via SCM.
3. Copies `vigil-agent.exe` to `%ProgramFiles%\Vigil\`.
4. Stages `%ProgramData%\Vigil\` (state, identity, spool) with an ACL
   that allows only `LocalSystem` and `BUILTIN\Administrators`.
5. Stages `%ProgramData%\Vigil\agent.env` from the template if missing.
6. Registers a scheduled task `VigilAgent` that runs at startup as SYSTEM
   with auto-restart, but **does not start it**.

Then edit `%ProgramData%\Vigil\agent.env` and:

```powershell
sc.exe start edr
Start-ScheduledTask -TaskName VigilAgent
```

Or pass `-AutoStart` to `install-vigil.ps1` to do this for you.

## Uninstall

```powershell
.\uninstall-vigil.ps1            # keep state + cert (default)
.\uninstall-vigil.ps1 -Purge     # also remove %ProgramData%\Vigil
.\uninstall-vigil.ps1 -RemoveCert
```

## Verifying self-protection (M7.2)

After install + start:

```powershell
.\46-self-protection-windows.ps1   # ships in tools\smoke\
```

## Why scheduled task instead of a real Windows service?

The agent binary today doesn't implement the SCM service control
handler protocol, so SCM kills it ~30s after start for not reporting
SERVICE_RUNNING. Wrapping it as a scheduled task with `/SC ONSTART
/RU SYSTEM /RL HIGHEST` gets us the same operational outcome
(auto-start at boot, runs as SYSTEM, auto-restart on crash via Task
Scheduler's `RestartCount`) without the binary refactor.

Implementing real SCM service support via the
[`windows-service`](https://crates.io/crates/windows-service) crate
is tracked as future polish (M7.4 follow-up). Once that lands the
launcher cmd + scheduled task can be replaced by a `sc.exe create
VigilAgent ...` invocation.

## Why no MSI?

WiX v4 setup on the build host is non-trivial and was out of scope
for the M7.4 timebox. The ZIP-based installer covers the same
operational surface (install / uninstall / cert / driver / agent / state)
and is cleanly auditable in PowerShell. WiX MSI is tracked as an M7.8
follow-up — the core install logic in `install-vigil.ps1` is small enough
to translate to WiX custom actions cleanly when we get there.

## Building the package on dev

```powershell
.\packaging\windows\make-package.ps1
```

(Run on lab-windows; gathers the just-built `vigil.sys` and
`vigil-agent.exe`, copies the test cert, and writes
`target\windows-package\vigil-windows-<version>.zip`.)
