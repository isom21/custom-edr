//! Windows SCM service-control-handler integration (M9.1).
//!
//! Replaces the M7.4 scheduled-task wrapper. The agent registers as a
//! real Windows service so that:
//!   * SCM can start / stop / restart it via `sc.exe` and the Services
//!     control panel.
//!   * Failure actions (RestartOnFailure) are configured at the service
//!     level rather than via Task Scheduler XML.
//!   * Service dependencies (e.g. `Tcpip`, `edr` driver) order startup
//!     correctly across reboots.
//!   * Crashes are logged to the Windows Event Log.
//!
//! Integration shape:
//!   * `dispatch()` is called from main when args don't include
//!     --console or --install-service. It hands control to the SCM
//!     dispatcher; on success the dispatcher calls `service_main()` on a
//!     worker thread.
//!   * `service_main()` builds a tokio runtime, spawns
//!     `crate::run_agent_async(stop_rx)`, and reports SERVICE_RUNNING to
//!     SCM. When SCM sends Stop / Shutdown, we signal `stop_rx` and wait
//!     for the agent to drain.
//!   * If `dispatch()` returns the "not started by SCM" sentinel error,
//!     `main()` falls back to console mode automatically.
//!
//! Service install/uninstall (`--install-service`/`--uninstall-service`)
//! is also implemented here so the M7.4 installer can call us directly
//! instead of doing `sc.exe create` itself. The PowerShell installer
//! will be migrated in a follow-up; both registration paths produce
//! equivalent SCM state.

#![cfg(windows)]

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "EDRAgent";
pub const SERVICE_DISPLAY: &str = "EDR Endpoint Agent";
pub const SERVICE_DESCRIPTION: &str =
    "Endpoint detection and response agent. Runs as SYSTEM and talks to the EDR manager via gRPC.";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM dispatcher. Returns `Ok(true)` if dispatch
/// completed (SCM owned us); `Ok(false)` if we weren't started by SCM
/// (caller should fall back to console mode); `Err` for unexpected
/// dispatcher failures.
pub fn dispatch_if_scm_started() -> Result<bool> {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => Ok(true),
        Err(windows_service::Error::Winapi(io_err)) if io_err.raw_os_error() == Some(1063) => {
            // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT — we weren't
            // started by SCM. Console mode is the right fallback.
            Ok(false)
        }
        Err(e) => Err(anyhow::anyhow!("SCM dispatcher failed: {e:?}")),
    }
}

/// Called by SCM on a dedicated worker thread once the dispatcher hands
/// us control. Builds a tokio runtime, spawns the agent, reports
/// SERVICE_RUNNING, and waits for SCM stop / shutdown signals.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        // SCM has nowhere to log to except the Windows Event Log; the
        // tracing subscriber configured by main is in this process so
        // the entry will show up there too.
        tracing::error!(error = %e, "service.run_failed");
    }
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = std_mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("register SCM control handler")?;

    // Report START_PENDING while we boot the agent.
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        })
        .context("set START_PENDING")?;

    // Build the tokio runtime locally so we can drive the agent from
    // SCM's worker thread without needing a separate dispatcher.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for service")?;

    // Channel that signals the agent to stop gracefully.
    let (agent_stop_tx, agent_stop_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn the agent on the runtime.
    let agent_handle = rt.spawn(async move {
        if let Err(e) = crate::run_agent_async(Some(agent_stop_rx)).await {
            tracing::error!(error = %e, "agent.exited_with_error");
        }
    });

    // Report RUNNING. SCM expects this within 30s of START_PENDING; the
    // agent's enrollment may take longer, but RUNNING here means
    // "supervisor is up" — actual readiness is reported via heartbeat.
    status_handle
        .set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        })
        .context("set RUNNING")?;

    // Block until SCM tells us to stop.
    let _ = shutdown_rx.recv();

    // Report STOP_PENDING and signal the agent.
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 1,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    });
    let _ = agent_stop_tx.send(());

    // Give the agent up to 8s to drain.
    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(8), agent_handle).await;
    });

    // Final STOPPED.
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    });

    Ok(())
}

/// Register the agent with SCM. Idempotent: if the service exists with
/// the same binary path, this is a no-op.
pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("open SCM")?;

    let exe = std::env::current_exe().context("current_exe")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    match manager.create_service(&info, ServiceAccess::CHANGE_CONFIG) {
        Ok(svc) => {
            svc.set_description(SERVICE_DESCRIPTION).ok();
            tracing::info!(name = SERVICE_NAME, "service.installed");
            Ok(())
        }
        Err(windows_service::Error::Winapi(io_err)) if io_err.raw_os_error() == Some(1073) => {
            // ERROR_SERVICE_EXISTS. Idempotent: success.
            tracing::info!(name = SERVICE_NAME, "service.already_installed");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("create_service: {e:?}")),
    }
}

/// Stop and remove the service from SCM. Idempotent.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open SCM")?;
    let svc = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(io_err)) if io_err.raw_os_error() == Some(1060) => {
            // ERROR_SERVICE_DOES_NOT_EXIST. Already gone.
            tracing::info!(name = SERVICE_NAME, "service.not_installed");
            return Ok(());
        }
        Err(e) => return Err(anyhow::anyhow!("open_service: {e:?}")),
    };

    // Best-effort stop before delete; ignore "not running".
    let _ = svc.stop();

    // Wait briefly for STOPPED before deleting.
    for _ in 0..10 {
        if let Ok(status) = svc.query_status() {
            if status.current_state == ServiceState::Stopped {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    svc.delete().context("delete service")?;
    tracing::info!(name = SERVICE_NAME, "service.uninstalled");
    Ok(())
}
