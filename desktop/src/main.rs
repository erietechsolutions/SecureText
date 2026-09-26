//! SecureText desktop client (Phase 4): a Tauri shell around
//! `securetext-app`. The shell does three things only: find the profile
//! directory, unlock/start the node, and pass UI calls and node events
//! across. All application logic lives in `securetext-app`, and all
//! commands the UI can run go through `securetext_app::api::dispatch`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use securetext_app::update::{install, Applied};
use securetext_app::{api, NodeConfig, NodeHandle, UpdateConfig};
use serde::Serialize;
use tauri::{Emitter, Manager, State};
use tokio::sync::{broadcast::error::RecvError, Mutex};

struct AppState {
    profile_dir: PathBuf,
    /// Where verified update downloads wait to be installed.
    update_dir: PathBuf,
    node: Mutex<Option<NodeHandle>>,
}

/// The update-signing public key(s) this build trusts (roadmap Phase 6).
/// Reviewable in the repository; a build whose file holds no key simply
/// has updates switched off.
const UPDATE_KEYS: &str = include_str!("../update-signing.pub");

/// How this copy was installed. The Tauri bundler stamps the package type
/// into the binary when it builds an installer, which is more reliable
/// than guessing from paths; an unstamped binary is a source build.
fn install_kind() -> install::InstallKind {
    use tauri::utils::config::BundleType;
    match tauri::utils::platform::bundle_type() {
        Some(BundleType::Deb) => install::InstallKind::Deb,
        Some(BundleType::Rpm) => install::InstallKind::Rpm,
        Some(BundleType::Nsis) => install::InstallKind::WindowsNsis,
        Some(BundleType::Msi) => install::InstallKind::WindowsMsi,
        // Needs the image's own path, which only the AppImage runtime knows.
        Some(BundleType::AppImage) => install::InstallKind::detect(),
        _ => install::InstallKind::Development,
    }
}

fn update_config(staging_dir: PathBuf) -> Option<UpdateConfig> {
    match securetext_app::update::manifest::parse_public_key(UPDATE_KEYS) {
        Ok(key) => {
            let mut config = UpdateConfig::desktop(env!("CARGO_PKG_VERSION").to_string(), vec![key], staging_dir);
            config.install = install_kind();
            Some(config)
        }
        Err(_) => {
            eprintln!("[securetext] no update-signing key is pinned in this build; automatic updates are off");
            None
        }
    }
}

#[derive(Serialize)]
struct ProfileInfo {
    exists: bool,
    unlocked: bool,
}

#[tauri::command]
async fn profile_info(state: State<'_, AppState>) -> Result<ProfileInfo, String> {
    Ok(ProfileInfo {
        exists: securetext_app::profile_exists(&state.profile_dir),
        unlocked: state.node.lock().await.is_some(),
    })
}

#[tauri::command]
async fn unlock(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    label: String,
    passphrase: String,
) -> Result<(), String> {
    let mut slot = state.node.lock().await;
    if slot.is_some() {
        return Ok(());
    }
    let mut config = NodeConfig::tor(state.profile_dir.clone(), label, passphrase);
    config.update = update_config(state.update_dir.clone());
    let node = NodeHandle::start(config).await.map_err(|e| format!("{e:#}"))?;

    let mut events = node.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let _ = app.emit("securetext://event", event);
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            }
        }
    });
    *slot = Some(node);
    Ok(())
}

#[tauri::command]
async fn node(state: State<'_, AppState>, cmd: String, args: serde_json::Value) -> Result<serde_json::Value, String> {
    let node = state
        .node
        .lock()
        .await
        .clone()
        .ok_or_else(|| "profile is locked".to_string())?;
    api::dispatch(&node, &cmd, args).await
}

#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum ApplyOutcome {
    /// The app is about to exit (and restart into the new version).
    Restarting,
    /// The package was handed to the system's software installer.
    SystemInstaller { path: String },
}

/// Install the downloaded update. The node only ever stages a file whose
/// hash matched the signed manifest; it's checked once more here, right
/// before it's used.
#[tauri::command]
async fn apply_update(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<ApplyOutcome, String> {
    let node = state.node.lock().await.clone().ok_or_else(|| "profile is locked".to_string())?;
    let (path, asset, kind) = node.staged_update().await.map_err(|e| format!("{e:#}"))?;
    install::verify_file(&path, &asset.sha256, asset.size).map_err(|e| format!("{e:#}"))?;
    match install::apply(&kind, &path).map_err(|e| format!("{e:#}"))? {
        Applied::Restart(program) => {
            node.shutdown().await;
            std::process::Command::new(program).spawn().map_err(|e| format!("couldn't start the new version: {e}"))?;
            app.exit(0);
            Ok(ApplyOutcome::Restarting)
        }
        Applied::InstallerLaunched => {
            // The installer closes and relaunches the app itself; seal
            // the profile and get out of its way.
            node.shutdown().await;
            app.exit(0);
            Ok(ApplyOutcome::Restarting)
        }
        Applied::HandedToSystem(path) => Ok(ApplyOutcome::SystemInstaller { path: path.display().to_string() }),
    }
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // SECURETEXT_PROFILE_DIR lets one machine run several profiles
            // (e.g. testing two users side by side) and points the profile
            // somewhere with a clean ownership chain when the default app
            // data directory doesn't have one (arti refuses such dirs;
            // tech-stack.md's implementation findings).
            let profile_dir = match std::env::var_os("SECURETEXT_PROFILE_DIR") {
                Some(dir) => PathBuf::from(dir),
                None => app.path().app_data_dir()?.join("profile"),
            };
            let update_dir = app.path().app_cache_dir()?.join("updates");
            app.manage(AppState { profile_dir, update_dir, node: Mutex::new(None) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![profile_info, unlock, node, apply_update])
        .build(tauri::generate_context!())
        .expect("failed to build the SecureText window")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // Seal the encrypted profile before the process ends so
                // nothing written in the last few seconds is lost.
                let state = app.state::<AppState>();
                tauri::async_runtime::block_on(async {
                    if let Some(node) = state.node.lock().await.take() {
                        node.shutdown().await;
                    }
                });
            }
        });
}
