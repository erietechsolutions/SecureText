//! SecureText desktop client (Phase 4): a Tauri shell around
//! `securetext-app`. The shell does three things only: find the profile
//! directory, unlock/start the node, and pass UI calls and node events
//! across. All application logic lives in `securetext-app`, and all
//! commands the UI can run go through `securetext_app::api::dispatch`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use securetext_app::{api, NodeConfig, NodeHandle};
use serde::Serialize;
use tauri::{Emitter, Manager, State};
use tokio::sync::{broadcast::error::RecvError, Mutex};

struct AppState {
    profile_dir: PathBuf,
    node: Mutex<Option<NodeHandle>>,
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
    let config = NodeConfig::tor(state.profile_dir.clone(), label, passphrase);
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
            app.manage(AppState { profile_dir, node: Mutex::new(None) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![profile_info, unlock, node])
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
