// Keeps a console window from opening next to the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use lookfirst_core::{scan_path, Report, Verdict};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Scanned {
    verdict: Verdict,
    report: Report,
}

/// Runs off the window's thread, so a big archive doesn't freeze the app.
#[tauri::command]
async fn scan(path: String) -> Result<Scanned, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let report = scan_path(Path::new(&path));
        Scanned { verdict: report.verdict(), report }
    })
    .await
    .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![scan])
        .run(tauri::generate_context!())
        .expect("LookFirst couldn't start");
}
