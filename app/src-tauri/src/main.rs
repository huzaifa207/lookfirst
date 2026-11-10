// Keeps a console window from opening next to the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use lookfirst_core::{
    branch_files, list_info, read_file, scan_url, scan_with, update_list, ListInfo, Location, Node, Options, Report,
    Verdict, View,
};
use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
struct Scanned {
    verdict: Verdict,
    report: Report,
}

/// Runs work off the window's thread, so a big archive doesn't freeze the app.
async fn off_thread<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(work).await.map_err(|e| e.to_string())
}

/// Checks a file or folder, and lists what's inside for browsing.
#[tauri::command]
async fn scan(path: String) -> Result<Scanned, String> {
    off_thread(move || {
        let report = scan_with(&PathBuf::from(path), Options { list: true });
        Scanned { verdict: report.verdict(), report }
    })
    .await
}

/// Checks a Git repository at an https or ssh address, without cloning it.
#[tauri::command]
async fn scan_address(url: String, token: Option<String>) -> Result<Scanned, String> {
    off_thread(move || {
        let report = scan_url(&url, token.as_deref());
        Scanned { verdict: report.verdict(), report }
    })
    .await
}

/// One file's contents, read in memory for the viewer.
#[tauri::command]
async fn read(path: String, location: Location) -> Result<View, String> {
    off_thread(move || read_file(&PathBuf::from(path), &location)).await
}

/// Every file on one branch or tag of a repository inside.
#[tauri::command]
async fn branch(path: String, repo: String, branch: String) -> Result<Vec<Node>, String> {
    off_thread(move || branch_files(&PathBuf::from(path), &repo, &branch)).await
}

/// Which list of known threats is in use.
#[tauri::command]
fn threat_list() -> ListInfo {
    list_info()
}

/// Downloads the latest list, if it is newer and signed.
#[tauri::command]
async fn update_threat_list() -> Result<ListInfo, String> {
    off_thread(update_list).await?
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![scan, scan_address, read, branch, threat_list, update_threat_list])
        .run(tauri::generate_context!())
        .expect("LookFirst couldn't start");
}
