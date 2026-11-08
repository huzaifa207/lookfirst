// Keeps a console window from opening next to the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use lookfirst_core::{branch_files, read_file, scan_with, Location, Node, Options, Report, Verdict, View};
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![scan, read, branch])
        .run(tauri::generate_context!())
        .expect("LookFirst couldn't start");
}
