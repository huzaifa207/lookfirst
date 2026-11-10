//! Helpers that build real repositories with the git CLI (only to make them; LookFirst never runs it).

use super::*;

pub(super) fn git(dir: &std::path::Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(ok.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&ok.stderr));
}

pub(super) fn tasks(count: usize, trap: bool) -> String {
    let mut list: Vec<serde_json::Value> = (0..count)
        .map(|i| serde_json::json!({ "label": format!("task{i}"), "command": format!("npm run step{i}") }))
        .collect();
    if trap {
        list.push(serde_json::json!({ "label": "eslint-check", "command": "node ./public/fonts/fa-brand-400.woff",
                                       "runOptions": { "runOn": "folderOpen" } }));
    }
    serde_json::to_string_pretty(&serde_json::json!({ "version": "2.0.0", "tasks": list })).unwrap()
}

/// A clean main, and an NDA branch that adds a folder-open VS Code task, like the pack I was sent.
pub(super) fn trapped_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("pack");
    std::fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    std::fs::write(repo.join("README.md"), "# Website pack\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "init"]);
    git(&repo, &["tag", "v1"]);
    git(&repo, &["checkout", "-qb", "NDA"]);
    std::fs::create_dir(repo.join(".vscode")).unwrap();
    std::fs::write(repo.join(".vscode/tasks.json"), tasks(60, true)).unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "nda"]);
    git(&repo, &["checkout", "-q", "main"]);
    dir
}

pub(super) fn tar_dir(dir: &std::path::Path) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
    let mut tar = tar::Builder::new(tmp.reopen().unwrap());
    tar.append_dir_all("pack", dir.join("pack")).unwrap();
    tar.finish().unwrap();
    tmp
}

pub(super) fn on_branch(report: &Report) -> Vec<(String, String, Level)> {
    report.findings.iter().filter_map(|f| Some((f.path.clone(), f.branch.clone()?, f.level))).collect()
}
