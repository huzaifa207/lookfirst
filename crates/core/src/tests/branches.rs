//! Branches and tags other than the one checked out.

use super::*;

#[test]
fn a_trap_on_another_branch() {
    let dir = trapped_repo();
    let report = scan(&tar_dir(dir.path()));
    assert_eq!(
        on_branch(&report),
        [("pack/.vscode/tasks.json".into(), "NDA".into(), Level::Danger)],
        "{:?}",
        titles(&report)
    );
    let task = report.findings.iter().find(|f| f.branch.is_some()).unwrap();
    assert!(
        task.detail.contains("fa-brand-400.woff") && !task.detail.contains("step0"),
        "the folder-open command, not the first ones: {}",
        task.detail
    );
    let repo = &report.repos[0];
    assert_eq!((repo.path.as_str(), repo.head.as_deref()), ("pack/.git", Some("main")));
    assert_eq!(repo.branches, ["main", "NDA"]);
    assert_eq!(repo.tags, ["v1"]);
    assert!(repo.note.is_none(), "{:?}", repo.note);

    // The same repository as a folder on disk.
    let report = scan_path(&dir.path().join("pack"));
    assert_eq!(
        on_branch(&report),
        [(".vscode/tasks.json".into(), "NDA".into(), Level::Danger)],
        "{:?}",
        titles(&report)
    );
}

#[test]
fn a_trap_stored_as_a_delta_in_a_pack() {
    let dir = trapped_repo();
    let repo = dir.path().join("pack");
    // A newer, bigger, clean version: git keeps the newest whole and stores NDA's as a delta.
    git(&repo, &["checkout", "-q", "-b", "later", "NDA"]);
    std::fs::write(repo.join(".vscode/tasks.json"), tasks(80, false)).unwrap();
    git(&repo, &["commit", "-qam", "later"]);
    git(&repo, &["checkout", "-q", "main"]);
    git(&repo, &["gc", "-q", "--aggressive"]);
    let packs: Vec<_> = std::fs::read_dir(repo.join(".git/objects/pack")).unwrap().flatten().collect();
    let idx = packs.iter().find(|p| p.path().extension().is_some_and(|e| e == "idx")).unwrap().path();
    let verify = std::process::Command::new("git").args(["verify-pack", "-v"]).arg(&idx).output().unwrap();
    let deltas = String::from_utf8_lossy(&verify.stdout).lines().filter(|l| l.split_whitespace().count() == 7).count();
    assert!(deltas > 0, "the test needs a delta in the pack");

    let report = scan(&tar_dir(dir.path()));
    assert_eq!(
        on_branch(&report),
        [("pack/.vscode/tasks.json".into(), "NDA".into(), Level::Danger)],
        "{:?}",
        titles(&report)
    );
    assert_eq!(report.repos[0].branches, ["main", "NDA", "later"]);
}

#[test]
fn the_checked_out_branch_is_reported_once() {
    let dir = trapped_repo();
    git(&dir.path().join("pack"), &["checkout", "-q", "NDA"]);
    let report = scan(&tar_dir(dir.path()));
    let tasks: Vec<_> = report.findings.iter().filter(|f| f.path.ends_with("tasks.json")).collect();
    assert_eq!(tasks.len(), 1, "{:?}", titles(&report));
    assert_eq!(tasks[0].branch, None, "it's in the files as they are now");
    assert_eq!(report.repos[0].head.as_deref(), Some("NDA"));
    assert_eq!(report.repos[0].branches, ["NDA", "main"]);
}

#[test]
fn broken_git_data_doesnt_break_the_scan() {
    let dir = trapped_repo();
    let repo = dir.path().join("pack");
    git(&repo, &["gc", "-q"]);
    for pack in std::fs::read_dir(repo.join(".git/objects/pack")).unwrap().flatten() {
        if pack.path().extension().is_some_and(|e| e == "pack") {
            let mut bytes = std::fs::read(pack.path()).unwrap();
            let middle = bytes.len() / 2;
            bytes.truncate(middle); // a hostile or damaged pack
            let mut perms = std::fs::metadata(pack.path()).unwrap().permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false); // git makes packs read-only
            std::fs::set_permissions(pack.path(), perms).unwrap();
            std::fs::write(pack.path(), bytes).unwrap();
        }
    }
    let report = scan(&tar_dir(dir.path()));
    assert_eq!(report.repos[0].branches, ["main", "NDA"]);
    assert!(report.repos[0].note.as_deref().unwrap_or("").contains("weren't checked"), "{:?}", report.repos[0].note);
}
