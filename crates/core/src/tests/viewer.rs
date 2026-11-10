//! The viewer: listing and reading files, without extracting anything.

use super::*;

#[test]
fn reading_files_for_the_viewer() {
    let inner = zip_of(&[f("x/run.sh", "echo hi\n")]);
    let inner_bytes = std::fs::read(inner.path()).unwrap();
    let big = "x".repeat(3 * 1024 * 1024);
    let pack = tgz_of(&[
        f("pack/README.md", "# Hello\n<script>alert(1)</script>\n"),
        F { path: "pack/logo.png", data: b"\x89PNG\r\n\x1a\n\0\0\0IHDR", mode: 0o644 },
        F { path: "pack/more.zip", data: &inner_bytes, mode: 0o644 },
        f("pack/big.txt", &big),
    ]);

    let report = scan_with(pack.path(), Options { list: true });
    let paths: Vec<&str> = report.entries.iter().map(|n| n.path.as_str()).collect();
    assert!(paths.contains(&"pack/README.md") && paths.contains(&"pack/more.zip › x/run.sh"), "{paths:?}");
    assert!(scan_path(pack.path()).entries.is_empty(), "only listed when asked");

    let read = |path: &str| read_file(pack.path(), &Location::File { path: path.into() });
    assert_eq!(
        read("pack/README.md"),
        View::Text { text: "# Hello\n<script>alert(1)</script>\n".into(), truncated: false },
        "text comes back as text, markup and all"
    );
    assert!(matches!(read("pack/logo.png"), View::Binary { size: 15 }));
    assert_eq!(read("pack/more.zip › x/run.sh"), View::Text { text: "echo hi\n".into(), truncated: false });
    assert!(matches!(read("pack/big.txt"), View::Text { truncated: true, ref text } if text.len() == MAX_VIEW));
    assert_eq!(read("pack/nope.txt"), View::Missing);
}

#[test]
fn folder_reads_stay_inside_the_folder() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("pack");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("a.txt"), "inside").unwrap();
    std::fs::write(outer.path().join("secret.txt"), "outside").unwrap();
    let read = |path: &str| read_file(&root, &Location::File { path: path.into() });
    assert_eq!(read("a.txt"), View::Text { text: "inside".into(), truncated: false });
    for escape in
        ["../secret.txt", "/etc/passwd", "", "./../secret.txt", "a.txt/../../secret.txt", "C:/Windows/win.ini"]
    {
        assert_eq!(read(escape), View::Missing, "{escape}");
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../secret.txt", root.join("link")).unwrap();
        assert_eq!(read("link"), View::Link { target: "../secret.txt".into() }, "links are shown, not followed");
        std::os::unix::fs::symlink(outer.path(), root.join("up")).unwrap();
        assert_eq!(read("up/secret.txt"), View::Missing, "nor followed through a linked folder");
    }
}

#[test]
fn browsing_a_branch() {
    let dir = trapped_repo();
    let tar = tar_dir(dir.path());
    let names = |branch: &str| -> Vec<String> {
        branch_files(tar.path(), "pack/.git", branch).into_iter().map(|n| n.path).collect()
    };
    assert_eq!(names("NDA"), ["pack/.vscode/tasks.json", "pack/README.md"]);
    assert_eq!(names("main"), ["pack/README.md"]);
    assert_eq!(names("tag v1"), ["pack/README.md"]);
    assert!(names("no-such-branch").is_empty());

    let location =
        Location::Branch { repo: "pack/.git".into(), branch: "NDA".into(), path: "pack/.vscode/tasks.json".into() };
    assert!(matches!(read_file(tar.path(), &location), View::Text { ref text, .. } if text.contains("folderOpen")));
    let missing =
        Location::Branch { repo: "pack/.git".into(), branch: "main".into(), path: "pack/.vscode/tasks.json".into() };
    assert_eq!(read_file(tar.path(), &missing), View::Missing);

    // The same, from the folder on disk.
    let folder = dir.path().join("pack");
    let files: Vec<String> = branch_files(&folder, ".git", "NDA").into_iter().map(|n| n.path).collect();
    assert_eq!(files, [".vscode/tasks.json", "README.md"]);
    let location = Location::Branch { repo: ".git".into(), branch: "NDA".into(), path: ".vscode/tasks.json".into() };
    assert!(matches!(read_file(&folder, &location), View::Text { ref text, .. } if text.contains("fa-brand-400.woff")));
}
