//! Git over ssh, using the user's own `ssh`.

use super::*;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The user's own `ssh`, running `git-upload-pack` on the server. No Git runs here; ssh brings the
/// user's keys, agent and known hosts, and never asks a question (BatchMode).
pub(super) struct Ssh {
    child: Arc<Mutex<Child>>,
    stdin: Option<std::process::ChildStdin>,
    stdout: std::process::ChildStdout,
    stderr: Option<std::thread::JoinHandle<String>>,
    done: Arc<AtomicBool>,
}

pub(super) struct SshTarget {
    /// "user@host" or "host", already checked to be safe to hand to ssh.
    host: String,
    port: Option<u16>,
    path: String,
}

impl Ssh {
    pub(super) fn start(target: &SshTarget) -> Result<Ssh, String> {
        let mut command = Command::new(std::env::var_os("LOOKFIRST_SSH").unwrap_or_else(|| "ssh".into()));
        command.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=20", "-o", "SendEnv=GIT_PROTOCOL"]);
        if let Some(port) = target.port {
            command.args(["-p", &port.to_string()]);
        }
        // "--" so a host can never be read as an option.
        command
            .arg("--")
            .arg(&target.host)
            .arg(format!("git-upload-pack {}", shell_quote(&target.path)))
            .env("GIT_PROTOCOL", "version=2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000); // no console window
        let mut child = command.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "ssh isn't installed on this computer, and an ssh address needs it".to_string()
            } else {
                format!("ssh couldn't start ({e})")
            }
        })?;
        let (stdin, stdout, mut stderr) =
            (child.stdin.take(), child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let reader = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = (&mut stderr).take(64 * 1024).read_to_string(&mut text);
            text
        });
        let child = Arc::new(Mutex::new(child));
        let done = Arc::new(AtomicBool::new(false));
        let (watched, finished) = (child.clone(), done.clone());
        std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < TIMEOUT {
                if finished.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            let _ = watched.lock().map(|mut c| c.kill());
        });
        Ok(Ssh { child, stdin, stdout, stderr: Some(reader), done })
    }

    /// Why it failed, in ssh's own words ("Permission denied (publickey)").
    pub(super) fn fail(&mut self, what: &str) -> String {
        self.finish();
        let said = self.stderr.take().and_then(|t| t.join().ok()).unwrap_or_default();
        match said.lines().rev().find(|l| !l.trim().is_empty()) {
            Some(line) => format!("ssh said: {}", line.trim().chars().take(200).collect::<String>()),
            None => what.to_string(),
        }
    }

    pub(super) fn finish(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        self.stdin = None;
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Transport for Ssh {
    fn advertise(&mut self) -> Result<Vec<u8>, String> {
        read_answer(&mut self.stdout).map_err(|e| self.fail(&format!("the server sent nothing ({e})")))
    }

    fn command(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        let sent = self.stdin.as_mut().map(|s| s.write_all(body).and_then(|_| s.flush()));
        if !matches!(sent, Some(Ok(()))) {
            return Err(self.fail("the connection closed"));
        }
        read_answer(&mut self.stdout).map_err(|e| self.fail(&format!("the server stopped answering ({e})")))
    }
}

impl Drop for Ssh {
    fn drop(&mut self) {
        self.finish();
    }
}

/// A path as one word for the remote shell: 'it'\''s'.
pub(super) fn shell_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

pub(super) fn safe_word(word: &str) -> bool {
    !word.is_empty() && !word.starts_with('-') && word.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// `ssh://user@host:22/owner/repo.git` or `user@host:owner/repo.git`, as ssh needs it.
pub(super) fn ssh_target(url: &str) -> Option<Result<(String, SshTarget), String>> {
    let bad = |m: &str| Some(Err(m.to_string()));
    let (userhost, port, path) = if let Some(rest) = url.strip_prefix("ssh://") {
        let (authority, path) = rest.split_once('/')?;
        let (userhost, port) = match authority.rsplit_once(':') {
            Some((uh, p)) => match p.parse::<u16>() {
                Ok(p) => (uh, Some(p)),
                Err(_) => return bad("that ssh address has a bad port"),
            },
            None => (authority, None),
        };
        (userhost, port, path.to_string())
    } else if !url.contains("://") {
        let (userhost, path) = url.split_once(':')?;
        if userhost.contains(['/', '\\']) || userhost.len() < 2 {
            return None; // a local path (or a Windows drive like C:), not host:path
        }
        (userhost, None, path.to_string())
    } else {
        return None;
    };
    let (user, host) = match userhost.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, userhost),
    };
    if !safe_word(host) || user.is_some_and(|u| !safe_word(u)) || path.chars().any(|c| c.is_control()) {
        return bad("that doesn't look like an ssh address (user@host:owner/repo)");
    }
    let path = path.trim_end_matches('/').to_string();
    if path.is_empty() {
        return bad("that ssh address has no repository path");
    }
    let name = format!("{host}/{}", path.trim_start_matches('/').trim_end_matches(".git"));
    Some(Ok((name, SshTarget { host: userhost.to_string(), port, path })))
}

/// Whether the text is an address to read online, rather than a path on this computer.
pub fn is_address(text: &str) -> bool {
    text.starts_with("https://")
        || text.starts_with("http://")
        || text.starts_with("ssh://")
        // host:path could also be a file with a colon in its name; a file that exists wins.
        || (matches!(ssh_target(text), Some(Ok(_))) && !std::path::Path::new(text).exists())
}
