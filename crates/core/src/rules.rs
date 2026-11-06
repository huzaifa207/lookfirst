//! What counts as a finding. Each check names a place where code runs without anyone choosing to
//! run it, and says when, in words a non-developer can act on.

use crate::{Entry, Finding, Kind, Level};
use regex::bytes::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Addresses and markers from published reports. Each needs a source.
const IOCS: &[(&str, &str)] = &[
    // The fake recruiter's post-checkout hook this project started from (November 2026).
    ("zenithflow-ext123456.vercel.app", "a fake recruiter's Git hook (November 2026)"),
    (".git-checker", "a fake recruiter's Git hook (November 2026)"),
    // OpenSourceMalware, "Lazarus Group uses Git hooks to hide malware" (May 2026).
    ("precommit.vercel.app", "the Contagious Interview Git hook campaign (May 2026)"),
];

static DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b(curl|wget)\b|invoke-webrequest|\biwr\b|downloadstring|downloadfile|urllib\.request|requests\.get|\bhttps?\.get\(|\bfetch\s*\(|axios\.get",
    )
});
/// Running something, in a shell script, PowerShell, Python or Node.
static RUN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(cmd|powershell|pwsh|python3?|node|iex)\b|chmod\s+\+x|invoke-expression|\biex\b|child_process|\bexecsync\s*\(|\bspawn\s*\(|new\s+function\s*\(|start-process|subprocess|os\.system",
    )
});
static HIDDEN: LazyLock<Regex> = LazyLock::new(|| {
    re(r">\s*/dev/null\s+2>&1\s*&|\bnohup\b|\bdisown\b|-windowstyle\s+hidden|windowshide|detached\s*:\s*true")
});
static BASE64: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\batob\s*\(|base64\s+(-d|--decode|-D)\b|buffer\.from\([^)]{0,200}base64|b64decode|frombase64string")
});
static HOSTING: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"[a-z0-9-]+\.(vercel\.app|netlify\.app|onrender\.com|glitch\.me|herokuapp\.com|workers\.dev|ngrok-free\.app|ngrok\.io|trycloudflare\.com)",
    )
});
/// `node fonts/fa-brand-400.woff`: code hidden in a file that shouldn't be code.
static NOT_CODE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bnode\s+[^\s;&|]+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|txt|md|css)\b"));
static FOLDER_OPEN: LazyLock<Regex> = LazyLock::new(|| re(r#""runOn"\s*:\s*"folderOpen""#));
static COMMAND: LazyLock<Regex> = LazyLock::new(|| re(r#""command"\s*:\s*"((?:[^"\\]|\\.)*)""#));
static BENIGN: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_.+-]+( +-{1,2}[A-Za-z0-9_=.+-]+)*$").unwrap());

fn re(pattern: &str) -> Regex {
    Regex::new(&format!("(?i){pattern}")).unwrap()
}

/// Windows and macOS file types that run as programs when double-clicked.
const PROGRAMS: &[&str] = &[
    "exe",
    "com",
    "bat",
    "cmd",
    "ps1",
    "msi",
    "jar",
    "reg",
    "command",
    "pkg",
    "dmg",
    "scpt",
    "applescript",
    "appimage",
    "desktop",
    "iso",
];
/// The same, but with almost no reason to be in a project or document pack.
const SNEAKY: &[&str] = &["scr", "hta", "vbs", "vbe", "jse", "wsf", "wsh", "lnk", "pif", "cpl", "msc"];
const MACROS: &[&str] = &["docm", "dotm", "xlsm", "xltm", "pptm", "potm"];
const DOCUMENTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "mp4", "mov",
];
/// Archives LookFirst opens when it finds them inside another (docx, jar and apk are zips too,
/// but they're documents and programs, not packs of files).
const ARCHIVES: &[&str] = &["zip", "tar", "tgz", "gz", "tbz2", "bz2", "txz", "xz", "7z", "rar"];
const BINARY: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "icns", "bmp", "tiff", "psd", "ai", "sketch", "fig", "mp3", "mp4",
    "mov", "wav", "avi", "webm", "pdf", "ttf", "otf", "woff", "woff2", "eot", "so", "dylib", "dll", "wasm", "class",
    "pyc", "o", "a", "lib", "node", "sqlite", "db",
];
/// Docs and data quote commands and addresses (a README's `curl … | sh`, a write-up naming a
/// malware URL) without running them.
const PROSE: &[&str] =
    &["md", "markdown", "txt", "rst", "adoc", "html", "htm", "csv", "json", "xml", "yml", "yaml", "svg"];
/// Files the general "downloads and runs" check reads. Files with no extension count when they
/// start with a #! line.
const SCRIPTS: &[&str] =
    &["sh", "bash", "zsh", "command", "ps1", "bat", "cmd", "py", "rb", "pl", "js", "mjs", "cjs", "ts", "mts", "cts"];
const LIFECYCLE: &[&str] =
    &["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish"];

fn ext(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|s| !s.is_empty())
}

/// The part of the path after a `.git/` folder, if it's inside one.
fn git_rel(path: &str) -> Option<&str> {
    if let Some(rest) = path.strip_prefix(".git/") {
        return Some(rest);
    }
    path.find("/.git/").map(|i| &path[i + 6..])
}

pub(crate) fn in_git_dir(path: &str) -> bool {
    path == ".git" || path.ends_with("/.git") || git_rel(path).is_some()
}

fn in_node_modules(path: &str) -> bool {
    segments(path).any(|s| s == "node_modules")
}

pub(crate) fn skip_dir(path: &str) -> bool {
    git_rel(path).is_some_and(|rel| rel == "objects" || rel.starts_with("objects/"))
}

pub(crate) fn is_archive(path: &str) -> bool {
    ARCHIVES.contains(&ext(path).as_str())
}

pub(crate) fn wants_content(path: &str, size: u64) -> bool {
    if size == 0 || git_rel(path).is_some_and(|rel| rel.starts_with("objects/")) {
        return false;
    }
    if in_node_modules(path) {
        return path.ends_with("/package.json");
    }
    !BINARY.contains(&ext(path).as_str())
}

pub(crate) fn cant_open(name: &str, why: &str) -> Finding {
    Finding {
        level: Level::Check,
        path: name.to_string(),
        title: format!("LookFirst couldn't look inside this, because {why}."),
        detail: "Don't extract or open it until someone has checked it another way.".into(),
    }
}

fn finding(level: Level, path: &str, title: impl Into<String>, detail: impl Into<String>) -> Finding {
    Finding { level, path: path.to_string(), title: title.into(), detail: detail.into() }
}

/// What the code in a file does, in plain words: "downloads something, runs it in the background…".
fn signs(content: &[u8]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (pattern, sign) in [
        (&*DOWNLOAD, "downloads something"),
        (&*RUN, "runs a program or makes a file executable"),
        (&*HIDDEN, "hides what it runs"),
        (&*BASE64, "decodes hidden (base64) text"),
        (&*HOSTING, "contacts a free hosting address"),
        (&*NOT_CODE, "runs a file that shouldn't be code (a font or image)"),
    ] {
        if pattern.is_match(content) {
            out.push(sign);
        }
    }
    out
}

fn describe(signs: &[&str]) -> String {
    match signs {
        [] => String::new(),
        [only] => format!(" It {only}."),
        [rest @ .., last] => format!(" It {}, and {last}.", rest.join(", ")),
    }
}

/// Downloads something and runs it, or runs a file that shouldn't be code.
fn alarming(content: &[u8]) -> bool {
    (DOWNLOAD.is_match(content) && RUN.is_match(content)) || NOT_CODE.is_match(content)
}

fn clip(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match text.char_indices().nth(160) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text,
    }
}

pub(crate) fn check(path: &str, entry: &Entry, content: Option<&[u8]>, seen: &mut HashSet<String>) -> Vec<Finding> {
    let mut out = checks(path, entry, content, seen);
    // One card per file: a malware match folds into the file's other finding, when it has one.
    if let Some(i) = out.iter().position(|f| f.title.starts_with("This contains an address")) {
        if out.len() > 1 {
            let mut ioc = out.remove(i);
            if out[0].level == Level::Danger {
                // The other finding says what the file does; the match backs it up.
                let main = &mut out[0];
                main.detail = format!(
                    "{} It also matches known malware: {}",
                    main.detail,
                    ioc.detail.trim_start_matches("It matches ")
                );
            } else {
                // A weaker finding becomes a note under the match.
                let other = out.remove(0);
                ioc.detail = format!("{} {}", ioc.detail, other.title);
                out.insert(0, ioc);
            }
        }
    }
    out
}

fn checks(path: &str, entry: &Entry, content: Option<&[u8]>, seen: &mut HashSet<String>) -> Vec<Finding> {
    let mut out = Vec::new();
    let path = path.trim_end_matches('/');
    let name = path.rsplit('/').next().unwrap_or(path);
    // macOS adds "._name" metadata files to tars and a __MACOSX folder to zips. Never code.
    if name.starts_with("._") || segments(path).next() == Some("__MACOSX") {
        return out;
    }

    if path.starts_with('/') || path.as_bytes().get(1) == Some(&b':') || segments(path).any(|s| s == "..") {
        out.push(finding(
            Level::Danger,
            path,
            "This would be written outside the folder you extract it into.",
            "Its path climbs out of the extraction folder (a \"Zip Slip\"), so extracting the archive could overwrite files elsewhere on the computer.",
        ));
    }
    if let Kind::Link(target) = &entry.kind {
        if escapes(path, target) {
            out.push(finding(
                Level::Danger,
                path,
                "This is a link to a place outside the folder.",
                format!(
                    "It points to {target}. Opening or extracting it can read or overwrite files outside the folder."
                ),
            ));
        }
        return out;
    }
    if entry.encrypted && seen.insert("encrypted".into()) {
        out.push(finding(
            Level::Check,
            path,
            "Some files are password-protected, so LookFirst could only check their names.",
            "A password on an archive also stops email and antivirus scanners from looking inside, which is why attackers use them.",
        ));
    }
    // A macOS app is a folder ending in .app; report the bundle once.
    if let Some(i) = path.find(".app/").or_else(|| path.ends_with(".app").then(|| path.len() - 4)) {
        let bundle = &path[..i + 4];
        if seen.insert(bundle.to_string()) {
            out.push(finding(
                Level::Check,
                bundle,
                "This is a Mac app, not a document. It runs as a program when opened.",
                "Only open apps from people and companies you've verified.",
            ));
        }
    }
    if entry.kind != Kind::File {
        return out;
    }

    if !in_node_modules(path) {
        out.extend(file_type(path, name)); // packages ship .cmd shims and the like
    }
    if let Some(content) = content.filter(|_| !PROSE.contains(&ext(name).as_str())) {
        if let Some((ioc, source)) = IOCS.iter().find(|(ioc, _)| contains(content, ioc)) {
            out.push(finding(
                Level::Danger,
                path,
                "This contains an address or marker from known malware.",
                format!("It matches \"{ioc}\", from {source}."),
            ));
        }
    }
    let handled = out.len();

    if let Some(rel) = git_rel(path) {
        if let Some(hook) = rel.strip_prefix("hooks/") {
            out.extend(git_hook(path, hook, entry.mode, content));
        } else if rel == "config" {
            out.extend(git_config(path, content.unwrap_or_default()));
        }
        return out; // the rest of .git is Git's own data
    }
    let content = content.unwrap_or_default();
    let parent = path.rsplit('/').nth(1).unwrap_or("");

    if segments(path).any(|s| s == ".githooks" || s == ".husky") && !path.contains(".husky/_/") {
        let signs = signs(content);
        out.push(finding(
            if alarming(content) { Level::Danger } else { Level::Check },
            path,
            "This is a Git hook waiting to be switched on.",
            format!("Git runs these only if its hooksPath setting points here, which husky does by itself on npm install.{}", describe(&signs)),
        ));
    } else if (name == "tasks.json" && parent == ".vscode") || name.ends_with(".code-workspace") {
        if FOLDER_OPEN.is_match(content) {
            let commands: Vec<String> =
                COMMAND.captures_iter(content).take(3).map(|c| clip(&String::from_utf8_lossy(&c[1]))).collect();
            out.push(finding(
                Level::Danger,
                path,
                "This runs a command as soon as the folder is opened in VS Code.",
                format!(
                    "A VS Code task set to run on folder open, which VS Code does once the folder is trusted. It runs: {}.{}",
                    commands.join("; "),
                    describe(&signs(content))
                ),
            ));
        }
    } else if parent == ".claude" && (name == "settings.json" || name == "settings.local.json") {
        out.extend(claude_settings(path, content));
    } else if name == ".mcp.json" || (name == "mcp.json" && (parent == ".cursor" || parent == ".vscode")) {
        out.extend(mcp_servers(path, content));
    } else if name == "package.json" {
        out.extend(npm_scripts(path, content));
    } else if name == ".envrc" {
        out.push(finding(
            Level::Check,
            path,
            "This runs commands when a terminal is opened in the folder, if direnv is installed.",
            format!("direnv asks once before running it.{}", describe(&signs(content))),
        ));
    } else if out.len() == handled && !in_node_modules(path) {
        out.extend(script(path, name, content));
    }
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Whether a link inside the folder points outside it.
fn escapes(path: &str, target: &str) -> bool {
    if target.starts_with('/') || target.starts_with('\\') || target.as_bytes().get(1) == Some(&b':') {
        return true;
    }
    let mut depth = segments(path).count() as i64 - 1; // the link's own folder
    for part in target.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => depth -= 1,
            _ => depth += 1,
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

fn file_type(path: &str, name: &str) -> Option<Finding> {
    if name.contains('\u{202E}') {
        return Some(finding(
            Level::Danger,
            path,
            "This file hides its real type with a hidden character that reverses its name.",
            "The right-to-left override character (U+202E) makes a name like \"reportfdp.exe\" display as \"reportexe.pdf\".",
        ));
    }
    let ext = ext(name);
    let program = PROGRAMS.contains(&ext.as_str()) || SNEAKY.contains(&ext.as_str());
    let pretend = name.rsplit('.').nth(1).map(|e| e.to_ascii_lowercase());
    if program && pretend.as_deref().is_some_and(|e| DOCUMENTS.contains(&e)) {
        return Some(finding(
            Level::Danger,
            path,
            "This pretends to be a document, but it's a program.",
            format!("Its name ends in .{}, so it runs when double-clicked, whatever the name before it says.", ext),
        ));
    }
    if SNEAKY.contains(&ext.as_str()) {
        return Some(finding(
            Level::Danger,
            path,
            "This runs as a program when double-clicked.",
            format!(".{ext} files run code on Windows, and almost never belong in a project or a pack of documents."),
        ));
    }
    if program {
        return Some(finding(
            Level::Check,
            path,
            "This is a program or script, not a document.",
            format!(".{ext} files run when opened. Normal in some projects; only run it if you know why it's there."),
        ));
    }
    if MACROS.contains(&ext.as_str()) {
        return Some(finding(
            Level::Check,
            path,
            "This document can contain macros, small programs that run inside Office.",
            "Keep macros turned off when you open it.",
        ));
    }
    None
}

fn git_hook(path: &str, hook: &str, mode: Option<u32>, content: Option<&[u8]>) -> Option<Finding> {
    if hook.is_empty() || hook.contains('/') || hook.ends_with(".sample") {
        return None;
    }
    let when = match hook {
        "post-checkout" => "switches branches or checks out code in Git",
        "pre-commit" | "prepare-commit-msg" | "commit-msg" | "post-commit" => "makes a commit in Git",
        "post-merge" => "pulls or merges in Git",
        "pre-merge-commit" => "merges in Git",
        "pre-rebase" | "post-rewrite" => "rebases or amends a commit in Git",
        "pre-push" => "pushes from Git",
        "pre-auto-gc" | "reference-transaction" => "runs almost any Git command",
        "post-index-change" => "stages files or switches branches in Git",
        "fsmonitor-watchman" => "checks the folder's status in Git (when Git is set to use it)",
        "applypatch-msg" | "pre-applypatch" | "post-applypatch" => "applies a patch in Git",
        "pre-receive" | "update" | "proc-receive" | "post-receive" | "post-update" | "push-to-checkout" => {
            "pushes to this copy"
        }
        _ => {
            return Some(finding(
                Level::Check,
                path,
                "This is a script in Git's hooks folder.",
                format!(
                    "\"{hook}\" isn't a name Git runs by itself, but a hook could call it.{}",
                    describe(&signs(content.unwrap_or_default()))
                ),
            ))
        }
    };
    let off = mode.is_some_and(|m| m & 0o111 == 0);
    Some(finding(
        if off { Level::Check } else { Level::Danger },
        path,
        format!("This runs code by itself when someone {when}."),
        format!(
            "A Git hook ({hook}){}. Git runs it on its own; nobody has to open it.{}",
            if off {
                ", not marked executable, so Git on macOS and Linux skips it (Git for Windows may still run it)"
            } else if mode.is_some() {
                ", marked executable"
            } else {
                ""
            },
            describe(&signs(content.unwrap_or_default()))
        ),
    ))
}

fn git_config(path: &str, content: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(content);
    let mut out = Vec::new();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[') {
            let inner = inner.split(']').next().unwrap_or("");
            section = match inner.split_once(char::is_whitespace) {
                Some((s, sub)) => format!("{}.{}", s.to_lowercase(), sub.trim().trim_matches('"')),
                None => inner.to_lowercase(),
            };
            continue;
        }
        let (key, value) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim())).unwrap_or((line, "true"));
        let value = match value.strip_prefix('"') {
            Some(rest) => rest.split('"').next().unwrap_or(""),
            None => value.split(['#', ';']).next().unwrap_or("").trim(),
        };
        let key = format!("{section}.{}", key.to_lowercase());
        let set = format!("{key} = {value}");
        let (group, name) = key.rsplit_once('.').unwrap_or(("", &key));
        let runs = |title: &str| finding(Level::Danger, path, title, set.clone());
        match (group, name) {
            ("core", "hookspath") => out.push(finding(
                Level::Danger,
                path,
                "This tells Git to run hooks from a different folder.",
                format!("{set}: Git runs the scripts there on commits, checkouts and more."),
            )),
            ("core", "fsmonitor") if !matches!(value.to_lowercase().as_str(), "true" | "false" | "") => {
                out.push(finding(
                    Level::Danger,
                    path,
                    "This makes Git run a program every time it checks the folder.",
                    format!(
                        "{set}: Git runs it on every status check, which editors and terminal prompts do constantly."
                    ),
                ))
            }
            ("core", "pager" | "editor" | "sshcommand" | "askpass")
            | ("sequence", "editor")
            | ("diff", "external")
            | ("gpg", "program")
                if !BENIGN.is_match(value) =>
            {
                out.push(runs("This makes Git run a program during everyday commands."))
            }
            (g, "program") if g.starts_with("gpg.") && !BENIGN.is_match(value) => {
                out.push(runs("This makes Git run a program during everyday commands."))
            }
            ("credential", "helper") if value.starts_with('!') || value.contains('/') => {
                out.push(runs("This makes Git run a program whenever it needs a password."))
            }
            (g, "clean" | "smudge" | "process") if g.starts_with("filter.") && !value.starts_with("git-lfs ") => {
                out.push(runs("This makes Git run a program when files are checked out or added."))
            }
            (g, "textconv" | "command") if g.starts_with("diff.") => {
                out.push(finding(Level::Check, path, "This makes Git run a program when comparing files.", set))
            }
            (g, "driver") if g.starts_with("merge.") => {
                out.push(finding(Level::Check, path, "This makes Git run a program when merging files.", set))
            }
            ("alias", alias) if value.starts_with('!') => out.push(finding(
                Level::Check,
                path,
                "This defines a Git shortcut that runs a shell command.",
                format!("{set}: it runs only if someone types git {alias}."),
            )),
            ("include", "path") => {
                out.push(finding(Level::Check, path, "This loads more Git settings from another file.", set))
            }
            (g, "path") if g.starts_with("includeif.") => {
                out.push(finding(Level::Check, path, "This loads more Git settings from another file.", set))
            }
            _ => {}
        }
    }
    out
}

fn claude_settings(path: &str, content: &[u8]) -> Option<Finding> {
    let json: Option<serde_json::Value> = serde_json::from_slice(content).ok();
    let hooks = match &json {
        Some(json) => match json.get("hooks").and_then(|h| h.as_object()) {
            Some(h) if !h.is_empty() => h,
            _ => return None,
        },
        None if contains(content, "\"hooks\"") => {
            return Some(finding(
                Level::Danger,
                path,
                "This runs commands when an AI coding assistant (Claude Code) works in the folder.",
                "Claude Code settings with hooks (the file isn't valid JSON, so the hooks couldn't be listed).",
            ))
        }
        None => return None,
    };
    let events: Vec<&str> = hooks.keys().map(String::as_str).collect();
    let commands: Vec<String> = serde_json::to_string(hooks)
        .ok()
        .map(|s| COMMAND.captures_iter(s.as_bytes()).take(3).map(|c| clip(&String::from_utf8_lossy(&c[1]))).collect())
        .unwrap_or_default();
    Some(finding(
        Level::Danger,
        path,
        "This runs commands when an AI coding assistant (Claude Code) starts or works in the folder.",
        format!("Claude Code hooks for {}. They run: {}.", events.join(", "), commands.join("; ")),
    ))
}

fn mcp_servers(path: &str, content: &[u8]) -> Option<Finding> {
    let json: serde_json::Value = serde_json::from_slice(content).ok()?;
    let servers = json.get("mcpServers").or_else(|| json.get("servers"))?.as_object()?;
    if servers.is_empty() {
        return None;
    }
    let list: Vec<String> = servers
        .iter()
        .take(5)
        .map(|(name, s)| {
            let cmd = s.get("command").and_then(|c| c.as_str()).unwrap_or("a remote server");
            let args: Vec<&str> = s
                .get("args")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            format!("{name}: {}", clip(&format!("{cmd} {}", args.join(" "))))
        })
        .collect();
    Some(finding(
        Level::Check,
        path,
        "This starts programs when an AI assistant connects to the project.",
        format!("MCP servers, which the assistant asks before starting: {}.", list.join("; ")),
    ))
}

fn npm_scripts(path: &str, content: &[u8]) -> Option<Finding> {
    let json: serde_json::Value = serde_json::from_slice(content).ok()?;
    let scripts = json.get("scripts")?.as_object()?;
    let found: Vec<(String, String)> =
        LIFECYCLE.iter().filter_map(|k| Some((k.to_string(), scripts.get(*k)?.as_str()?.to_string()))).collect();
    if found.is_empty() {
        return None;
    }
    let joined = found.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join("\n");
    let bad = alarming(joined.as_bytes()) || IOCS.iter().any(|(ioc, _)| joined.contains(ioc));
    if in_node_modules(path) && !bad {
        return None; // installed packages run install scripts all the time
    }
    let list: Vec<String> = found.iter().map(|(k, v)| format!("{k}: {}", clip(v))).collect();
    Some(finding(
        if bad { Level::Danger } else { Level::Check },
        path,
        "This runs commands when someone installs the project with npm.",
        format!(
            "Install scripts, which npm runs by itself: {}.{}",
            list.join("; "),
            describe(&signs(joined.as_bytes()))
        ),
    ))
}

/// Any other script: flag only the alarming combination, since normal code downloads things and
/// runs things all the time, just rarely both at once.
fn script(path: &str, name: &str, content: &[u8]) -> Option<Finding> {
    let head = &content[..content.len().min(8192)];
    if head.contains(&0) {
        return None; // binary
    }
    let ext = ext(name);
    if !(SCRIPTS.contains(&ext.as_str()) || (!name.contains('.') && content.starts_with(b"#!"))) {
        return None;
    }
    let minified = matches!(ext.as_str(), "js" | "mjs" | "cjs")
        && (name.ends_with(".min.js")
            || content.len() > 200_000
            || segments(path).any(|s| s == "dist" || s == "build"));
    if minified || !alarming(content) {
        return None;
    }
    Some(finding(
        Level::Check,
        path,
        "This script downloads something and runs it.",
        format!("Fine in an installer you trust; a red flag in a pack of documents.{}", describe(&signs(content))),
    ))
}
