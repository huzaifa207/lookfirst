use super::*;

pub(super) static BENIGN: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_.+-]+( +-{1,2}[A-Za-z0-9_=.+-]+)*$").unwrap());

pub(super) fn hook(path: &str, hook: &str, mode: Option<u32>, content: Option<&[u8]>) -> Option<Finding> {
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

pub(super) fn config(path: &str, content: &[u8]) -> Vec<Finding> {
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
