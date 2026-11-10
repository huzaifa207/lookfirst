//! What counts as a finding. Each check names a place where code runs without anyone choosing to
//! run it, and says when, in words a non-developer can act on.

use crate::{campaigns, Entry, Finding, Kind, Level};
use regex::bytes::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

mod ai;
mod filetype;
mod git;
mod markers;
mod npm;
mod paths;
mod script;
mod text;
mod vscode;

use paths::*;
pub(crate) use paths::{in_git_dir, is_archive, split_git, wants_branch_content, wants_content, wants_repo_content};
use text::*;

/// Docs and data quote commands and addresses (a README's `curl … | sh`, a write-up naming a
/// malware URL) without running them.
const PROSE: &[&str] =
    &["md", "markdown", "txt", "rst", "adoc", "html", "htm", "csv", "json", "xml", "yml", "yaml", "svg"];

pub(crate) fn cant_open(name: &str, why: &str) -> Finding {
    Finding {
        level: Level::Check,
        path: name.to_string(),
        title: format!("LookFirst couldn't look inside this, because {why}."),
        detail: "Don't extract or open it until someone has checked it another way.".into(),
        branch: None,
        campaign: None,
    }
}

fn finding(level: Level, path: &str, title: impl Into<String>, detail: impl Into<String>) -> Finding {
    Finding { level, path: path.to_string(), title: title.into(), detail: detail.into(), branch: None, campaign: None }
}

pub(crate) fn check(path: &str, entry: &Entry, content: Option<&[u8]>, seen: &mut HashSet<String>) -> Vec<Finding> {
    let file = path.trim_end_matches('/');
    let (mut plain, tagged): (Vec<_>, Vec<_>) =
        checks(path, entry, content, seen).into_iter().partition(|f| f.campaign.is_none() || f.path != file);
    // A campaign match folds into the finding it backs up, so a file gets one card. If every other
    // finding on the file is weaker, the match leads and they become notes under it. Separate
    // problems in one file (two settings in a Git config) stay separate cards.
    for mut hit in tagged {
        if let Some(main) = plain.iter_mut().find(|p| p.path == file && p.level >= hit.level) {
            main.campaign = main.campaign.take().or(hit.campaign);
            main.detail = if hit.title.starts_with("This contains an address") {
                format!(
                    "{} It also matches known malware: {}",
                    main.detail,
                    hit.detail.trim_start_matches("It matches ")
                )
            } else {
                format!("{} Also: {} {}", main.detail, hit.title, hit.detail)
            };
        } else {
            let (weaker, rest): (Vec<_>, Vec<_>) = plain.into_iter().partition(|p| p.path == file);
            for w in weaker {
                hit.detail = format!("{} Also: {}", hit.detail, w.title);
            }
            plain = rest;
            plain.insert(0, hit);
        }
    }
    plain
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
        out.extend(filetype::file_type(path, name)); // packages ship .cmd shims and the like
    }
    if let Some(content) = content.filter(|_| !PROSE.contains(&ext(name).as_str())) {
        out.extend(markers::check(path, content));
    }
    if git_rel(path).is_none() {
        out.extend(campaigns::check(path, content));
    }
    let handled = out.len();

    if let Some(rel) = git_rel(path) {
        if let Some(hook) = rel.strip_prefix("hooks/") {
            out.extend(git::hook(path, hook, entry.mode, content));
        } else if rel == "config" {
            out.extend(git::config(path, content.unwrap_or_default()));
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
        if vscode::FOLDER_OPEN.is_match(content) {
            let commands = vscode::folder_open_commands(content);
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
        out.extend(ai::claude_settings(path, content));
    } else if name == ".mcp.json" || (name == "mcp.json" && (parent == ".cursor" || parent == ".vscode")) {
        out.extend(ai::mcp_servers(path, content));
    } else if name == "package.json" {
        out.extend(npm::scripts(path, content));
    } else if name == ".envrc" {
        out.push(finding(
            Level::Check,
            path,
            "This runs commands when a terminal is opened in the folder, if direnv is installed.",
            format!("direnv asks once before running it.{}", describe(&signs(content))),
        ));
    } else if out.len() == handled && !in_node_modules(path) {
        out.extend(script::script(path, name, content));
    }
    out
}
