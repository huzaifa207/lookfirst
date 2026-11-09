use super::*;

/// Archives LookFirst opens when it finds them inside another (docx, jar and apk are zips too,
/// but they're documents and programs, not packs of files).
pub(super) const ARCHIVES: &[&str] = &["zip", "tar", "tgz", "gz", "tbz2", "bz2", "txz", "xz", "7z", "rar"];
pub(super) const BINARY: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "icns", "bmp", "tiff", "psd", "ai", "sketch", "fig", "mp3", "mp4",
    "mov", "wav", "avi", "webm", "pdf", "ttf", "otf", "woff", "woff2", "eot", "so", "dylib", "dll", "wasm", "class",
    "pyc", "o", "a", "lib", "node", "sqlite", "db",
];

pub(super) fn ext(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

pub(super) fn segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|s| !s.is_empty())
}

/// The part of the path after a `.git/` folder, if it's inside one.
pub(super) fn git_rel(path: &str) -> Option<&str> {
    if let Some(rest) = path.strip_prefix(".git/") {
        return Some(rest);
    }
    path.find("/.git/").map(|i| &path[i + 6..])
}

pub(crate) fn in_git_dir(path: &str) -> bool {
    path == ".git" || path.ends_with("/.git") || git_rel(path).is_some()
}

pub(super) fn in_node_modules(path: &str) -> bool {
    segments(path).any(|s| s == "node_modules")
}

/// Splits a path inside a .git folder into the folder and the rest: ("pack/.git", "HEAD").
pub(crate) fn split_git(path: &str) -> Option<(&str, &str)> {
    if let Some(rest) = path.strip_prefix(".git/") {
        return Some((".git", rest));
    }
    path.find("/.git/").map(|i| (&path[..i + 5], &path[i + 6..]))
}

/// Files on other branches whose contents the checks read. Everything else is checked by name.
pub(crate) fn wants_branch_content(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let parent = path.rsplit('/').nth(1).unwrap_or("");
    (name == "tasks.json" && parent == ".vscode")
        || name.ends_with(".code-workspace")
        || (parent == ".claude" && name.starts_with("settings"))
        || name == ".mcp.json"
        || name == "mcp.json"
        || (name == "package.json" && !in_node_modules(path))
        || name == ".envrc"
        || segments(path).any(|s| s == ".githooks" || s == ".husky")
        || campaigns::wants(path)
        || name == ".gitignore"
        || path.contains(".github/workflows/")
        || name.contains(".config.")
        || name.starts_with(".eslintrc")
}

pub(crate) fn is_archive(path: &str) -> bool {
    ARCHIVES.contains(&ext(path).as_str())
}

pub(crate) fn wants_content(path: &str, size: u64) -> bool {
    if size == 0 || git_rel(path).is_some_and(|rel| rel.starts_with("objects/")) {
        return false;
    }
    if in_node_modules(path) {
        return campaigns::wants(path); // package.json, lockfiles and the worm's files
    }
    !BINARY.contains(&ext(path).as_str())
}

/// Whether a link inside the folder points outside it.
pub(super) fn escapes(path: &str, target: &str) -> bool {
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
