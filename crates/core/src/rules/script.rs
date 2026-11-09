use super::*;

/// Files the general "downloads and runs" check reads. Files with no extension count when they
/// start with a #! line.
pub(super) const SCRIPTS: &[&str] =
    &["sh", "bash", "zsh", "command", "ps1", "bat", "cmd", "py", "rb", "pl", "js", "mjs", "cjs", "ts", "mts", "cts"];

/// Any other script: flag only the alarming combination, since normal code downloads things and
/// runs things all the time, just rarely both at once.
pub(super) fn script(path: &str, name: &str, content: &[u8]) -> Option<Finding> {
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
    if minified {
        return None;
    }
    if !alarming(content) {
        // Code pushed off the right edge of an editor by a long run of spaces.
        return campaigns::HIDDEN_AFTER_SPACES.is_match(content).then(|| {
            finding(
                Level::Check,
                path,
                "Code here is pushed off-screen by a long run of spaces.",
                "An editor shows the start of the line and hides the rest past the right edge. Look at the whole line.",
            )
        });
    }
    Some(finding(
        Level::Check,
        path,
        "This script downloads something and runs it.",
        format!("Fine in an installer you trust; a red flag in a pack of documents.{}", describe(&signs(content))),
    ))
}
