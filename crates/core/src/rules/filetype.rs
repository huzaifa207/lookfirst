use super::*;

/// Windows and macOS file types that run as programs when double-clicked.
pub(super) const PROGRAMS: &[&str] = &[
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
pub(super) const SNEAKY: &[&str] = &["scr", "hta", "vbs", "vbe", "jse", "wsf", "wsh", "lnk", "pif", "cpl", "msc"];
pub(super) const MACROS: &[&str] = &["docm", "dotm", "xlsm", "xltm", "pptm", "potm"];
pub(super) const DOCUMENTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "mp4", "mov",
];

pub(super) fn file_type(path: &str, name: &str) -> Option<Finding> {
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
