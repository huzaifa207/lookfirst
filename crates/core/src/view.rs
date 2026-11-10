//! Files shown in the read-only viewer: text is shown, never opened or run.

use crate::{View, MAX_VIEW};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Text when it looks like text, cut off at MAX_VIEW; a size otherwise.
pub(crate) fn view_of(bytes: Vec<u8>, size: Option<u64>) -> View {
    let size = size.unwrap_or(0).max(bytes.len() as u64);
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return View::Binary { size };
    }
    let truncated = bytes.len() > MAX_VIEW;
    View::Text { text: String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_VIEW)]).into_owned(), truncated }
}

/// A file in a folder on disk, refusing any path that would leave the folder.
pub(crate) fn read_in_folder(root: &Path, inner: &str) -> View {
    let bad = inner.is_empty()
        || inner.starts_with('/')
        || inner.contains('\\')
        || inner.contains(':')
        || inner.split('/').any(|s| s == ".." || s.is_empty());
    if bad {
        return View::Missing;
    }
    let path = root.join(inner);
    let Ok(meta) = std::fs::symlink_metadata(&path) else { return View::Missing };
    if meta.file_type().is_symlink() {
        // Shown, never followed.
        return View::Link { target: std::fs::read_link(&path).map(|t| t.display().to_string()).unwrap_or_default() };
    }
    // A link in a parent folder could still lead outside, so compare the real locations.
    let (Ok(real), Ok(real_root)) = (path.canonicalize(), root.canonicalize()) else { return View::Missing };
    if !real.starts_with(&real_root) || !meta.is_file() {
        return View::Missing;
    }
    let mut bytes = Vec::new();
    match File::open(&real).and_then(|f| f.take(MAX_VIEW as u64 + 1).read_to_end(&mut bytes)) {
        Ok(_) => view_of(bytes, Some(meta.len())),
        Err(_) => View::Missing,
    }
}
