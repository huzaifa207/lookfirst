//! Branch and tag names, and what they point at.
use super::*;
use std::collections::BTreeMap;

/// The label a ref goes by in findings and the branch picker: "main", "origin/dev", "tag v1".
pub(super) fn label(name: &str) -> String {
    name.strip_prefix("refs/tags/").map(|t| format!("tag {t}")).unwrap_or_else(|| short_ref(name))
}

/// The commit a label points at.
pub(super) fn resolve(files: &Files, wanted: &str) -> Option<Oid> {
    let (refs, head_ref, head_oid) = read_refs(files);
    let head = match (&head_ref, head_oid) {
        (Some(r), _) => Some(short_ref(r)),
        (None, Some(oid)) => Some(format!("a detached commit ({})", &hex(&oid)[..7])),
        _ => None,
    };
    if head.as_deref() == Some(wanted) {
        return head_oid;
    }
    refs.iter().find(|(name, _)| label(name) == wanted).map(|(_, oid)| *oid)
}

pub(super) fn short_ref(name: &str) -> String {
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    name.strip_prefix("refs/remotes/").unwrap_or(name).to_string()
}

pub(super) fn hex(oid: &Oid) -> String {
    oid.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn parse_hex(text: &str) -> Option<Oid> {
    let text = text.get(..40)?;
    let mut oid = [0u8; 20];
    for (i, byte) in oid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(oid)
}

/// Branches, remote-tracking branches and tags, each pointing at a commit or tag object, plus
/// what HEAD points at.
pub(super) fn read_refs(files: &Files) -> (BTreeMap<String, Oid>, Option<String>, Option<Oid>) {
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    if let Some(packed) = files.load("packed-refs") {
        for line in String::from_utf8_lossy(&packed).lines() {
            if let Some((oid, name)) = line.split_once(' ') {
                if !line.starts_with('#') && !line.starts_with('^') {
                    raw.insert(name.trim().to_string(), oid.to_string());
                }
            }
        }
    }
    for rel in files.map.keys().filter(|k| k.starts_with("refs/")) {
        if let Some(data) = files.load(rel) {
            raw.insert(rel.clone(), String::from_utf8_lossy(&data).trim().to_string());
            // loose refs win
        }
    }
    let resolve = |mut value: String| -> (Option<String>, Option<Oid>) {
        let mut via = None;
        for _ in 0..5 {
            match value.strip_prefix("ref: ") {
                Some(target) => {
                    via = Some(target.trim().to_string());
                    match raw.get(target.trim()) {
                        Some(next) => value = next.clone(),
                        None => return (via, None),
                    }
                }
                None => return (via, parse_hex(value.trim())),
            }
        }
        (via, None)
    };
    let mut refs = BTreeMap::new();
    for (name, value) in &raw {
        let wanted =
            name.starts_with("refs/heads/") || name.starts_with("refs/tags/") || name.starts_with("refs/remotes/");
        if !wanted || name.ends_with("/HEAD") {
            continue; // origin/HEAD only points at another branch
        }
        if let (_, Some(oid)) = resolve(value.clone()) {
            refs.insert(name.clone(), oid);
        }
    }
    let head = files.load("HEAD").map(|d| String::from_utf8_lossy(&d).trim().to_string());
    let (head_ref, head_oid) = head.map(resolve).unwrap_or((None, None));
    (refs, head_ref, head_oid)
}
