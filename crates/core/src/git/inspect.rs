//! Lists a repository's branches and tags, and the files on them that differ from the checked-out
//! commit, reading the ones the checks care about.
use super::*;
use std::collections::{BTreeMap, HashSet};

/// Files compared per repository, so a giant monorepo with many branches stays quick.
pub(super) const MAX_ENTRIES: usize = 200_000;

/// What a repository holds: its branches and tags, and what couldn't be checked.
pub(crate) struct Inspected {
    pub head: Option<String>,
    pub branches: Vec<String>,
    pub tags: Vec<String>,
    pub note: Option<String>,
    pub files: Vec<BranchFile>,
}

/// A file on one or more branches that isn't the same in the checked-out commit.
pub(crate) struct BranchFile {
    pub refs: Vec<String>,
    pub path: String,
    pub mode: u32,
    /// Read only when `wants_content` asked for it; a link's target otherwise.
    pub content: Option<Vec<u8>>,
}

/// Which files differ on which branches, found from the trees alone (no file contents yet).
pub(super) struct Plan {
    out: Inspected,
    order: Vec<(String, Oid, u32)>,
    seen: BTreeMap<(String, Oid, u32), Vec<String>>,
    problems: Vec<String>,
    budget: usize,
}

pub(super) fn plan(store: &mut Store, files: &Files) -> Plan {
    let (refs, head_ref, head_oid) = read_refs(files);
    let mut out = Inspected { head: None, branches: vec![], tags: vec![], note: None, files: vec![] };
    let mut problems = Vec::new();

    out.head = match (&head_ref, head_oid) {
        (Some(r), _) => Some(short_ref(r)),
        (None, Some(oid)) => Some(format!("a detached commit ({})", &hex(&oid)[..7])),
        _ => None,
    };
    for name in refs.keys() {
        if let Some(tag) = name.strip_prefix("refs/tags/") {
            out.tags.push(tag.to_string());
        } else {
            out.branches.push(short_ref(name));
        }
    }
    // The checked-out branch first, then local branches, then remote-tracking ones.
    out.branches.sort_by_key(|b| (Some(b) != out.head.as_ref(), b.contains('/'), b.clone()));

    // The baseline every other ref is compared against: the checked-out commit's files.
    let head_tree = head_oid.and_then(|oid| store.tree_of(oid));
    let mut seen: BTreeMap<(String, Oid, u32), Vec<String>> = BTreeMap::new();
    let mut order = Vec::new();
    let mut budget = MAX_ENTRIES;
    let mut targets: Vec<(String, Oid)> = Vec::new();
    if let (Some(oid), Some(name)) = (head_oid, out.head.clone()) {
        targets.push((name, oid));
    }
    for (name, oid) in &refs {
        let label = label(name);
        if Some(&label) != out.head.as_ref() {
            targets.push((label, *oid));
        }
    }
    for (i, (label, oid)) in targets.iter().enumerate() {
        let Some(tree) = store.tree_of(*oid) else {
            problems.push(label.clone());
            continue;
        };
        // The checked-out commit is read in full; everything else only where it differs from it.
        let base = if i == 0 && head_oid.is_some() { None } else { head_tree };
        let mut found = Vec::new();
        if !store.walk(tree, base, "", &mut found, &mut budget) {
            problems.push(label.clone());
        }
        for (path, oid, mode) in found {
            let key = (path, oid, mode);
            if !seen.contains_key(&key) {
                order.push(key.clone());
            }
            seen.entry(key).or_default().push(label.clone());
        }
    }
    Plan { out, order, seen, problems, budget }
}

pub(crate) fn inspect(files: &Files, wants_content: impl Fn(&str) -> bool) -> Inspected {
    let mut store = Store::new(files);
    let Plan { mut out, order, mut seen, mut problems, budget } = plan(&mut store, files);
    for key in order {
        let (path, oid, mode) = key.clone();
        let refs = seen.remove(&key).unwrap_or_default();
        let content = if mode == 0o120000 || wants_content(&path) {
            let blob = store.blob(oid);
            if blob.is_none() {
                // A file the checks need but can't read: say so, rather than pass it as clean.
                problems.push(format!("{path} on {}", refs.join(", ")));
            }
            blob
        } else {
            None
        };
        out.files.push(BranchFile { refs, path, mode, content });
    }
    if budget == 0 {
        out.note = Some("It has too many files to compare every branch, so some weren't checked.".into());
    } else if !problems.is_empty() {
        let more = problems.len().saturating_sub(8);
        out.note = Some(format!(
            "Some of its data is missing or unreadable, so these weren't checked: {}{}.",
            problems.iter().take(8).cloned().collect::<Vec<_>>().join(", "),
            if more > 0 { format!(", and {more} more") } else { String::new() }
        ));
    }
    out
}

/// The ids (in hex) of the files the checks would read, for fetching just those from a remote.
pub(crate) fn needed(files: &Files, wants_content: impl Fn(&str) -> bool) -> Vec<String> {
    let mut store = Store::new(files);
    let mut once = HashSet::new();
    plan(&mut store, files)
        .order
        .iter()
        .filter(|(path, _, mode)| *mode == 0o120000 || wants_content(path))
        .filter(|(_, oid, _)| once.insert(*oid))
        .map(|(_, oid, _)| hex(oid))
        .collect()
}

/// Every file on a branch or tag: (path, mode), up to `limit`.
pub(crate) fn list(files: &Files, branch: &str, limit: usize) -> Vec<(String, u32)> {
    let mut store = Store::new(files);
    let Some(tree) = resolve(files, branch).and_then(|oid| store.tree_of(oid)) else { return vec![] };
    let mut found = Vec::new();
    let mut budget = limit;
    store.walk(tree, None, "", &mut found, &mut budget);
    found.into_iter().map(|(path, _, mode)| (path, mode)).collect()
}

/// One file's contents on a branch or tag; a link's target for a link.
pub(crate) fn read(files: &Files, branch: &str, path: &str) -> Option<Vec<u8>> {
    let mut store = Store::new(files);
    let mut oid = store.tree_of(resolve(files, branch)?)?;
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        let (TREE, data) = store.get(oid)? else { return None };
        let (mode, _, next) = parse_tree(&data).into_iter().find(|(_, name, _)| name == part.as_bytes())?;
        let last = i == parts.len() - 1;
        if last && mode == 0o40000 || !last && mode != 0o40000 {
            return None;
        }
        oid = next;
    }
    store.blob(oid)
}
