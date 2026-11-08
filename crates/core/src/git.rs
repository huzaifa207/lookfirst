//! Reads a repository's branches straight from Git's data files, without running Git. A hostile
//! repo can make Git itself run code (hooks, a pager, fsmonitor), so nothing here calls it.
//!
//! For each branch and tag it lists the files that differ from the checked-out commit, and reads
//! the ones the checks care about. Every read is bounds-checked: the bytes come from a stranger.

use flate2::read::ZlibDecoder;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::PathBuf;
use std::rc::Rc;

type Oid = [u8; 20];

/// Git data held per repository: in memory for an archive, as paths for a folder on disk.
pub(crate) enum Source {
    Mem(Rc<Vec<u8>>),
    Disk(PathBuf),
}

/// Bytes of Git data kept per repository from an archive, so a huge pack can't exhaust memory.
pub(crate) const MAX_REPO_BYTES: u64 = 512 * 1024 * 1024;
/// A single object bigger than this isn't a hook or a settings file, so it's never inflated.
const MAX_OBJECT: u64 = 32 * 1024 * 1024;
/// Files compared per repository, so a giant monorepo with many branches stays quick.
const MAX_ENTRIES: usize = 200_000;
const MAX_DELTA_DEPTH: usize = 1000;

#[derive(Default)]
pub(crate) struct Files {
    /// Keyed by the path inside the .git folder: "HEAD", "refs/heads/main", "objects/pack/x.pack".
    map: HashMap<String, Source>,
    bytes: u64,
    pub too_big: bool,
}

impl Files {
    pub fn room_for(&self, size: u64) -> bool {
        self.bytes + size <= MAX_REPO_BYTES
    }

    pub fn add(&mut self, rel: &str, source: Source) {
        if let Source::Mem(data) = &source {
            self.bytes += data.len() as u64;
        }
        self.map.insert(rel.to_string(), source);
    }

    fn load(&self, rel: &str) -> Option<Rc<Vec<u8>>> {
        match self.map.get(rel)? {
            Source::Mem(data) => Some(data.clone()),
            Source::Disk(path) => std::fs::read(path).ok().map(Rc::new),
        }
    }
}

/// Whether a file inside .git is one the branch reader needs.
pub(crate) fn wants(rel: &str) -> bool {
    rel == "HEAD"
        || rel == "packed-refs"
        || rel.starts_with("refs/")
        || (rel.starts_with("objects/") && !rel.starts_with("objects/info/"))
}

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

pub(crate) fn inspect(files: &Files, wants_content: impl Fn(&str) -> bool) -> Inspected {
    let mut store = Store::new(files);
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
        out.note = Some(format!(
            "Some of its data is missing or unreadable, so these weren't checked: {}.",
            problems.join(", ")
        ));
    }
    out
}

/// The label a ref goes by in findings and the branch picker: "main", "origin/dev", "tag v1".
fn label(name: &str) -> String {
    name.strip_prefix("refs/tags/").map(|t| format!("tag {t}")).unwrap_or_else(|| short_ref(name))
}

/// The commit a label points at.
fn resolve(files: &Files, wanted: &str) -> Option<Oid> {
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

fn short_ref(name: &str) -> String {
    let name = name.strip_prefix("refs/heads/").unwrap_or(name);
    name.strip_prefix("refs/remotes/").unwrap_or(name).to_string()
}

fn hex(oid: &Oid) -> String {
    oid.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex(text: &str) -> Option<Oid> {
    let text = text.get(..40)?;
    let mut oid = [0u8; 20];
    for (i, byte) in oid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(oid)
}

/// Branches, remote-tracking branches and tags, each pointing at a commit or tag object, plus
/// what HEAD points at.
fn read_refs(files: &Files) -> (BTreeMap<String, Oid>, Option<String>, Option<Oid>) {
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

struct Pack {
    data: Rc<Vec<u8>>,
}

struct Store<'a> {
    files: &'a Files,
    packs: Vec<Pack>,
    /// Where each packed object lives: which pack, and at what offset.
    index: HashMap<Oid, (usize, u64)>,
    cache: HashMap<(usize, u64), Object>,
}

/// An object's type and contents.
type Object = (u8, Rc<Vec<u8>>);

const COMMIT: u8 = 1;
const TREE: u8 = 2;
const BLOB: u8 = 3;
const TAG: u8 = 4;

impl<'a> Store<'a> {
    fn new(files: &'a Files) -> Self {
        let mut store = Store { files, packs: vec![], index: HashMap::new(), cache: HashMap::new() };
        let mut idxs: Vec<&String> = files.map.keys().filter(|k| k.ends_with(".idx")).collect();
        idxs.sort();
        for idx_name in idxs {
            let pack_name = format!("{}.pack", idx_name.trim_end_matches(".idx"));
            let (Some(idx), Some(data)) = (files.load(idx_name), files.load(&pack_name)) else { continue };
            let Some(entries) = parse_idx(&idx) else { continue };
            let p = store.packs.len();
            store.packs.push(Pack { data });
            for (oid, offset) in entries {
                store.index.entry(oid).or_insert((p, offset));
            }
        }
        store
    }

    fn get(&mut self, oid: Oid) -> Option<Object> {
        if let Some(&(p, offset)) = self.index.get(&oid) {
            return self.packed(p, offset, 0);
        }
        let h = hex(&oid);
        let raw = self.files.load(&format!("objects/{}/{}", &h[..2], &h[2..]))?;
        let data = inflate(&raw, MAX_OBJECT + 64)?;
        let nul = data.iter().position(|&b| b == 0)?;
        let header = std::str::from_utf8(&data[..nul]).ok()?;
        let kind = match header.split(' ').next()? {
            "commit" => COMMIT,
            "tree" => TREE,
            "blob" => BLOB,
            "tag" => TAG,
            _ => return None,
        };
        Some((kind, Rc::new(data[nul + 1..].to_vec())))
    }

    fn packed(&mut self, p: usize, offset: u64, depth: usize) -> Option<Object> {
        if let Some(hit) = self.cache.get(&(p, offset)) {
            return Some(hit.clone());
        }
        if depth > MAX_DELTA_DEPTH {
            return None;
        }
        let data = self.packs.get(p)?.data.clone();
        let mut i = usize::try_from(offset).ok()?;
        let mut byte = *data.get(i)?;
        i += 1;
        let kind = (byte >> 4) & 7;
        let mut size = u64::from(byte & 15);
        let mut shift = 4;
        while byte & 0x80 != 0 {
            byte = *data.get(i)?;
            i += 1;
            size |= u64::from(byte & 0x7f).checked_shl(shift)?;
            shift += 7;
        }
        if size > MAX_OBJECT {
            return None;
        }
        let object = match kind {
            COMMIT | TREE | BLOB | TAG => (kind, inflate(data.get(i..)?, size)?),
            6 => {
                // A delta against an object earlier in the same pack.
                let mut byte = *data.get(i)?;
                i += 1;
                let mut back = u64::from(byte & 0x7f);
                while byte & 0x80 != 0 {
                    byte = *data.get(i)?;
                    i += 1;
                    back = (back.checked_add(1)?.checked_shl(7)?) | u64::from(byte & 0x7f);
                }
                let (base_kind, base) = self.packed(p, offset.checked_sub(back)?, depth + 1)?;
                (base_kind, apply_delta(&base, &inflate(data.get(i..)?, size)?)?)
            }
            7 => {
                // A delta against an object named by its id.
                let base_oid: Oid = data.get(i..i + 20)?.try_into().ok()?;
                i += 20;
                let (base_kind, base) = match self.index.get(&base_oid) {
                    Some(&(bp, bo)) => self.packed(bp, bo, depth + 1)?,
                    None => self.get(base_oid)?,
                };
                (base_kind, apply_delta(&base, &inflate(data.get(i..)?, size)?)?)
            }
            _ => return None,
        };
        let object = (object.0, Rc::new(object.1));
        // ponytail: an unbounded count cap; switch to an LRU if very large repos get slow.
        if object.1.len() < 1 << 20 {
            if self.cache.len() > 50_000 {
                self.cache.clear();
            }
            self.cache.insert((p, offset), object.clone());
        }
        Some(object)
    }

    /// The tree a commit (or a tag pointing at one) records.
    fn tree_of(&mut self, mut oid: Oid) -> Option<Oid> {
        for _ in 0..10 {
            let (kind, data) = self.get(oid)?;
            let text = String::from_utf8_lossy(&data[..data.len().min(512)]).into_owned();
            match kind {
                COMMIT => return parse_hex(text.strip_prefix("tree ")?),
                TAG => oid = parse_hex(text.strip_prefix("object ")?)?,
                TREE => return Some(oid),
                _ => return None,
            }
        }
        None
    }

    fn blob(&mut self, oid: Oid) -> Option<Vec<u8>> {
        match self.get(oid)? {
            (BLOB, data) => Some(data.to_vec()),
            _ => None,
        }
    }

    /// Lists the files under `tree` that aren't identical in `base`, skipping whole folders that
    /// are. False if part of it couldn't be read.
    fn walk(
        &mut self,
        tree: Oid,
        base: Option<Oid>,
        prefix: &str,
        out: &mut Vec<(String, Oid, u32)>,
        budget: &mut usize,
    ) -> bool {
        if Some(tree) == base {
            return true;
        }
        let Some((TREE, data)) = self.get(tree) else { return false };
        let base_entries: HashMap<Vec<u8>, (u32, Oid)> = match base.and_then(|b| self.get(b)) {
            Some((TREE, b)) => parse_tree(&b).into_iter().map(|(m, n, o)| (n, (m, o))).collect(),
            _ => HashMap::new(),
        };
        let mut ok = true;
        for (mode, name, oid) in parse_tree(&data) {
            if *budget == 0 {
                return ok;
            }
            *budget -= 1;
            let name_str = String::from_utf8_lossy(&name).into_owned();
            let path = format!("{prefix}{name_str}");
            let in_base = base_entries.get(&name).copied();
            match mode {
                0o40000 => {
                    let sub_base = in_base.filter(|(m, _)| *m == 0o40000).map(|(_, o)| o);
                    ok &= self.walk(oid, sub_base, &format!("{path}/"), out, budget);
                }
                0o160000 => {} // a submodule: another repository, not files here
                _ if in_base == Some((mode, oid)) => {}
                _ => out.push((path, oid, mode)),
            }
        }
        ok
    }
}

fn inflate(data: &[u8], size: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    ZlibDecoder::new(data).take(size.saturating_add(1)).read_to_end(&mut out).ok()?;
    Some(out)
}

/// A tree's entries: (mode, name, id).
fn parse_tree(data: &[u8]) -> Vec<(u32, Vec<u8>, Oid)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let Some(space) = data[i..].iter().position(|&b| b == b' ') else { break };
        let Some(nul) = data[i + space..].iter().position(|&b| b == 0) else { break };
        let mode = std::str::from_utf8(&data[i..i + space]).ok().and_then(|m| u32::from_str_radix(m, 8).ok());
        let name = data[i + space + 1..i + space + nul].to_vec();
        let start = i + space + nul + 1;
        let Some(oid) = data.get(start..start + 20).and_then(|o| <Oid>::try_from(o).ok()) else { break };
        if let Some(mode) = mode {
            out.push((mode, name, oid));
        }
        i = start + 20;
    }
    out
}

/// A version 2 pack index: every object id in the pack and its offset.
fn parse_idx(idx: &[u8]) -> Option<Vec<(Oid, u64)>> {
    let u32_at = |at: usize| idx.get(at..at + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap()));
    if idx.get(..4)? != b"\xfftOc" || u32_at(4)? != 2 {
        return None; // version 1 indexes predate 2008
    }
    let count = u32_at(8 + 255 * 4)? as usize;
    let ids = 8 + 256 * 4;
    let offsets = ids + count.checked_mul(24)?; // ids (20 bytes each), then CRCs (4)
    let large = offsets + count * 4;
    let mut out = Vec::with_capacity(count.min(1 << 24));
    for k in 0..count {
        let oid: Oid = idx.get(ids + k * 20..ids + k * 20 + 20)?.try_into().ok()?;
        let small = u32_at(offsets + k * 4)?;
        let offset = if small & 0x8000_0000 != 0 {
            let at = large + (small & 0x7fff_ffff) as usize * 8;
            u64::from_be_bytes(idx.get(at..at + 8)?.try_into().ok()?)
        } else {
            u64::from(small)
        };
        out.push((oid, offset));
    }
    Some(out)
}

fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    let mut varint = || -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *delta.get(i)?;
            i += 1;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
    };
    let base_size = varint()?;
    let result_size = varint()?;
    if base_size != base.len() as u64 || result_size > MAX_OBJECT {
        return None;
    }
    let mut out = Vec::with_capacity(result_size as usize);
    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op & 0x80 != 0 {
            // Copy a run from the base: which bytes follow depends on the bits set in `op`.
            let mut offset = 0usize;
            let mut len = 0usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    offset |= usize::from(*delta.get(i)?) << (bit * 8);
                    i += 1;
                }
            }
            for bit in 0..3 {
                if op & (0x10 << bit) != 0 {
                    len |= usize::from(*delta.get(i)?) << (bit * 8);
                    i += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            out.extend_from_slice(base.get(offset..offset.checked_add(len)?)?);
        } else if op != 0 {
            // Insert the next `op` bytes as they are.
            out.extend_from_slice(delta.get(i..i + usize::from(op))?);
            i += usize::from(op);
        } else {
            return None;
        }
    }
    (out.len() as u64 == result_size).then_some(out)
}
