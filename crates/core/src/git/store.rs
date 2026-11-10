//! Finds objects (commits, trees, files) in a repository's packs and loose files.
use super::*;
use std::collections::HashMap;
use std::rc::Rc;

pub(super) const MAX_DELTA_DEPTH: usize = 1000;

pub(super) struct Pack {
    data: Rc<Vec<u8>>,
}

pub(super) struct Store<'a> {
    files: &'a Files,
    packs: Vec<Pack>,
    /// Where each packed object lives: which pack, and at what offset.
    index: HashMap<Oid, (usize, u64)>,
    cache: HashMap<(usize, u64), Object>,
}

/// An object's type and contents.
pub(super) type Object = (u8, Rc<Vec<u8>>);

impl<'a> Store<'a> {
    pub(super) fn new(files: &'a Files) -> Self {
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
        // Packs that came without an index (a bundle, or a fetch): find their objects by reading through.
        let mut bare: Vec<&String> = files
            .map
            .keys()
            .filter(|k| {
                k.ends_with(".pack") && !files.map.contains_key(&format!("{}.idx", k.trim_end_matches(".pack")))
            })
            .collect();
        bare.sort();
        for name in bare {
            let Some(data) = files.load(name) else { continue };
            let p = store.packs.len();
            store.packs.push(Pack { data });
            store.index_pack(p);
        }
        store
    }

    /// Finds every object in a pack that has no index: where each starts, then what it hashes to.
    /// A delta against an object not seen yet waits for a later round.
    pub(super) fn index_pack(&mut self, p: usize) {
        let mut pending = pack_offsets(&self.packs[p].data);
        loop {
            let before = pending.len();
            pending.retain(|&offset| match self.packed(p, offset, 0) {
                Some((kind, body)) => {
                    self.index.entry(object_id(kind, &body)).or_insert((p, offset));
                    false
                }
                None => true,
            });
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
    }

    pub(super) fn get(&mut self, oid: Oid) -> Option<Object> {
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

    pub(super) fn packed(&mut self, p: usize, offset: u64, depth: usize) -> Option<Object> {
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
    pub(super) fn tree_of(&mut self, mut oid: Oid) -> Option<Oid> {
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

    pub(super) fn blob(&mut self, oid: Oid) -> Option<Vec<u8>> {
        match self.get(oid)? {
            (BLOB, data) => Some(data.to_vec()),
            _ => None,
        }
    }

    /// Lists the files under `tree` that aren't identical in `base`, skipping whole folders that
    /// are. False if part of it couldn't be read.
    pub(super) fn walk(
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
