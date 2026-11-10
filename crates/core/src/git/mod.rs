//! Reads a repository's branches straight from Git's data files, without running Git. A hostile
//! repo can make Git itself run code (hooks, a pager, fsmonitor), so nothing here calls it.
//!
//! For each branch and tag it lists the files that differ from the checked-out commit, and reads
//! the ones the checks care about. Every read is bounds-checked: the bytes come from a stranger.

use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

mod bundle;
mod inspect;
mod pack;
mod refs;
mod store;

pub(crate) use bundle::{bundle, refs_to_files};
pub(crate) use inspect::{inspect, list, needed, read};
use pack::*;
use refs::*;
use store::*;

type Oid = [u8; 20];

/// Git data held per repository: in memory for an archive, as paths for a folder on disk.
pub(crate) enum Source {
    Mem(Rc<Vec<u8>>),
    Disk(PathBuf),
}

/// Bytes of Git data kept per repository from an archive, so a huge pack can't exhaust memory.
pub(crate) const MAX_REPO_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct Files {
    /// Keyed by the path inside the .git folder: "HEAD", "refs/heads/main", "objects/pack/x.pack".
    map: HashMap<String, Source>,
    bytes: u64,
    pub too_big: bool,
    /// Why not everything in it can be checked, when it came from a bundle or a remote.
    pub note: Option<String>,
    /// A limit LookFirst chose, rather than data it couldn't read: shown, but not a finding.
    pub limit: Option<String>,
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
