//! LookFirst's scanner: finds the files in an archive or folder that run code without anyone
//! choosing to run them (Git hooks, Git settings, editor tasks, AI assistant hooks, install scripts),
//! programs dressed up as documents, and paths that escape the folder when extracted.
//!
//! It reads archives in place. Nothing is extracted, written, run, or sent anywhere.

mod campaigns;
mod git;
mod indicators;
mod remote;
mod report;
mod rules;
mod scan;
mod view;

pub use indicators::{list_info, update_list, ListInfo};
pub use remote::is_address;
pub use report::{Finding, Level, Location, Node, Options, Repo, Report, Verdict, View};

pub(crate) use scan::{Entry, Kind};
// Reached from the tests, which see the crate's private items.
#[cfg(test)]
use scan::remote as scan_remote;

use scan::{walk, Want};
use std::path::Path;
use view::{read_in_folder, view_of};

/// Bytes read from any one file. Hooks, settings and scripts are far smaller.
const MAX_READ: u64 = 4 * 1024 * 1024;
/// Lockfiles and the worm's files are read whole, so versions can be listed and hashes taken.
const MAX_WHOLE: u64 = 64 * 1024 * 1024;
/// An archive inside an archive is read into memory, so it gets a cap, and so does the nesting.
const MAX_NESTED: u64 = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 3;
/// Bytes of one file shown in the viewer; the rest is cut off with a note.
const MAX_VIEW: usize = 2 * 1024 * 1024;
/// Entries listed for browsing, so a folder full of node_modules can't flood the window.
const MAX_LIST: usize = 100_000;

/// Scans an archive (zip, tar, tar.gz/.bz2/.xz, 7z), a folder, or a single file.
pub fn scan_path(path: &Path) -> Report {
    scan_with(path, Options::default())
}

pub fn scan_with(path: &Path, options: Options) -> Report {
    walk(path, Want { list: options.list, ..Default::default() }).report
}

/// Checks a Git repository at an https or ssh address without cloning it: reads its branches and the
/// files the checks need over Git's own protocol, and never runs Git. A private repository needs an
/// access token (https; sent only to known hosts) or the user's ssh keys (ssh).
pub fn scan_url(url: &str, token: Option<&str>) -> Report {
    scan::remote(url, token, false)
}

/// One file's contents, for the viewer. From an archive it's read in memory, never extracted.
pub fn read_file(src: &Path, location: &Location) -> View {
    match location {
        Location::File { path } if src.is_dir() => read_in_folder(src, path),
        Location::File { path } => walk(src, Want { target: Some(path.clone()), ..Default::default() }).view,
        Location::Branch { repo, branch, path } => {
            let Some(files) = walk(src, Want { repo: Some(repo.clone()), ..Default::default() }).repo else {
                return View::Missing;
            };
            let root = repo.strip_suffix(".git").unwrap_or("");
            match git::read(&files, branch, path.strip_prefix(root).unwrap_or(path)) {
                Some(bytes) => view_of(bytes, None),
                None => View::Missing,
            }
        }
    }
}

/// Every file on one branch or tag of a repository, with paths as findings show them.
pub fn branch_files(src: &Path, repo: &str, branch: &str) -> Vec<Node> {
    let Some(files) = walk(src, Want { repo: Some(repo.to_string()), ..Default::default() }).repo else {
        return vec![];
    };
    let root = repo.strip_suffix(".git").unwrap_or("");
    git::list(&files, branch, MAX_LIST)
        .into_iter()
        .map(|(path, mode)| Node {
            path: format!("{root}{path}"),
            kind: if mode == 0o120000 { "link" } else { "file" },
            size: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests;
