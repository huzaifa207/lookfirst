//! What a scan finds, as the CLI and the app show it.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Worth a look before opening, but common in normal projects too.
    Check,
    /// Runs code on an ordinary action (opening the folder, switching branches, installing), or
    /// pretends to be something it isn't.
    Danger,
}

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub level: Level,
    /// Where it is: "pack/.git/hooks/post-checkout", or "outer.zip › inner/file" when nested.
    pub path: String,
    /// One sentence anyone can read.
    pub title: String,
    /// The technical detail, for whoever checks it next.
    pub detail: String,
    /// The branches or tags it's on, when it isn't in the files as they are now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// The known campaign it matches, like "the Shai-Hulud npm worm".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign: Option<String>,
}

/// A file, folder or link inside, for browsing.
#[derive(Serialize, Clone, Debug)]
pub struct Node {
    /// As findings show it: "pack/src/app.js", or "outer.zip › inner/file".
    pub path: String,
    /// "file", "dir" or "link".
    pub kind: &'static str,
    pub size: u64,
}

/// One file, ready to show. Text is only ever shown, never rendered or run.
#[derive(Serialize, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum View {
    Text { text: String, truncated: bool },
    Binary { size: u64 },
    Link { target: String },
    Missing,
}

/// Where a file to show lives: in the files as they are now, or on a branch of a repository.
#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Location {
    File { path: String },
    Branch { repo: String, branch: String, path: String },
}

#[derive(Default, Clone, Copy)]
pub struct Options {
    /// Also list every entry, for browsing.
    pub list: bool,
}

/// A Git repository found inside, and what's on its branches.
#[derive(Serialize, Clone, Debug)]
pub struct Repo {
    /// Its .git folder: "pack/.git".
    pub path: String,
    /// The checked-out branch, or a note that it's a detached commit.
    pub head: Option<String>,
    /// Local branches, then remote-tracking ones ("origin/dev").
    pub branches: Vec<String>,
    pub tags: Vec<String>,
    /// Why some branches couldn't be checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing known was found. Not a promise that it's safe.
    Clear,
    Check,
    Danger,
    /// It couldn't be read at all.
    Unreadable,
}

#[derive(Serialize, Debug, Default)]
pub struct Report {
    pub source: String,
    pub files: usize,
    /// It contains a Git repository's own folder, which is where hooks and settings live.
    pub has_git: bool,
    /// Every Git repository inside, with its branches and tags.
    pub repos: Vec<Repo>,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
    /// Every entry, when asked for with `Options::list`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<Node>,
    /// The listing stopped at MAX_LIST entries.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub entries_truncated: bool,
}

impl Report {
    pub fn verdict(&self) -> Verdict {
        match self.findings.iter().map(|f| f.level).max() {
            Some(Level::Danger) => Verdict::Danger,
            Some(Level::Check) => Verdict::Check,
            None if !self.errors.is_empty() => Verdict::Unreadable,
            None => Verdict::Clear,
        }
    }
}
