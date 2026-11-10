//! Walks whatever is being scanned (archive, folder, file, bundle, remote) and checks each entry.

use crate::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read, Seek};
use std::path::Path;
use std::rc::Rc;

mod archives;
mod folder;
mod repos;

/// One file, folder or link inside whatever is being scanned.
pub(crate) struct Entry {
    pub path: String,
    pub kind: Kind,
    /// Unix permissions, when the archive records them.
    pub mode: Option<u32>,
    pub size: u64,
    pub encrypted: bool,
}

#[derive(PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Dir,
    Link(String),
}

/// What a walk collects besides the findings.
#[derive(Default)]
pub(crate) struct Want {
    pub list: bool,
    /// A file to capture for the viewer.
    pub target: Option<String>,
    /// A repository (as Repo::path shows it) whose Git data to keep for browsing its branches.
    pub repo: Option<String>,
}

pub(crate) struct Walked {
    pub report: Report,
    pub view: View,
    pub repo: Option<git::Files>,
}

pub(crate) fn walk(path: &Path, want: Want) -> Walked {
    let mut report = Report { source: path.display().to_string(), ..Default::default() };
    let mut scan = Scan::new(&mut report, want);
    let result = if path.is_dir() {
        scan.folder(path, path)
    } else {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        File::open(path).and_then(|f| scan.reader(BufReader::new(f), &name))
    };
    scan.branches();
    let (view, repo) = (scan.view.take(), scan.kept.take());
    if let Err(e) = result {
        report.errors.push(format!("{}: {e}", path.display()));
    }
    report.findings.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.path.cmp(&b.path)));
    Walked { report, view: view.unwrap_or(View::Missing), repo }
}

pub(crate) struct Scan<'a> {
    report: &'a mut Report,
    /// "outer.zip › " while inside a nested archive.
    prefix: String,
    depth: usize,
    /// Findings reported once per thing, like a macOS app bundle with many files in it.
    seen: std::collections::HashSet<String>,
    /// Each repository's Git data, keyed by its .git folder, read once the walk is done.
    repos: BTreeMap<String, git::Files>,
    /// Repositories with no folder on disk (a bundle, or a remote): their files are on their branches only.
    bare: std::collections::HashSet<String>,
    want: Want,
    view: Option<View>,
    kept: Option<git::Files>,
}

enum Format {
    Zip,
    SevenZ,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Rar,
    Bundle,
    Other,
}

fn sniff(head: &[u8]) -> Format {
    match head {
        [b'P', b'K', 3 | 5 | 7, 4 | 6 | 8, ..] => Format::Zip,
        [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, ..] => Format::SevenZ,
        [0x1F, 0x8B, ..] => Format::Gzip,
        [b'B', b'Z', b'h', ..] => Format::Bzip2,
        [0xFD, b'7', b'z', b'X', b'Z', 0, ..] => Format::Xz,
        [b'R', b'a', b'r', b'!', 0x1A, 0x07, ..] => Format::Rar,
        _ if head.starts_with(b"# v2 git bundle\n") || head.starts_with(b"# v3 git bundle\n") => Format::Bundle,
        _ if head.len() > 262 && &head[257..262] == b"ustar" => Format::Tar,
        _ => Format::Other,
    }
}

pub(crate) fn remote(url: &str, token: Option<&str>, allow_http: bool) -> Report {
    let mut report = Report { source: url.to_string(), ..Default::default() };
    match remote::fetch(url, token, allow_http) {
        Ok((name, files)) => {
            let mut scan = Scan::new(&mut report, Want::default());
            scan.add_bare(&format!("{name}/.git"), files);
            scan.branches();
        }
        Err(e) => report.errors.push(format!("{url}: {e}")),
    }
    report.findings.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.path.cmp(&b.path)));
    report
}

impl<'a> Scan<'a> {
    pub(crate) fn new(report: &'a mut Report, want: Want) -> Self {
        Scan {
            report,
            prefix: String::new(),
            depth: 0,
            seen: Default::default(),
            repos: BTreeMap::new(),
            bare: Default::default(),
            want,
            view: None,
            kept: None,
        }
    }
}

impl Scan<'_> {
    /// Works out what the bytes are from their first few hundred, not from the file name.
    pub(super) fn reader<R: Read + Seek>(&mut self, mut src: BufReader<R>, name: &str) -> io::Result<()> {
        let head = src.fill_buf()?.to_vec();
        match sniff(&head) {
            Format::Zip => self.zip(src),
            Format::SevenZ => self.sevenz(src),
            Format::Tar => self.tar(src),
            Format::Gzip => self.compressed(flate2::bufread::MultiGzDecoder::new(src), name, ".gz"),
            Format::Bzip2 => self.compressed(bzip2::bufread::MultiBzDecoder::new(src), name, ".bz2"),
            Format::Xz => {
                // ponytail: lzma-rs has no streaming xz reader, so it decompresses into memory,
                // capped at 1 GB; switch to a streaming decoder if real packs get bigger.
                let mut out = Vec::new();
                lzma_rs::xz_decompress(&mut BufReader::new(src.take(1 << 30)), &mut out)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                self.compressed(Cursor::new(out), name, ".xz")
            }
            Format::Bundle => self.bundle(src, name),
            Format::Rar => {
                self.add(rules::cant_open(name, "it's a RAR archive, which LookFirst can't read yet"));
                Ok(())
            }
            Format::Other => {
                // A single file, not an archive: check it like any file inside one.
                let mut data = Vec::new();
                src.take(MAX_READ).read_to_end(&mut data)?;
                let entry = Entry {
                    path: name.to_string(),
                    kind: Kind::File,
                    mode: None,
                    size: data.len() as u64,
                    encrypted: false,
                };
                self.visit(&entry, Some(&data));
                Ok(())
            }
        }
    }

    /// Reads what the checks need (often nothing), then checks the entry.
    pub(super) fn read_and_visit(&mut self, entry: &Entry, data: &mut dyn Read) -> io::Result<()> {
        let clean = entry.path.replace('\\', "/");
        if self.view.is_none()
            && self.want.target.as_deref() == Some(&format!("{}{}", self.prefix, clean.trim_start_matches("./")))
        {
            // The file the viewer asked for.
            self.view = Some(match &entry.kind {
                Kind::Link(target) => View::Link { target: target.clone() },
                Kind::Dir => View::Missing,
                Kind::File => {
                    let mut bytes = Vec::new();
                    data.take(MAX_VIEW as u64 + 1).read_to_end(&mut bytes)?;
                    view_of(bytes, Some(entry.size))
                }
            });
            self.visit(entry, None);
            return Ok(());
        }
        if entry.kind != Kind::File {
            self.visit(entry, None);
            return Ok(());
        }
        if let Some((dir, rel)) = rules::split_git(clean.trim_start_matches("./")).filter(|(_, rel)| git::wants(rel)) {
            // Git's data: kept for reading the branches once the whole archive has been seen.
            let files = self.repos.entry(dir.to_string()).or_default();
            if files.room_for(entry.size) {
                let mut bytes = Vec::new();
                data.take(git::MAX_REPO_BYTES).read_to_end(&mut bytes)?;
                files.add(rel, git::Source::Mem(Rc::new(bytes)));
            } else {
                files.too_big = true;
            }
            self.visit(entry, None);
            return Ok(());
        }
        if rules::is_archive(&entry.path) && entry.size <= MAX_NESTED {
            self.report.files += 1;
            let mut bytes = Vec::new();
            data.take(MAX_NESTED).read_to_end(&mut bytes)?;
            return self.nested(&entry.path, bytes);
        }
        let content = if rules::wants_content(&entry.path, entry.size) {
            let mut bytes = Vec::new();
            let cap = if campaigns::needs_whole(&entry.path) { MAX_WHOLE } else { MAX_READ };
            data.take(cap).read_to_end(&mut bytes)?;
            Some(bytes)
        } else {
            None
        };
        self.visit(entry, content.as_deref());
        Ok(())
    }

    pub(super) fn nested(&mut self, name: &str, bytes: Vec<u8>) -> io::Result<()> {
        if self.depth >= MAX_DEPTH {
            self.add(rules::cant_open(name, "it's an archive nested too deep inside others"));
            return Ok(());
        }
        let inside = format!("{}{name} › ", self.prefix);
        let outer = std::mem::replace(&mut self.prefix, inside);
        self.depth += 1;
        let short = name.rsplit('/').next().unwrap_or(name).to_string();
        let outer_repos = std::mem::take(&mut self.repos);
        let result = self.reader(BufReader::new(Cursor::new(bytes)), &short);
        self.branches();
        self.repos = outer_repos;
        self.depth -= 1;
        self.prefix = outer;
        if let Err(e) = result {
            // A file that only looked like an archive is worth a note, not a failed scan.
            self.add(rules::cant_open(name, &format!("it couldn't be read ({e})")));
        }
        Ok(())
    }

    pub(super) fn visit(&mut self, entry: &Entry, content: Option<&[u8]>) {
        if entry.kind == Kind::File {
            self.report.files += 1;
        }
        let path = entry.path.replace('\\', "/");
        let path = path.trim_start_matches("./");
        if rules::in_git_dir(path) {
            self.report.has_git = true;
        }
        if self.want.list {
            if self.report.entries.len() < MAX_LIST {
                let kind = match entry.kind {
                    Kind::File => "file",
                    Kind::Dir => "dir",
                    Kind::Link(_) => "link",
                };
                let path = format!("{}{}", self.prefix, path.trim_end_matches('/'));
                self.report.entries.push(Node { path, kind, size: entry.size });
            } else {
                self.report.entries_truncated = true;
            }
        }
        for finding in rules::check(path, entry, content, &mut self.seen) {
            self.add(finding);
        }
    }

    pub(super) fn add(&mut self, mut finding: Finding) {
        finding.path = format!("{}{}", self.prefix, finding.path);
        self.report.findings.push(finding);
    }
}
