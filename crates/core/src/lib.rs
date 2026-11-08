//! LookFirst's scanner: finds the files in an archive or folder that run code without anyone
//! choosing to run them (Git hooks, Git settings, editor tasks, AI assistant hooks, install scripts),
//! programs dressed up as documents, and paths that escape the folder when extracted.
//!
//! It reads archives in place. Nothing is extracted, written, run, or sent anywhere.

mod git;
mod rules;

use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Cursor, Read, Seek};
use std::path::Path;
use std::rc::Rc;

/// Bytes read from any one file. Hooks, settings and scripts are far smaller.
const MAX_READ: u64 = 4 * 1024 * 1024;
/// An archive inside an archive is read into memory, so it gets a cap, and so does the nesting.
const MAX_NESTED: u64 = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 3;

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

/// Scans an archive (zip, tar, tar.gz/.bz2/.xz, 7z), a folder, or a single file.
pub fn scan_path(path: &Path) -> Report {
    let mut report = Report { source: path.display().to_string(), ..Default::default() };
    let mut scan =
        Scan { report: &mut report, prefix: String::new(), depth: 0, seen: Default::default(), repos: BTreeMap::new() };
    let result = if path.is_dir() {
        scan.folder(path, path)
    } else {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        File::open(path).and_then(|f| scan.reader(BufReader::new(f), &name))
    };
    scan.branches();
    if let Err(e) = result {
        report.errors.push(format!("{}: {e}", path.display()));
    }
    report.findings.sort_by(|a, b| b.level.cmp(&a.level).then_with(|| a.path.cmp(&b.path)));
    report
}

struct Scan<'a> {
    report: &'a mut Report,
    /// "outer.zip › " while inside a nested archive.
    prefix: String,
    depth: usize,
    /// Findings reported once per thing, like a macOS app bundle with many files in it.
    seen: std::collections::HashSet<String>,
    /// Each repository's Git data, keyed by its .git folder, read once the walk is done.
    repos: BTreeMap<String, git::Files>,
}

enum Format {
    Zip,
    SevenZ,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    Rar,
    Other,
}

/// Permissions only mean something in a zip made on Unix. For one made on Windows the zip
/// library invents a mode with no execute bit, which would wrongly make a hook look switched off
/// (Git for Windows runs hooks either way).
fn unix_mode(system: zip::System, mode: Option<u32>) -> Option<u32> {
    if system == zip::System::Unix {
        mode
    } else {
        None
    }
}

fn sniff(head: &[u8]) -> Format {
    match head {
        [b'P', b'K', 3 | 5 | 7, 4 | 6 | 8, ..] => Format::Zip,
        [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C, ..] => Format::SevenZ,
        [0x1F, 0x8B, ..] => Format::Gzip,
        [b'B', b'Z', b'h', ..] => Format::Bzip2,
        [0xFD, b'7', b'z', b'X', b'Z', 0, ..] => Format::Xz,
        [b'R', b'a', b'r', b'!', 0x1A, 0x07, ..] => Format::Rar,
        _ if head.len() > 262 && &head[257..262] == b"ustar" => Format::Tar,
        _ => Format::Other,
    }
}

impl Scan<'_> {
    /// Works out what the bytes are from their first few hundred, not from the file name.
    fn reader<R: Read + Seek>(&mut self, mut src: BufReader<R>, name: &str) -> io::Result<()> {
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

    /// A .gz, .bz2 or .xz is usually a tar, but can be one compressed file.
    fn compressed(&mut self, dec: impl Read, name: &str, ext: &str) -> io::Result<()> {
        let mut src = BufReader::with_capacity(64 * 1024, dec);
        let head = src.fill_buf()?.to_vec();
        if let Format::Tar = sniff(&head) {
            return self.tar(src);
        }
        let inner = name.strip_suffix(ext).unwrap_or(name);
        let mut data = Vec::new();
        src.take(MAX_NESTED).read_to_end(&mut data)?;
        self.nested(inner, data)
    }

    fn zip<R: Read + Seek>(&mut self, src: R) -> io::Result<()> {
        let mut zip = zip::ZipArchive::new(src).map_err(io::Error::other)?;
        for i in 0..zip.len() {
            // Encrypted entries can't be opened, but their names can still be checked.
            if matches!(zip.by_index(i), Err(zip::result::ZipError::UnsupportedArchive(_))) {
                let raw = zip.by_index_raw(i).map_err(io::Error::other)?;
                let entry = Entry {
                    path: raw.name().map_err(io::Error::other)?.into_owned(),
                    kind: if raw.is_dir() { Kind::Dir } else { Kind::File },
                    mode: unix_mode(raw.system(), raw.unix_mode()),
                    size: raw.size(),
                    encrypted: true,
                };
                drop(raw);
                self.visit(&entry, None);
                continue;
            }
            let mut file = zip.by_index(i).map_err(io::Error::other)?;
            let path = file.name().map_err(io::Error::other)?.into_owned();
            let kind = if file.is_symlink() {
                let mut target = String::new();
                file.by_ref().take(4096).read_to_string(&mut target)?;
                Kind::Link(target)
            } else if file.is_dir() {
                Kind::Dir
            } else {
                Kind::File
            };
            let entry = Entry {
                path,
                kind,
                mode: unix_mode(file.system(), file.unix_mode()),
                size: file.size(),
                encrypted: false,
            };
            self.read_and_visit(&entry, &mut file)?;
        }
        Ok(())
    }

    fn tar<R: Read>(&mut self, src: R) -> io::Result<()> {
        let mut tar = tar::Archive::new(src);
        for item in tar.entries()? {
            let mut item = item?;
            let header = item.header();
            let kind = match header.entry_type() {
                t if t.is_dir() => Kind::Dir,
                t if t.is_symlink() || t.is_hard_link() => Kind::Link(
                    item.link_name_bytes().map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default(),
                ),
                t if t.is_file() || t.is_contiguous() => Kind::File,
                _ => continue, // pax headers, devices, fifos
            };
            let entry = Entry {
                path: String::from_utf8_lossy(&item.path_bytes()).into_owned(),
                kind,
                mode: header.mode().ok(),
                size: header.size().unwrap_or(0),
                encrypted: false,
            };
            self.read_and_visit(&entry, &mut item)?;
        }
        Ok(())
    }

    fn sevenz<R: Read + Seek>(&mut self, src: R) -> io::Result<()> {
        let mut reader = match sevenz_rust2::ArchiveReader::new(src, sevenz_rust2::Password::empty()) {
            Ok(r) => r,
            Err(sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_)) => {
                self.add(rules::cant_open(
                    "this archive",
                    "it's password-protected, so its contents couldn't be checked",
                ));
                return Ok(());
            }
            Err(e) => return Err(io::Error::other(e.to_string())),
        };
        let mut failure = None;
        let result = reader.for_each_entries(|e, data| {
            // 7z keeps Unix permissions in the high 16 bits when this flag is set.
            let attrs = e.windows_attributes();
            let mode = (attrs & 0x8000 != 0).then_some(attrs >> 16);
            let kind = if e.is_directory() {
                Kind::Dir
            } else if mode.is_some_and(|m| m & 0o170000 == 0o120000) {
                let mut target = String::new();
                data.take(4096).read_to_string(&mut target)?;
                Kind::Link(target)
            } else {
                Kind::File
            };
            let entry = Entry { path: e.name().to_string(), kind, mode, size: e.size(), encrypted: false };
            if let Err(err) = self.read_and_visit(&entry, data) {
                failure = Some(err);
                return Ok(false);
            }
            Ok(true)
        });
        if let Some(err) = failure {
            return Err(err);
        }
        match result {
            Err(sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_)) => {
                self.add(rules::cant_open(
                    "this archive",
                    "it's password-protected, so its contents couldn't be checked",
                ));
                Ok(())
            }
            other => other.map_err(|e| io::Error::other(e.to_string())),
        }
    }

    fn folder(&mut self, root: &Path, dir: &Path) -> io::Result<()> {
        let mut items: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        items.sort_by_key(|i| i.file_name());
        for item in items {
            let path = item.path();
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
            let meta = std::fs::symlink_metadata(&path)?;
            #[cfg(unix)]
            let mode = Some(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()));
            #[cfg(not(unix))]
            let mode = None;
            let kind = if meta.file_type().is_symlink() {
                Kind::Link(std::fs::read_link(&path).map(|t| t.to_string_lossy().into_owned()).unwrap_or_default())
            } else if meta.is_dir() {
                Kind::Dir
            } else {
                Kind::File
            };
            let entry = Entry { path: rel, kind, mode, size: meta.len(), encrypted: false };
            match entry.kind {
                Kind::Dir => {
                    self.visit(&entry, None);
                    self.folder(root, &path)?;
                }
                Kind::File if rules::split_git(&entry.path).is_some_and(|(_, rel)| git::wants(rel)) => {
                    // On disk, Git's data is read later and one repository at a time.
                    let (dir, rel) = rules::split_git(&entry.path).unwrap();
                    self.repos.entry(dir.to_string()).or_default().add(rel, git::Source::Disk(path.clone()));
                    self.visit(&entry, None);
                }
                Kind::File => self.read_and_visit(&entry, &mut File::open(&path)?)?,
                Kind::Link(_) => self.visit(&entry, None),
            }
        }
        Ok(())
    }

    /// Reads what the checks need (often nothing), then checks the entry.
    fn read_and_visit(&mut self, entry: &Entry, data: &mut dyn Read) -> io::Result<()> {
        if entry.kind != Kind::File {
            self.visit(entry, None);
            return Ok(());
        }
        let clean = entry.path.replace('\\', "/");
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
            data.take(MAX_READ).read_to_end(&mut bytes)?;
            Some(bytes)
        } else {
            None
        };
        self.visit(entry, content.as_deref());
        Ok(())
    }

    fn nested(&mut self, name: &str, bytes: Vec<u8>) -> io::Result<()> {
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

    fn visit(&mut self, entry: &Entry, content: Option<&[u8]>) {
        if entry.kind == Kind::File {
            self.report.files += 1;
        }
        let path = entry.path.replace('\\', "/");
        let path = path.trim_start_matches("./");
        if rules::in_git_dir(path) {
            self.report.has_git = true;
        }
        for finding in rules::check(path, entry, content, &mut self.seen) {
            self.add(finding);
        }
    }

    /// Lists each repository's branches and tags, and checks the files on them that differ from
    /// the checked-out commit.
    fn branches(&mut self) {
        for (dir, files) in std::mem::take(&mut self.repos) {
            let mut repo =
                Repo { path: format!("{}{dir}", self.prefix), head: None, branches: vec![], tags: vec![], note: None };
            if files.too_big {
                repo.note = Some("Its Git data is too big to read here, so its branches weren't checked.".into());
                self.report.repos.push(repo);
                continue;
            }
            let found = git::inspect(&files, rules::wants_branch_content);
            repo.head = found.head;
            repo.branches = found.branches;
            repo.tags = found.tags;
            repo.note = found.note;
            self.report.repos.push(repo);

            let root = dir.strip_suffix(".git").unwrap_or("");
            for file in found.files {
                let path = format!("{root}{}", file.path);
                let link = file.mode == 0o120000;
                let entry = Entry {
                    path: path.clone(),
                    kind: if link {
                        Kind::Link(String::from_utf8_lossy(file.content.as_deref().unwrap_or_default()).into_owned())
                    } else {
                        Kind::File
                    },
                    mode: Some(file.mode),
                    size: file.content.as_ref().map_or(0, |c| c.len() as u64),
                    encrypted: false,
                };
                let content = if link { None } else { file.content.as_deref() };
                for mut finding in rules::check(&path, &entry, content, &mut self.seen) {
                    let shown = format!("{}{}", self.prefix, finding.path);
                    // Already reported from the files as they are now.
                    if self
                        .report
                        .findings
                        .iter()
                        .any(|f| f.branch.is_none() && f.path == shown && f.title == finding.title)
                    {
                        continue;
                    }
                    finding.branch = Some(file.refs.join(", "));
                    self.add(finding);
                }
            }
        }
    }

    fn add(&mut self, mut finding: Finding) {
        finding.path = format!("{}{}", self.prefix, finding.path);
        self.report.findings.push(finding);
    }
}

#[cfg(test)]
mod tests;
