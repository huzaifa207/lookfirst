//! Git repositories found inside, or read from a bundle or a remote with no folder on disk.

use super::*;

impl Scan<'_> {
    pub(super) fn add_bare(&mut self, dir: &str, files: git::Files) {
        self.bare.insert(dir.to_string());
        self.repos.insert(dir.to_string(), files);
    }

    /// A Git bundle: branch names and a pack, read in memory without Git.
    pub(super) fn bundle<R: Read>(&mut self, src: R, name: &str) -> io::Result<()> {
        let mut data = Vec::new();
        src.take(git::MAX_REPO_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > git::MAX_REPO_BYTES {
            self.add(rules::cant_open(name, "it's a Git bundle too big to read here"));
            return Ok(());
        }
        match git::bundle(data) {
            Ok(files) => self.add_bare(&format!("{name}/.git"), files),
            Err(why) => self.add(rules::cant_open(name, &why)),
        }
        Ok(())
    }

    /// Lists each repository's branches and tags, and checks the files on them that differ from
    /// the checked-out commit.
    pub(super) fn branches(&mut self) {
        for (dir, files) in std::mem::take(&mut self.repos) {
            if self.want.repo.as_deref() == Some(&format!("{}{dir}", self.prefix)) {
                self.kept = Some(files); // kept for browsing, not checked again
                continue;
            }
            let mut repo =
                Repo { path: format!("{}{dir}", self.prefix), head: None, branches: vec![], tags: vec![], note: None };
            if files.too_big {
                repo.note = Some("Its Git data is too big to read here, so its branches weren't checked.".into());
                self.report.repos.push(repo);
                continue;
            }
            let bare = self.bare.contains(&dir);
            let wants: fn(&str) -> bool = if bare { rules::wants_repo_content } else { rules::wants_branch_content };
            let found = git::inspect(&files, wants);
            let head = found.head.clone();
            if bare {
                // Its checked-out files are the ones on HEAD, so they count as the files here.
                self.report.has_git = true;
                self.report.files +=
                    found.files.iter().filter(|f| head.as_ref().is_some_and(|h| f.refs.contains(h))).count();
            }
            repo.head = found.head;
            repo.branches = found.branches;
            repo.tags = found.tags;
            let gap = [files.note.clone(), found.note].into_iter().flatten().reduce(|a, b| format!("{a} {b}"));
            repo.note = [files.limit.clone(), gap.clone()].into_iter().flatten().reduce(|a, b| format!("{a} {b}"));
            if let (true, Some(note)) = (bare, &gap) {
                // With no files on disk to fall back on, a gap is a gap in the check itself.
                self.add(Finding {
                    level: Level::Check,
                    path: dir.strip_suffix("/.git").unwrap_or(&dir).to_string(),
                    title: "Not everything in this repository could be checked.".into(),
                    detail: note.clone(),
                    branch: None,
                    campaign: None,
                });
            }
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
                    if !bare
                        && self
                            .report
                            .findings
                            .iter()
                            .any(|f| f.branch.is_none() && f.path == shown && f.title == finding.title)
                    {
                        continue;
                    }
                    // In a bare repository the files on HEAD are the files as they are now.
                    let on_head = bare && head.as_ref().is_some_and(|h| file.refs.contains(h));
                    finding.branch = (!on_head).then(|| file.refs.join(", "));
                    self.add(finding);
                }
            }
        }
    }
}
