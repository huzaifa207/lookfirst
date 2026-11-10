//! A folder on disk, walked in place.

use super::*;

impl Scan<'_> {
    pub(super) fn folder(&mut self, root: &Path, dir: &Path) -> io::Result<()> {
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
                Kind::Link(_) => self.read_and_visit(&entry, &mut io::empty())?,
            }
        }
        Ok(())
    }
}
