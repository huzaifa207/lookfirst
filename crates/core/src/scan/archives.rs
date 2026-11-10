//! The archive formats: zip, tar, 7z, and the compressed single files around them.

use super::*;

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

impl Scan<'_> {
    /// A .gz, .bz2 or .xz is usually a tar, but can be one compressed file.
    pub(super) fn compressed(&mut self, dec: impl Read, name: &str, ext: &str) -> io::Result<()> {
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

    pub(super) fn zip<R: Read + Seek>(&mut self, src: R) -> io::Result<()> {
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

    pub(super) fn tar<R: Read>(&mut self, src: R) -> io::Result<()> {
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

    pub(super) fn sevenz<R: Read + Seek>(&mut self, src: R) -> io::Result<()> {
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
}
