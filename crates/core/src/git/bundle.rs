//! A Git bundle, or a list of refs, as the files of a repository.
use super::*;
use std::rc::Rc;

/// A Git bundle (a file holding branch names and a pack) as the files of a repository.
pub(crate) fn bundle(mut data: Vec<u8>) -> Result<Files, String> {
    let header_end = data.windows(2).position(|w| w == b"\n\n").map(|i| i + 2).ok_or("it has no pack of objects")?;
    let header = String::from_utf8_lossy(&data[..header_end]).into_owned();
    let mut lines = header.lines();
    if !matches!(lines.next(), Some("# v2 git bundle" | "# v3 git bundle")) {
        return Err("it isn't a Git bundle LookFirst can read".into());
    }
    let (mut refs, mut incomplete) = (Vec::new(), false);
    for line in lines {
        if line.starts_with("@object-format=sha256") {
            return Err("it uses SHA-256 object ids, which LookFirst can't read yet".into());
        } else if line.starts_with('-') {
            incomplete = true;
        } else if let Some((oid, name)) = line.split_once(' ') {
            if parse_hex(oid).is_some() {
                refs.push((oid.to_string(), name.to_string()));
            }
        }
    }
    data.drain(..header_end);
    let mut files = refs_to_files(&refs).ok_or("it lists no branches")?;
    files.add("objects/pack/bundle.pack", Source::Mem(Rc::new(data)));
    if incomplete {
        files.note = Some(
            "This bundle builds on older commits it doesn't contain, so files that only exist there couldn't be read."
                .into(),
        );
    }
    Ok(files)
}

/// Branch and tag names with the commits they point at, as the files of a bare repository: a
/// packed-refs list, and a HEAD that follows "HEAD" if given, else main, master or the first branch.
pub(crate) fn refs_to_files(refs: &[(String, String)]) -> Option<Files> {
    let mut files = Files::default();
    let packed: String =
        refs.iter().filter(|(_, n)| n != "HEAD").map(|(oid, name)| format!("{oid} {name}\n")).collect();
    let heads: Vec<&(String, String)> = refs.iter().filter(|(_, n)| n.starts_with("refs/heads/")).collect();
    let head_oid = refs.iter().find(|(_, n)| n == "HEAD").map(|(oid, _)| oid);
    let pick = |name: &str| heads.iter().find(|(_, n)| n == name);
    let head = head_oid
        .and_then(|oid| {
            let same = |name: &str| heads.iter().find(|(o, n)| o == oid && n == name);
            same("refs/heads/main")
                .or_else(|| same("refs/heads/master"))
                .or_else(|| heads.iter().find(|(o, _)| o == oid))
        })
        .or_else(|| pick("refs/heads/main"))
        .or_else(|| pick("refs/heads/master"))
        .or_else(|| heads.first())
        .map(|(_, name)| format!("ref: {name}\n"))
        .or_else(|| head_oid.map(|oid| format!("{oid}\n")))?;
    files.add("packed-refs", Source::Mem(Rc::new(packed.into_bytes())));
    files.add("HEAD", Source::Mem(Rc::new(head.into_bytes())));
    Some(files)
}
