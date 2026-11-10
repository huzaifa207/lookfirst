//! Reads a repository at an https or ssh address without cloning it, over Git's own protocol
//! (version 2), and without running Git. Private repositories work with an access token (https) or
//! the user's own ssh keys (ssh).
//!
//! Two requests do the work: one for the latest commit of every branch and tag with its folder
//! listing but no file contents, then one for just the files the checks read. Everything that
//! comes back is data from a stranger, read with the same bounds-checked code as a local repo.

use crate::git::{self, Files, Source};
use base64::Engine;
use std::rc::Rc;
use std::time::Duration;

mod http;
mod pkt;
mod ssh;

use http::*;
use pkt::*;
pub use ssh::is_address;
use ssh::*;

/// Bytes accepted in any one response.
const MAX_RESPONSE: u64 = 256 * 1024 * 1024;

/// Branches and tags checked; a repository with thousands would otherwise mean a huge download.
const MAX_REFS: usize = 500;

/// Files asked for in the second request.
const MAX_FILES: usize = 5000;

const TIMEOUT: Duration = Duration::from_secs(180);

/// Where an access token may be sent. Anywhere else, a link from a stranger could collect it.
const TOKEN_HOSTS: &[&str] = &["github.com", "gitlab.com", "bitbucket.org"];

/// Talks to a Git server: the first answer lists what it can do, then each command gets an answer.
trait Transport {
    fn advertise(&mut self) -> Result<Vec<u8>, String>;
    fn command(&mut self, body: &[u8]) -> Result<Vec<u8>, String>;
}

fn token_header(token: &str) -> String {
    // A token alone works on GitHub, GitLab and Bitbucket with any user name; "user:token" is kept as is.
    let pair = if token.contains(':') { token.to_string() } else { format!("x-access-token:{token}") };
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))
}

/// The repository's name for display, and its files: branch names, and a pack of the latest
/// commit of each with just the files the checks read.
pub(crate) fn fetch(url: &str, token: Option<&str>, allow_http: bool) -> Result<(String, Files), String> {
    let url = url.trim();
    let token = token.map(str::trim).filter(|t| !t.is_empty());
    if let Some(target) = ssh_target(url) {
        let (name, target) = target?;
        let mut ssh = Ssh::start(&target)?;
        return Ok((name, files(&mut ssh)?));
    }
    let (scheme, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => ("https", rest),
        (_, Some(rest)) if allow_http => ("http", rest),
        _ => return Err("only https:// and ssh addresses can be checked (not a local path)".into()),
    };
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    if rest.contains(|c: char| c.is_whitespace() || c.is_control() || "@?#\\".contains(c)) || !rest.contains('/') {
        return Err("that doesn't look like a repository address (https://host/owner/name)".into());
    }
    if token.is_some() {
        let host = rest.split('/').next().unwrap_or("").split(':').next().unwrap_or("").to_ascii_lowercase();
        let extra = std::env::var("LOOKFIRST_TOKEN_HOST").unwrap_or_default();
        let allowed = TOKEN_HOSTS.contains(&host.as_str())
            || extra.split(',').any(|h| !h.trim().is_empty() && h.trim().eq_ignore_ascii_case(&host))
            || (allow_http && host == "127.0.0.1");
        if !allowed {
            return Err(format!(
                "an access token is only sent to github.com, gitlab.com and bitbucket.org, not to {host}. For another \
                 host, set LOOKFIRST_TOKEN_HOST={host} and use the command line."
            ));
        }
    }
    let mut config = ureq::Agent::config_builder().https_only(!allow_http).timeout_global(Some(TIMEOUT));
    if token.is_some() {
        config = config.max_redirects(0).max_redirects_will_error(false);
    }
    let agent: ureq::Agent = config.build().into();
    let auth = token.map(token_header);
    // Some servers want the ".git" on the end and some refuse it.
    let mut last = String::new();
    for suffix in ["", ".git"] {
        let mut http = Http { agent: agent.clone(), base: format!("{scheme}://{rest}{suffix}"), auth: auth.clone() };
        match files(&mut http) {
            Ok(files) => return Ok((rest.to_string(), files)),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// One `fetch` command: a pack of whatever was asked for, or an error from the server.
fn fetch_pack(server: &mut dyn Transport, wants: &[String], first: bool) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    pkt(&mut body, "command=fetch\n");
    pkt(&mut body, "agent=lookfirst\n");
    body.extend(b"0001");
    pkt(&mut body, "ofs-delta\n");
    pkt(&mut body, "no-progress\n");
    if first {
        // Only the newest commit of each branch, and no file contents.
        pkt(&mut body, "deepen 1\n");
        pkt(&mut body, "filter blob:none\n");
    }
    for oid in wants {
        pkt(&mut body, &format!("want {oid}\n"));
    }
    pkt(&mut body, "done\n");
    body.extend(b"0000");
    let answer = server.command(&body)?;
    let mut pack = Vec::new();
    let mut in_pack = false;
    for item in pkts(&answer)? {
        let Pkt::Data(line) = item else { continue };
        if !in_pack {
            if let Some(error) = line.strip_prefix(b"ERR ") {
                return Err(format!("the server refused: {}", String::from_utf8_lossy(error).trim()));
            }
            in_pack = line == b"packfile\n";
        } else {
            match line.split_first() {
                Some((1, data)) => pack.extend_from_slice(data),
                Some((2, _)) => {}
                Some((3, error)) => {
                    return Err(format!("the server refused: {}", String::from_utf8_lossy(error).trim()))
                }
                _ => return Err("the server's answer wasn't what Git sends".into()),
            }
        }
    }
    if in_pack {
        Ok(pack)
    } else {
        Err("the server sent no files".into())
    }
}

fn files(server: &mut dyn Transport) -> Result<Files, String> {
    let advert = server.advertise()?;
    let lines: Vec<&[u8]> =
        pkts(&advert)?.into_iter().filter_map(|p| if let Pkt::Data(d) = p { Some(d) } else { None }).collect();
    let text = |l: &&[u8]| String::from_utf8_lossy(l).trim().to_string();
    if !lines.iter().any(|l| text(l) == "version 2") {
        return Err("the server is too old: it doesn't speak Git protocol version 2".into());
    }
    let fetch_caps = lines.iter().map(text).find(|l| l.starts_with("fetch=")).unwrap_or_default();
    if !(fetch_caps.contains("shallow") && fetch_caps.contains("filter")) {
        return Err("the server can't send just the latest files, so it can't be checked without cloning".into());
    }

    let mut body = Vec::new();
    pkt(&mut body, "command=ls-refs\n");
    pkt(&mut body, "agent=lookfirst\n");
    body.extend(b"0001");
    for arg in ["peel\n", "symrefs\n", "ref-prefix HEAD\n", "ref-prefix refs/heads/\n", "ref-prefix refs/tags/\n"] {
        pkt(&mut body, arg);
    }
    body.extend(b"0000");
    let answer = server.command(&body)?;
    let (mut head, mut heads, mut tags) = (None, Vec::new(), Vec::new());
    for item in pkts(&answer)? {
        let Pkt::Data(line) = item else { continue };
        let line = String::from_utf8_lossy(line);
        let mut parts = line.trim().split(' ');
        let (Some(oid), Some(name)) = (parts.next(), parts.next()) else { continue };
        // A tag object's own id isn't a commit; the commit it points at is.
        let oid = parts.find_map(|a| a.strip_prefix("peeled:")).unwrap_or(oid).to_string();
        match name {
            "HEAD" => head = Some(oid),
            n if n.starts_with("refs/heads/") => heads.push((oid, n.to_string())),
            n if n.starts_with("refs/tags/") => tags.push((oid, n.to_string())),
            _ => {}
        }
    }
    let total = heads.len() + tags.len();
    let mut refs: Vec<(String, String)> = heads.into_iter().chain(tags).take(MAX_REFS).collect();
    let skipped = total - refs.len();
    refs.extend(head.map(|oid| (oid, "HEAD".to_string())));
    let mut wants: Vec<String> = Vec::new();
    for (oid, _) in &refs {
        if !wants.contains(oid) {
            wants.push(oid.clone());
        }
    }
    let mut files = git::refs_to_files(&refs).ok_or("it has no branches")?;
    if skipped > 0 {
        files.limit = Some(format!("It has {skipped} more branches and tags than LookFirst checks over the network."));
    }
    files.add("objects/pack/latest.pack", Source::Mem(Rc::new(fetch_pack(server, &wants, true)?)));

    let mut blobs = git::needed(&files, crate::rules::wants_repo_content);
    let more = blobs.len().saturating_sub(MAX_FILES);
    blobs.truncate(MAX_FILES);
    let mut notes = Vec::new();
    if more > 0 {
        notes.push(format!("{more} files were left unread because there are too many."));
    }
    if !blobs.is_empty() {
        match fetch_pack(server, &blobs, false) {
            Ok(pack) => files.add("objects/pack/files.pack", Source::Mem(Rc::new(pack))),
            Err(e) => notes.push(format!("The server wouldn't send the files themselves ({e}).")),
        }
    }
    files.note = [files.note.take()].into_iter().flatten().chain(notes).reduce(|a, b| format!("{a} {b}"));
    Ok(files)
}
