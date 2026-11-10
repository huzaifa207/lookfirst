//! The lists of known-bad things: infected npm versions, file hashes, strings and addresses from
//! published reports. They ship inside the app, and can be refreshed on request from a file signed
//! with the maintainer's key, so a new indicator doesn't need a new release.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;

const BUILT_IN: &str = include_str!("../data/indicators.json");
/// The maintainer's public key. Only a list signed with the matching private key is accepted.
const PUBLIC_KEY: &str = "cb2f21aaf7bad47d120ab70bbc8d86115e7ef8172334845b9f38364d96389cc7";
const FEED: &str = "https://raw.githubusercontent.com/huzaifa207/lookfirst/main/crates/core/data/indicators.json";
const FORMAT: u32 = 1;
const MAX_FEED: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
struct Raw {
    format: u32,
    version: u32,
    updated: String,
    /// "name version", one per entry.
    packages: Vec<String>,
    hashes: Vec<Hash>,
    markers: Vec<Marker>,
    iocs: Vec<Ioc>,
}

#[derive(Deserialize)]
pub(crate) struct Hash {
    pub sha256: String,
    pub what: String,
}

/// A string found only in one campaign's code.
#[derive(Deserialize)]
pub(crate) struct Marker {
    pub text: String,
    pub campaign: String,
    /// Infected code uses this as code, so inside matching quotes it is being named, not used
    /// (a detection script's list of markers).
    #[serde(default)]
    pub mention_if_quoted: bool,
}

/// An address or marker from a published report, with where it was reported.
#[derive(Deserialize)]
pub(crate) struct Ioc {
    pub text: String,
    pub source: String,
    pub campaign: String,
}

pub(crate) struct Indicators {
    pub version: u32,
    pub updated: String,
    pub packages: HashSet<(String, String)>,
    pub hashes: Vec<Hash>,
    pub markers: Vec<Marker>,
    pub iocs: Vec<Ioc>,
}

/// Which list is in use, and whether an update just changed it.
#[derive(Serialize, Clone, Debug)]
pub struct ListInfo {
    pub version: u32,
    pub updated: String,
    pub changed: bool,
}

fn parse(bytes: &[u8]) -> Result<Indicators, String> {
    let raw: Raw = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if raw.format != FORMAT {
        return Err("it is in a newer format than this version of LookFirst reads".into());
    }
    let packages =
        raw.packages.iter().filter_map(|l| l.split_once(' ').map(|(n, v)| (n.to_string(), v.trim().to_string())));
    Ok(Indicators {
        version: raw.version,
        updated: raw.updated,
        packages: packages.collect(),
        hashes: raw.hashes,
        markers: raw.markers,
        iocs: raw.iocs,
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    text.len()
        .is_multiple_of(2)
        .then(|| (0..text.len()).step_by(2).map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok()).collect())
        .flatten()
}

/// The list, if the signature is the maintainer's and it parses.
fn verified(json: &[u8], signature: &str) -> Result<Indicators, String> {
    let key = VerifyingKey::from_bytes(&unhex(PUBLIC_KEY).and_then(|k| k.try_into().ok()).ok_or("bad built-in key")?)
        .map_err(|e| e.to_string())?;
    let signature =
        unhex(signature).and_then(|s| Signature::from_slice(&s).ok()).ok_or("the signature file isn't a signature")?;
    key.verify(json, &signature).map_err(|_| "it isn't signed by LookFirst's maintainer")?;
    parse(json)
}

fn data_dir() -> Option<PathBuf> {
    let var = |k| std::env::var_os(k).map(PathBuf::from);
    if let Some(dir) = var("LOOKFIRST_DATA_DIR") {
        return Some(dir);
    }
    let base = if cfg!(target_os = "macos") {
        var("HOME")?.join("Library/Application Support")
    } else if cfg!(windows) {
        var("APPDATA")?
    } else {
        var("XDG_DATA_HOME").or_else(|| var("HOME").map(|h| h.join(".local/share")))?
    };
    Some(base.join("LookFirst"))
}

/// The downloaded list, re-checked every time: a file edited on disk fails the signature.
fn downloaded() -> Option<Indicators> {
    let dir = data_dir()?;
    let json = std::fs::read(dir.join("indicators.json")).ok()?;
    verified(&json, &std::fs::read_to_string(dir.join("indicators.json.sig")).ok()?).ok()
}

static CURRENT: LazyLock<RwLock<Arc<Indicators>>> = LazyLock::new(|| {
    let built_in = parse(BUILT_IN.as_bytes()).expect("the built-in indicators are valid");
    // A list from an older download never replaces a newer app's own.
    RwLock::new(Arc::new(downloaded().filter(|d| d.version > built_in.version).unwrap_or(built_in)))
});

pub(crate) fn current() -> Arc<Indicators> {
    CURRENT.read().unwrap().clone()
}

pub fn list_info() -> ListInfo {
    let list = current();
    ListInfo { version: list.version, updated: list.updated.clone(), changed: false }
}

fn get(url: &str) -> Result<Vec<u8>, String> {
    let mut response = ureq::get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .call()
        .map_err(|e| format!("couldn't download it ({e})"))?;
    response.body_mut().with_config().limit(MAX_FEED).read_to_vec().map_err(|e| format!("couldn't download it ({e})"))
}

/// Downloads the latest list, and uses it if it is signed and newer than the one in use. Only
/// downloads: nothing about the user or their files is sent.
pub fn update_list() -> Result<ListInfo, String> {
    let url = std::env::var("LOOKFIRST_FEED_URL").unwrap_or_else(|_| FEED.to_string());
    let json = get(&url)?;
    let signature = String::from_utf8(get(&format!("{url}.sig"))?).map_err(|_| "the signature file is damaged")?;
    let new = verified(&json, &signature).map_err(|e| format!("The downloaded list was thrown away: {e}."))?;
    let have = current();
    if new.version <= have.version {
        return Ok(ListInfo { version: have.version, updated: have.updated.clone(), changed: false });
    }
    let dir = data_dir().ok_or("couldn't find a place to keep the list")?;
    std::fs::create_dir_all(&dir)
        .and_then(|_| std::fs::write(dir.join("indicators.json"), &json))
        .map_err(|e| e.to_string())?;
    std::fs::write(dir.join("indicators.json.sig"), signature.trim()).map_err(|e| e.to_string())?;
    let info = ListInfo { version: new.version, updated: new.updated.clone(), changed: true };
    *CURRENT.write().unwrap() = Arc::new(new);
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE: &str = include_str!("../data/indicators.json.sig");

    /// Fails if the list was edited and not signed again.
    #[test]
    fn committed_list_is_signed() {
        verified(BUILT_IN.as_bytes(), SIGNATURE).unwrap();
    }

    #[test]
    fn edited_list_is_refused() {
        let edited = BUILT_IN.replacen("\"packages\": [", "\"packages\": [\"x 1\",", 1);
        assert!(verified(edited.as_bytes(), SIGNATURE).is_err());
        assert!(verified(BUILT_IN.as_bytes(), "00").is_err());
    }
}
