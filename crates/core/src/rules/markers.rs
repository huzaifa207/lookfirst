//! Strings from published reports that only a campaign's malware (or a note about it) contains.

use super::*;

/// Whether `needle` is in `haystack`: not at all, only inside matching quotes (named, as a list of
/// indicators does), or at least once as code. Matching ignores case.
fn presence(haystack: &[u8], needle: &str, quoted_is_mention: bool) -> Option<bool> {
    let needle = needle.as_bytes();
    let mut found = false;
    for (i, window) in haystack.windows(needle.len()).enumerate() {
        if !window.eq_ignore_ascii_case(needle) {
            continue;
        }
        found = true;
        let before = i.checked_sub(1).map(|j| haystack[j]);
        let after = haystack.get(i + needle.len()).copied();
        let wrapped = before == after && matches!(before, Some(b'"' | b'\'' | b'`'));
        if !(quoted_is_mention && wrapped) {
            return Some(true);
        }
    }
    found.then_some(false)
}

/// A known address or marker in the file: Danger when it is used, and a Check when a marker is only
/// named in quotes, which is what a detection script or a write-up does.
pub(super) fn check(path: &str, content: &[u8]) -> Option<Finding> {
    let list = crate::indicators::current();
    let markers =
        list.markers.iter().map(|m| (m.text.as_str(), m.campaign.as_str(), m.campaign.as_str(), m.mention_if_quoted));
    let iocs = list.iocs.iter().map(|i| (i.text.as_str(), i.source.as_str(), i.campaign.as_str(), false));
    let mut named = None;
    for (text, source, campaign, quoted_is_mention) in iocs.chain(markers) {
        match presence(content, text, quoted_is_mention) {
            Some(true) => {
                let mut hit = finding(
                    Level::Danger,
                    path,
                    "This contains an address or marker from known malware.",
                    format!("It matches \"{text}\", from {source}."),
                );
                hit.campaign = Some(campaign.to_string());
                return Some(hit);
            }
            Some(false) => named = named.or(Some((text, campaign))),
            None => {}
        }
    }
    named.map(|(text, campaign)| {
        finding(
            Level::Check,
            path,
            "This names a known malware marker, but only as text.",
            format!(
                "It lists \"{text}\" ({campaign}) inside quotes, the way a detection script or a write-up does. \
                 Real malware uses it as code, so this is probably a scanner or a note about the campaign. \
                 Look at it to be sure."
            ),
        )
    })
}
