use super::*;

pub(super) const LIFECYCLE: &[&str] =
    &["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish"];

pub(super) fn scripts(path: &str, content: &[u8]) -> Option<Finding> {
    let json: serde_json::Value = serde_json::from_slice(content).ok()?;
    let scripts = json.get("scripts")?.as_object()?;
    let found: Vec<(String, String)> =
        LIFECYCLE.iter().filter_map(|k| Some((k.to_string(), scripts.get(*k)?.as_str()?.to_string()))).collect();
    if found.is_empty() {
        return None;
    }
    let joined = found.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>().join("\n");
    let bad = alarming(joined.as_bytes()) || crate::indicators::current().iocs.iter().any(|i| joined.contains(&i.text));
    if in_node_modules(path) && !bad {
        return None; // installed packages run install scripts all the time
    }
    let list: Vec<String> = found.iter().map(|(k, v)| format!("{k}: {}", clip(v))).collect();
    Some(finding(
        if bad { Level::Danger } else { Level::Check },
        path,
        "This runs commands when someone installs the project with npm.",
        format!(
            "Install scripts, which npm runs by itself: {}.{}",
            list.join("; "),
            describe(&signs(joined.as_bytes()))
        ),
    ))
}
