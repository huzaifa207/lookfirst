//! The packages and versions a lockfile pins: npm, yarn, pnpm and bun.

use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// The package a yarn.lock entry is for: `foo@^1`, `"@s/p@npm:^1"`, or an alias `foo@npm:bar@^1`.
fn spec_name(spec: &str) -> String {
    let spec = spec.trim().trim_matches('"');
    let (head, rest) = spec.split_once("@npm:").unwrap_or((spec, ""));
    let head = match rest.chars().next() {
        Some(c) if !c.is_ascii_digit() && !"^~<>=*".contains(c) => rest,
        _ => head,
    };
    match head.get(1..).and_then(|h| h.find('@')) {
        Some(i) => head[..i + 1].to_string(),
        None => head.to_string(),
    }
}

/// Every (package, version) a lockfile pins.
pub(crate) fn locked(name: &str, text: &str) -> HashSet<(String, String)> {
    let mut pairs = HashSet::new();
    if name.ends_with(".json") {
        // npm: v2 and v3 list "packages"; v1 nests "dependencies".
        let Ok(data) = serde_json::from_str::<serde_json::Value>(text) else { return pairs };
        if let Some(packages) = data.get("packages").and_then(|p| p.as_object()) {
            for (path, entry) in packages {
                if let (false, Some(version)) = (path.is_empty(), entry.get("version").and_then(|v| v.as_str())) {
                    let pkg = entry
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or_else(|| path.rsplit("node_modules/").next().unwrap_or(path));
                    pairs.insert((pkg.to_string(), version.to_string()));
                }
            }
        }
        fn walk(deps: Option<&serde_json::Value>, pairs: &mut HashSet<(String, String)>, depth: usize) {
            let Some(deps) = deps.and_then(|d| d.as_object()) else { return };
            for (pkg, entry) in deps {
                pairs.insert((pkg.clone(), entry.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string()));
                if depth < 64 {
                    walk(entry.get("dependencies"), pairs, depth + 1);
                }
            }
        }
        walk(data.get("dependencies"), &mut pairs, 0);
    } else if name == "yarn.lock" {
        // `"foo@^1", foo@~1:` then an indented `version "1.2.3"` (v1) or `version: 1.2.3` (berry).
        static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^\s+version:?\s+"?([^"\s]+)"#).unwrap());
        let mut names: Vec<String> = Vec::new();
        for line in text.lines() {
            if !line.is_empty()
                && !line.starts_with(char::is_whitespace)
                && line.trim_end().ends_with(':')
                && !line.starts_with('#')
            {
                let header = line.trim_end();
                names = header[..header.len() - 1].split(',').map(spec_name).collect();
            } else if let Some(m) = VERSION.captures(line) {
                pairs.extend(names.iter().map(|n| (n.clone(), m[1].to_string())));
            }
        }
    } else if name == "pnpm-lock.yaml" {
        // `/foo/1.2.3:` (v5), `/foo@1.2.3:` (v6), `foo@1.2.3(peer@x):` (v9).
        static ENTRY: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"(?m)^\s+'?/?((?:@[^/@\s']+/)?[^/@\s:'(]+)[@/](\d+\.\d+\.\d+[^\s:'(_]*)").unwrap()
        });
        pairs.extend(ENTRY.captures_iter(text).map(|c| (c[1].to_string(), c[2].to_string())));
    } else {
        // bun.lock: `"foo": ["foo@1.2.3", …]`.
        static ENTRY: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#""((?:@[^"/@]+/)?[^"/@\s]+)@(\d+\.\d+\.\d+[^"]*)""#).unwrap());
        pairs.extend(ENTRY.captures_iter(text).map(|c| (c[1].to_string(), c[2].to_string())));
    }
    pairs
}

#[cfg(test)]
pub(crate) fn spec(spec: &str) -> String {
    spec_name(spec)
}
