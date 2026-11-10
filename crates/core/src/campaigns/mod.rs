//! Indicators from two known campaigns, ported from the scanners written for them
//! (github.com/huzaifa207/shai-hulud-scan and github.com/huzaifa207/polinrider-scan), with the
//! same sources and the same false-positive lessons. A match names the campaign.

use crate::indicators;
use crate::{Finding, Level};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

mod lockfiles;

pub(crate) use lockfiles::locked;
#[cfg(test)]
pub(crate) use lockfiles::spec;

pub(crate) const SHAI_HULUD: &str = "Shai-Hulud npm worm";
pub(crate) const POLINRIDER: &str = "PolinRider";

/// The payload's names in this wave, and the previous one's.
const PAYLOADS: &[&str] =
    &["math_init.js", "Math_Symbol.js", "router_runtime.js", "setup_bun.js", "bun_environment.js"];
pub(crate) const LOCKFILES: &[&str] =
    &["package-lock.json", "npm-shrinkwrap.json", ".package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"];
static LOADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(setup\.mjs|setup_bun\.js)\b").unwrap());

/// PolinRider's fake fonts. The real Font Awesome files are fa-brands-400, fa-regular-400 and
/// fa-solid-900, which the campaign copies in alongside as camouflage.
static FAKE_FONT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|/)fa-(brand-400\.woff|solid-[45]00\.woff2)$").unwrap());
/// Config files build tools and editors load, where PolinRider appends code after a long run of spaces.
static CONFIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(^|/)((next|nuxt|astro|vite|vitest|svelte|tailwind|postcss|eslint|webpack|rollup|babel|jest|prisma|tsup|remix)\.config\.(js|cjs|mjs|ts)|\.eslintrc\.(js|cjs)|api\.js)$",
    )
    .unwrap()
});
/// Code, then 150 or more spaces, then more code.
pub(crate) static HIDDEN_AFTER_SPACES: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"\S {150,}\S").unwrap());

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn in_node_modules(path: &str) -> bool {
    path.split('/').any(|s| s == "node_modules")
}

/// Files these checks read, including a few inside node_modules, where the rest isn't read.
pub(crate) fn wants(path: &str) -> bool {
    let name = name_of(path);
    LOCKFILES.contains(&name) || PAYLOADS.contains(&name) || name == "setup.mjs" || name == "package.json"
}

/// Lockfiles and payloads can be big, and a hash needs the whole file.
pub(crate) fn needs_whole(path: &str) -> bool {
    let name = name_of(path);
    LOCKFILES.contains(&name) || PAYLOADS.contains(&name) || name == "setup.mjs"
}

fn found(level: Level, path: &str, campaign: &str, title: impl Into<String>, detail: impl Into<String>) -> Finding {
    Finding {
        level,
        path: path.to_string(),
        title: title.into(),
        detail: detail.into(),
        branch: None,
        campaign: Some(campaign.to_string()),
    }
}

pub(crate) fn check(path: &str, content: Option<&[u8]>) -> Vec<Finding> {
    let name = name_of(path);
    let mut out = Vec::new();

    // PolinRider, by name.
    if FAKE_FONT.is_match(path) {
        out.push(found(
            Level::Danger,
            path,
            POLINRIDER,
            "This is a fake font file that a known campaign hides code in.",
            "Its name copies Font Awesome's, but the real files are fa-brands-400, fa-regular-400 and fa-solid-900. PolinRider runs code stored in files named like this one.",
        ));
    }
    if name == "temp_auto_push.bat" {
        out.push(found(
            Level::Danger,
            path,
            POLINRIDER,
            "This is a script a known campaign uses to push itself to repositories.",
            "PolinRider's push script, temp_auto_push.bat.",
        ));
    }
    let Some(content) = content else { return out };
    let list = indicators::current();
    let text = String::from_utf8_lossy(content);

    // Shai-Hulud: infected versions in lockfiles and installed packages.
    if LOCKFILES.contains(&name) {
        let mut bad: Vec<String> = locked(name, &text)
            .into_iter()
            .filter(|pair| list.packages.contains(pair))
            .map(|(p, v)| format!("{p}@{v}"))
            .collect();
        bad.sort();
        if !bad.is_empty() {
            let shown = bad.iter().take(10).cloned().collect::<Vec<_>>().join(", ");
            let more = if bad.len() > 10 { format!(", and {} more", bad.len() - 10) } else { String::new() };
            out.push(found(
                Level::Danger,
                path,
                SHAI_HULUD,
                "This installs npm packages that a self-spreading worm infected.",
                format!(
                    "It pins {} infected version{}: {shown}{more}. Installing runs the worm.",
                    bad.len(),
                    if bad.len() == 1 { "" } else { "s" }
                ),
            ));
        }
    }
    if name == "package.json" {
        if let Ok(package) = serde_json::from_slice::<serde_json::Value>(content) {
            let scripts = package.get("scripts");
            let loader = ["preinstall", "install", "postinstall"].iter().find_map(|k| {
                let script = scripts?.get(*k)?.as_str()?;
                LOADER.is_match(script).then(|| format!("{k}: {script}"))
            });
            if let Some(script) = loader {
                out.push(found(
                    Level::Danger,
                    path,
                    SHAI_HULUD,
                    "This runs a known worm's loader when someone installs it with npm.",
                    format!("Shai-Hulud adds this install script: {script}."),
                ));
            }
            let (pkg, version) =
                (package.get("name").and_then(|n| n.as_str()), package.get("version").and_then(|v| v.as_str()));
            if let (true, Some(pkg), Some(version)) = (in_node_modules(path), pkg, version) {
                if list.packages.contains(&(pkg.to_string(), version.to_string())) {
                    out.push(found(
                        Level::Danger,
                        path,
                        SHAI_HULUD,
                        "This is an installed npm package that a self-spreading worm infected.",
                        format!("{pkg}@{version} is a version Shai-Hulud published. Installing it already ran the worm's script."),
                    ));
                }
            }
        }
    }
    // Shai-Hulud's loader and payload files.
    if PAYLOADS.contains(&name) || name == "setup.mjs" {
        let hash: String = Sha256::digest(content).iter().map(|b| format!("{b:02x}")).collect();
        if let Some(known) = list.hashes.iter().find(|h| h.sha256 == hash) {
            let what = &known.what;
            out.push(found(
                Level::Danger,
                path,
                SHAI_HULUD,
                format!("This is {what}, a known malicious file."),
                format!("Its SHA-256 matches {what} in published reports: {hash}."),
            ));
        } else if re_planted(path, name) {
            // Inside node_modules a name alone isn't enough: regenerate-unicode-properties ships a real
            // Math_Symbol.js (the Unicode category), and an infected package is caught by its version.
            out.push(found(
                Level::Check,
                path,
                SHAI_HULUD,
                "A known worm plants a file with this name here.",
                "Look at it before anything runs it: Shai-Hulud puts its loader (setup.mjs) and payload (math_init.js and similar) in places like this.",
            ));
        }
    }
    // Planted triggers: a VS Code task or a Claude Code hook.
    let parent = path.rsplit('/').nth(1).unwrap_or("");
    let task = name == "tasks.json" && parent == ".vscode";
    if (task || (parent == ".claude" && name.starts_with("settings"))) && LOADER.is_match(&text) {
        out.push(found(
            Level::Danger,
            path,
            SHAI_HULUD,
            "This runs a known worm's loader.",
            "Shai-Hulud plants this file so its loader (setup.mjs) runs when the folder opens or an AI session starts.",
        ));
    }
    if task && text.contains("folderOpen") && text.contains(".woff") {
        out.push(found(
            Level::Danger,
            path,
            POLINRIDER,
            "This runs code hidden in a font file when the folder opens.",
            "PolinRider plants a VS Code task like this one, which runs node on a fake .woff font.",
        ));
    }
    if path.contains(".github/workflows/")
        && (name.ends_with(".yml") || name.ends_with(".yaml"))
        && (text.contains("toJSON(secrets)") || name == "shai-hulud-workflow.yml")
    {
        out.push(found(
            Level::Danger,
            path,
            SHAI_HULUD,
            "This GitHub workflow copies every secret in the repository.",
            "It dumps all of them at once with toJSON(secrets), the way Shai-Hulud's planted workflow does. Normal workflows almost never need every secret.",
        ));
    }

    // PolinRider: code hidden in a config file after a long run of spaces.
    if CONFIG.is_match(path) && HIDDEN_AFTER_SPACES.is_match(content) {
        out.push(found(
            Level::Danger,
            path,
            POLINRIDER,
            "Code is hidden in this config file, pushed off-screen by a long run of spaces.",
            "PolinRider appends its code to config files that build tools load, after 150 or more spaces so an editor doesn't show it.",
        ));
    }
    if name == ".gitignore" && text.lines().any(|l| l.trim() == "config.bat") {
        out.push(found(
            Level::Check,
            path,
            POLINRIDER,
            "This ignores a file that a known campaign uses.",
            "PolinRider adds config.bat to .gitignore so its script isn't committed by accident.",
        ));
    }
    out
}

fn re_planted(path: &str, name: &str) -> bool {
    path.split('/').any(|s| s == ".claude" || s == ".vscode") || (PAYLOADS.contains(&name) && !in_node_modules(path))
}

#[cfg(test)]
pub(crate) fn compromised(pkg: &str, version: &str) -> bool {
    indicators::current().packages.contains(&(pkg.to_string(), version.to_string()))
}
