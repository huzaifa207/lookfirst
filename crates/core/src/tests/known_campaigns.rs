//! Known campaigns: the checks from shai-hulud-scan and polinrider-scan, with their fixtures.

use super::*;

const NPM_V3: &str = r#"{"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/keyv": {"version": "6.0.0"},
    "node_modules/a/node_modules/flat-cache": {"version": "6.1.23"},
    "node_modules/alias": {"name": "@cacheable/memory", "version": "2.2.1"}}}"#;

const NPM_V1: &str = r#"{"lockfileVersion": 1, "dependencies": {
    "a": {"version": "1.0.0", "dependencies": {"ecto": {"version": "5.0.1"}}}}}"#;

const YARN_V1: &str = "# yarn lockfile v1\n\n\"@cacheable/utils@^2.5.0\", \"@cacheable/utils@~2.5.1\":\n  version \"2.5.1\"\n  resolved \"https://registry.yarnpkg.com/@cacheable/utils/-/utils-2.5.1.tgz\"\n\ncacheable@^2.5.0:\n  version \"2.5.0\"\n";

const YARN_BERRY: &str = "__metadata:\n  version: 8\n\n\"cache-manager@npm:^7.2.0\":\n  version: 7.2.10\n  resolution: \"cache-manager@npm:7.2.10\"\n\n\"kv@npm:keyv@^6\":\n  version: 6.0.0\n";

const PNPM_V9: &str = "packages:\n\n  '@cacheable/net@2.1.1':\n    resolution: {integrity: sha512-x}\n\nsnapshots:\n\n  file-entry-cache@11.1.6(eslint@9.0.0):\n    dependencies:\n      flat-cache: 6.1.24\n";

const PNPM_V5: &str = "packages:\n\n  /cacheable-request/13.0.20:\n    resolution: {integrity: sha512-x}\n  /@cacheable/node-cache/3.1.1_typescript@5.0.0:\n    dev: true\n";

const BUN: &str = r#"{ "packages": {
    "keyv": ["keyv@6.0.0", "", {}, "sha512-x"],
    "@cacheable/memory": ["@cacheable/memory@2.2.0", "", {}, "sha512-y"],
} }"#;

fn pair(p: &str, v: &str) -> (String, String) {
    (p.to_string(), v.to_string())
}

#[test]
fn lockfiles_of_every_kind() {
    let npm = campaigns::locked("package-lock.json", NPM_V3);
    let bad: std::collections::HashSet<_> = npm.iter().filter(|(p, v)| campaigns::compromised(p, v)).cloned().collect();
    assert_eq!(bad, [pair("keyv", "6.0.0"), pair("@cacheable/memory", "2.2.1")].into());
    assert!(campaigns::locked("package-lock.json", NPM_V1).contains(&pair("ecto", "5.0.1")));
    let v1 = campaigns::locked("yarn.lock", YARN_V1);
    assert!(v1.contains(&pair("@cacheable/utils", "2.5.1")) && v1.contains(&pair("cacheable", "2.5.0")));
    let berry = campaigns::locked("yarn.lock", YARN_BERRY);
    assert!(
        berry.contains(&pair("cache-manager", "7.2.10")) && berry.contains(&pair("keyv", "6.0.0")),
        "through the alias"
    );
    let v9 = campaigns::locked("pnpm-lock.yaml", PNPM_V9);
    assert!(v9.contains(&pair("@cacheable/net", "2.1.1")) && v9.contains(&pair("file-entry-cache", "11.1.6")));
    let v5 = campaigns::locked("pnpm-lock.yaml", PNPM_V5);
    assert!(v5.contains(&pair("cacheable-request", "13.0.20")) && v5.contains(&pair("@cacheable/node-cache", "3.1.1")));
    assert_eq!(campaigns::locked("bun.lock", BUN), [pair("keyv", "6.0.0"), pair("@cacheable/memory", "2.2.0")].into());
    // The versions the CSA advisory names.
    for (p, v) in [("keyv", "6.0.0"), ("@cacheable/node-cache", "3.1.2"), ("ecto", "5.0.1")] {
        assert!(campaigns::compromised(p, v), "{p}@{v}");
    }
    // The November 2025 wave (Datadog's consolidated list), a separate set from ChainDrop's.
    assert!(
        campaigns::compromised("02-echo", "0.0.7") && campaigns::compromised("@accordproject/concerto-types", "3.24.1")
    );
    assert_eq!(campaigns::spec("\"@s/p@npm:^1.0.0\""), "@s/p");
    assert_eq!(campaigns::spec("foo@npm:@s/bar@^2"), "@s/bar");
    assert_eq!(campaigns::spec(" foo@~1.2"), "foo");
}

fn campaign_of(report: &Report, path: &str) -> Option<(Level, String)> {
    report.findings.iter().find(|f| f.path == path).map(|f| (f.level, f.campaign.clone().unwrap_or_default()))
}

#[test]
fn shai_hulud_in_a_pack() {
    let shai = || (Level::Danger, campaigns::SHAI_HULUD.to_string());
    let report = scan(&zip_of(&[
        f("app/package-lock.json", NPM_V3),
        f("app/bun.lock", BUN),
        f("app/node_modules/keyv/package.json", r#"{"name": "keyv", "version": "6.0.0"}"#),
        f("app/node_modules/safe/package.json", r#"{"name": "keyv", "version": "5.3.3"}"#),
        f("lib/package.json", r#"{"scripts": {"preinstall": "node setup.mjs"}}"#),
        f("ok/package.json", r#"{"scripts": {"preinstall": "npx only-allow pnpm"}}"#),
        f(
            "a/.vscode/tasks.json",
            r#"{"tasks": [{"label": "Environment Setup", "command": "node .claude/setup.mjs", "runOptions": {"runOn": "folderOpen"}}]}"#,
        ),
        f(
            "b/.claude/settings.json",
            r#"{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .vscode/setup.mjs"}]}]}}"#,
        ),
        f("c/.github/workflows/codeql_analysis.yml", "env:\n  DATA: ${{ toJSON(secrets) }}\n"),
        f("c/.github/workflows/ci.yml", "env:\n  TOKEN: ${{ secrets.NPM_TOKEN }}\n"),
        f("d/.claude/math_init.js", "anything"),
        f("d/Math_Symbol.js", "anything"),
        f("d/node_modules/regenerate-unicode-properties/General_Category/Math_Symbol.js", "module.exports=set"),
        f("d/node_modules/x/setup.mjs", "var a='thebeautifulmarchoftime ';"),
        f("d/scripts/setup.mjs", "console.log('set up')"),
    ]));
    let all = titles(&report).join("\n");
    for path in [
        "app/package-lock.json",
        "app/bun.lock",
        "app/node_modules/keyv/package.json",
        "lib/package.json",
        "a/.vscode/tasks.json",
        "b/.claude/settings.json",
        "c/.github/workflows/codeql_analysis.yml",
        "d/node_modules/x/setup.mjs",
    ] {
        assert_eq!(campaign_of(&report, path), Some(shai()), "{path}\n{all}");
    }
    for path in ["d/.claude/math_init.js", "d/Math_Symbol.js"] {
        assert_eq!(campaign_of(&report, path), Some((Level::Check, campaigns::SHAI_HULUD.into())), "{path}\n{all}");
    }
    // An ordinary install script is still a plain Check, just not the worm's.
    assert_eq!(campaign_of(&report, "ok/package.json"), Some((Level::Check, String::new())), "{all}");
    for path in ["app/node_modules/safe/package.json", "c/.github/workflows/ci.yml", "d/scripts/setup.mjs"] {
        assert!(report.findings.iter().all(|f| f.path != path), "{path} is fine\n{all}");
    }
    assert!(
        report.findings.iter().all(|f| !f.path.contains("regenerate-unicode-properties")),
        "the genuine Unicode table\n{all}"
    );
    let lock = report.findings.iter().find(|f| f.path == "app/package-lock.json").unwrap();
    assert!(lock.detail.contains("keyv@6.0.0") && lock.detail.contains("@cacheable/memory@2.2.1"), "{}", lock.detail);
    // One card per file: the install script's plain finding folds under the worm's loader.
    assert_eq!(report.findings.iter().filter(|f| f.path == "lib/package.json").count(), 1, "{all}");
}

#[test]
fn polinrider_in_a_pack() {
    let pr = || Some((Level::Danger, campaigns::POLINRIDER.to_string()));
    let hidden =
        format!("module.exports = {{ reactStrictMode: true }};{}global['!']='x';eval(atob(p))\n", " ".repeat(200));
    let padded = format!("export const x = 1;{}fetch('/x')\n", " ".repeat(180));
    let report = scan(&zip_of(&[
        f("site/api/public/fonts/fa-brand-400.woff", "not a font"),
        f("site/public/fonts/fa-brands-400.woff", "a real font"),
        f("site/next.config.js", &hidden),
        f("ok/next.config.js", "module.exports = { reactStrictMode: true };\n"),
        f("site/src/util.js", &padded),
        f(
            "site/.vscode/tasks.json",
            r#"{"tasks": [{"label": "eslint-check", "command": "node ./api/public/fonts/fa-brand-400.woff", "runOptions": {"runOn": "folderOpen"}}]}"#,
        ),
        f("site/.gitignore", "node_modules\nconfig.bat\n"),
        f("site/temp_auto_push.bat", "@echo off"),
    ]));
    let all = titles(&report).join("\n");
    for path in [
        "site/api/public/fonts/fa-brand-400.woff",
        "site/next.config.js",
        "site/.vscode/tasks.json",
        "site/temp_auto_push.bat",
    ] {
        assert_eq!(campaign_of(&report, path), pr(), "{path}\n{all}");
    }
    assert_eq!(campaign_of(&report, "site/.gitignore"), Some((Level::Check, campaigns::POLINRIDER.into())), "{all}");
    assert_eq!(
        campaign_of(&report, "site/src/util.js"),
        Some((Level::Check, String::new())),
        "padding alone is a Check\n{all}"
    );
    for path in ["site/public/fonts/fa-brands-400.woff", "ok/next.config.js"] {
        assert!(report.findings.iter().all(|f| f.path != path), "{path} is fine\n{all}");
    }
}

#[test]
fn an_infected_lockfile_on_another_branch() {
    let dir = trapped_repo();
    let repo = dir.path().join("pack");
    git(&repo, &["checkout", "-q", "-b", "deps", "main"]);
    std::fs::write(repo.join("package-lock.json"), NPM_V3).unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "deps"]);
    git(&repo, &["checkout", "-q", "main"]);
    let report = scan(&tar_dir(dir.path()));
    let lock = report.findings.iter().find(|f| f.path == "pack/package-lock.json").expect("found on the branch");
    assert_eq!((lock.branch.as_deref(), lock.campaign.as_deref()), (Some("deps"), Some(campaigns::SHAI_HULUD)));
}

#[test]
fn scanners_that_name_markers_are_not_malware() {
    let list = r#"const MARKERS = ["global['!']", "global['_V']", '_$_1e42', 'rmcej%otb%', 'Cot%3t=shtP'];"#;
    let py = "MARKERS = (\"global['!']\", \"_$_1e42\", \"rmcej%otb%\")\n";
    let report = scan(&zip_of(&[
        f("tools/check-repo.mjs", list),
        f("tools/scan.py", py),
        // Used as code: the assignment and the obfuscator's own names, unquoted.
        f("real/a.js", "var x=1;global['!']='8-24';var _$_1e42=(function(l,e){})();\n"),
        // The same with a quoted decoy added: the unquoted marker still counts.
        f("real/b.js", "var decoy = \"global['!']\"; global['!']='8-24';\n"),
        // Shai-Hulud carries its markers inside quoted strings, so quotes mean nothing for them.
        f("real/c.js", "const m = \"thebeautifulmarchoftime\";\n"),
    ]));
    let all = titles(&report).join("\n");
    for path in ["tools/check-repo.mjs", "tools/scan.py"] {
        let found = report.findings.iter().find(|f| f.path == path).unwrap_or_else(|| panic!("{path}\n{all}"));
        assert_eq!((found.level, found.campaign.clone()), (Level::Check, None), "{path}\n{all}");
        assert!(found.title.contains("only as text"), "{}", found.title);
    }
    for path in ["real/a.js", "real/b.js", "real/c.js"] {
        let found = report.findings.iter().find(|f| f.path == path).unwrap_or_else(|| panic!("{path}\n{all}"));
        assert_eq!(found.level, Level::Danger, "{path}\n{all}");
        assert!(found.campaign.is_some(), "{path}\n{all}");
    }
}
