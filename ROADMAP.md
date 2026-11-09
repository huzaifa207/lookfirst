# Roadmap

Ideas for LookFirst, roughly by value. Nothing here is promised or scheduled. To discuss or vote on one, open an issue or react with 👍. Each idea below is tracked in an issue labeled `roadmap`.

## Architecture notes

- `crates/core` is a scanner library with no UI. Its only network use is the user-triggered list update. The CLI (`crates/cli`) and the desktop app (`app/`) both call it, so a new check reaches both.
- `rules/` has one file per ecosystem. A new ecosystem gets its own file.
- The threat list is `crates/core/data/indicators.json`, signed, and embedded as the default. `lookfirst --update` and the app button fetch a newer signed copy, so a new indicator needs no release.
- The app isn't code-signed yet, so first launch shows a warning on Mac and Windows.
- The CLI uses `clap`, so new options (a `--format`, an ignore file) are one field each.

## Ideas

1. **RAR support.** ([#1](https://github.com/huzaifa207/lookfirst/issues/1)) Listed as missing in the README, and common in lure archives.
2. **More auto-run vectors.** ([#2](https://github.com/huzaifa207/lookfirst/issues/2))
   - Python: `setup.py`, `.pth` files, `conftest.py`, `sitecustomize.py`
   - Cargo `build.rs`
   - Makefile
   - Gradle and Maven plugins
   - `.vscode/settings.json` and `extensions.json`
   - JetBrains run configurations
   - Cursor, Windsurf and Copilot config (`.cursor/`, `.cursorrules`)
   - Dev containers: `devcontainer.json` `postCreateCommand`
   - macOS `.pkg` and `.command` files
   - Linux `.desktop` files
3. **Scan a Git URL or Git bundle without cloning.** ([#3](https://github.com/huzaifa207/lookfirst/issues/3)) Cloning is where hooks would fire.
4. **Check older commits and unmerged refs.** ([#4](https://github.com/huzaifa207/lookfirst/issues/4)) Today only branch tips are checked. Add stash, reflog and packed history.
5. **Obfuscation and payload heuristics.** ([#5](https://github.com/huzaifa207/lookfirst/issues/5)) Base64 or hex blobs followed by `eval`, `Function(...)` or `child_process`, long minified lines in config files, and `curl | sh`.
6. ~~**Updatable indicator feed.**~~ ([#6](https://github.com/huzaifa207/lookfirst/issues/6)) Done: a signed list, fetched only on request.
7. **More named campaigns.** ([#7](https://github.com/huzaifa207/lookfirst/issues/7)) Contagious Interview and other npm and PyPI worms, using the method already used for Shai-Hulud and PolinRider.
8. **CI output formats.** ([#8](https://github.com/huzaifa207/lookfirst/issues/8)) SARIF for GitHub code scanning, plus a GitHub Action around the CLI.
9. **Lockfile checks against OSV or npm advisories.** ([#9](https://github.com/huzaifa207/lookfirst/issues/9)) Opt-in, for known-malicious packages beyond Shai-Hulud.
10. **Multi-item drag-and-drop and report history** ([#10](https://github.com/huzaifa207/lookfirst/issues/10)) in the app.
11. **Distribution.** ([#11](https://github.com/huzaifa207/lookfirst/issues/11)) Code signing, Homebrew and winget packages, and a crates.io release.
12. **Suppression file.** ([#12](https://github.com/huzaifa207/lookfirst/issues/12)) A `.lookfirstignore` or allow-list so the CLI is usable in CI on repos with known-benign hooks.

## Suggested order

1. RAR (#1) and the extra auto-run vectors (#2).
2. Git URL and bundle scan (#3) and SARIF output (#8).
3. Then #4, #5, #12, then the opt-in network features (#6, #9) and distribution (#11).
