# Contributing to LookFirst

Thanks for helping keep this useful. Issues and pull requests are both welcome.

## The rules LookFirst keeps

- **Read-only.** It never extracts, writes, runs, installs or imports anything it scans.
- **Offline by default.** No telemetry. The only network use is the user-triggered download of the signed threat list (`lookfirst --update`, or the button in the app).
- **Plain words first.** Every finding has a title anyone can act on, and a detail line for a developer.
- **Every indicator needs a public source**: a vendor report, an advisory, or a write-up. Link it in the pull request.
- **No false alarms on common files.** If a rule matches by name or pattern, check a normal project doesn't trip it.

## The threat list

Package versions, hashes, strings and addresses live in `crates/core/data/indicators.json`, not in code. Adding one is a data-only pull request: add the entry, raise `version`, set `updated`. Only the maintainer can sign it, so the pull request will be merged with a fresh `indicators.json.sig` (`cargo test -p lookfirst-core` fails until the two match).

Maintainer, to publish a list update without a release (it costs no CI minutes):

```bash
cargo run -p lookfirst-core --example sign -- sign ~/.lookfirst/signing.key
cargo test -p lookfirst-core
git add crates/core/data && git commit -m "Update the threat list" && git push
```

Users get it when they press **Update the list of known threats**. The private key never goes in the repo. A new `format` number is for list changes older programs can't read, and needs a release.

## Reporting

- **It flagged something that's fine (false positive)**, or **missed something it should catch**: open an issue with the matching template.
- **A security problem in LookFirst itself** (for example, it could write outside a folder or run code it reads): don't open an issue; see [SECURITY.md](SECURITY.md).
- **You think you've opened something malicious**: follow [If it says "Don't open this"](../README.md#if-it-says-dont-open-this) in the README first.

Never attach malware to an issue or pull request. Describe it, or share the hash and the public report it comes from.

## Changing the code

1. Fork, and make one change per pull request.
2. Rules live in `crates/core/src/rules/`, one file per ecosystem. Add a test to `crates/core/src/tests.rs` for any rule you add or change: one case it should catch, and one it shouldn't.
3. Run the tests: `cargo test -p lookfirst-core`.
4. Run the CLI on a real project or archive you know (`cargo run -p lookfirst -- PATH`), and say what you checked in the pull request.

## Code of conduct

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
