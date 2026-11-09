# LookFirst

**Check a project or a pack of files for code that runs by itself, before you open it.**

Fake recruiters and "clients" send developers, and the people who hire them, archives that look like documentation or a code test. Inside is a file one of your tools runs for you: a Git hook that fires when you switch branches, a VS Code task that runs when you open the folder, an install script, a program named like a PDF. Nobody has to double-click anything.

LookFirst opens the archive in place, tells you in plain words what would run and when, and gives a developer the details. If the archive holds a Git repository, it checks every branch and tag too, without running Git, and lists the branches it found. It never extracts, runs, or uploads anything. It works offline; the one thing that goes online is the **Update the list of known threats** button (or `lookfirst --update`), which only downloads, and only when you ask.

![LookFirst warning "Don't open this" about an archive: a Git hook that runs code when someone switches branches, a VS Code task on the NDA branch that runs when the folder opens, and a program pretending to be a PDF. Below, the repository's branches, main and NDA, and its tag.](docs/result.png)

## Download

Get the app for your computer from the [latest release](https://github.com/huzaifa207/lookfirst/releases/latest):

| Computer | File |
|---|---|
| Mac (Apple silicon or Intel) | `LookFirst_…_universal.dmg` |
| Windows | `LookFirst_…_x64-setup.exe` (or the `.msi`) |
| Linux | `.AppImage`, `.deb` or `.rpm` |

**The first time you open it,** your computer will warn you, because the app isn't code-signed yet:

- **Mac:** open it once, choose **Done**, then go to **System Settings → Privacy & Security**, scroll down, and choose **Open Anyway** next to LookFirst.
- **Windows:** on the blue "Windows protected your PC" screen, choose **More info**, then **Run anyway**.

Only do this for an app you downloaded from this page.

## Use it

Drop a file on the window, or click to choose one. It reads `.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz` and `.7z` files, folders, and single files, including archives inside archives.

You get one of three answers:

- **Don't open this:** something in it runs code by itself, or pretends to be something it isn't.
- **Look closer before opening:** some files can run code, which is normal in many projects but worth a developer's look.
- **No known traps found:** nothing it knows about. That isn't a promise the files are safe.

When the archive holds a Git repository, the report lists its branches and tags, and marks anything found on a branch other than the one that's open: "On branch NDA, not in the files as they are now". Checking out that branch would bring it in.

**Copy the report** puts the findings on your clipboard, to send to whoever checks it next.

### Browse the files

**Browse the files** opens a read-only view of everything inside: the folders on the left, with a dot on anything flagged, and the file you pick on the right. **Show this file** on a finding jumps straight to it. Pick a branch or tag to see the files on it instead.

Files are read in memory and shown as plain text. Nothing is extracted, opened in another app, run, or rendered: HTML, scripts and links inside a file are shown as characters. Binary files aren't shown at all. The viewer also shows what code editors hide:

- **Invisible and direction-reversing characters** are marked in place, like `U+202E`. They can make code read differently from how it runs ("Trojan Source").
- **Long runs of spaces** that push code off the right edge of the screen are shortened to a visible marker, so whatever follows them is in plain view.

## What it checks

| What | Runs when | Level |
|---|---|---|
| Git hooks in `.git/hooks/` | Someone switches branches, commits, pulls or pushes | Danger (Check if not executable) |
| Git settings in `.git/config` that run programs (`core.hooksPath`, `core.fsmonitor`, filters, pagers, editors, aliases) | Everyday Git commands | Danger or Check |
| `.githooks/` and `.husky/` folders | Once Git or `npm install` switches them on | Check |
| VS Code tasks set to `"runOn": "folderOpen"` | The folder is opened in VS Code | Danger |
| Claude Code hooks in `.claude/settings.json` | An AI assistant session starts or works in the folder | Danger |
| MCP servers in `.mcp.json` | An AI assistant connects to the project | Check |
| npm install scripts in `package.json` | `npm install` | Check (Danger if they download and run something) |
| `.envrc` | A terminal opens in the folder, with direnv | Check |
| Programs named like documents (`brief.pdf.exe`), hidden reversed names, `.lnk`, `.scr`, `.hta`, `.vbs` and similar | Double-clicked | Danger |
| Other programs and scripts (`.exe`, `.bat`, `.ps1`, `.dmg`, Mac apps), Office files with macros | Opened | Check |
| Scripts that download something and run it, or run a font or image as code | Run | Check |
| Code pushed off-screen by a long run of spaces | Read in an editor | Check (Danger in a build-tool config) |
| Paths that climb out of the folder, and links that point outside it | Extracted | Danger |
| Password-protected files | Can't be checked | Check |
| Any of the above on another branch or tag | That branch is checked out | Same as above, marked with the branch |
| Addresses from published reports | | Danger |

### Known campaigns

On top of the general checks, LookFirst carries the indicators of two campaigns, ported from the scanners written for them. A match says which campaign it is.

- **The Shai-Hulud npm worm** ([shai-hulud-scan](https://github.com/huzaifa207/shai-hulud-scan)): the 2,300+ infected package versions it published, in `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` and `bun.lock` files and in installed packages; its loader in install scripts, VS Code tasks and Claude Code hooks; its payload files, by hash, marker strings and where it plants them; and the workflow it adds to copy every repository secret.
- **PolinRider** ([polinrider-scan](https://github.com/huzaifa207/polinrider-scan)): its fake Font Awesome files and the VS Code task that runs one, code hidden in build-tool config files after a long run of spaces, its obfuscator's marker strings, its push script, and the line it adds to `.gitignore`.

The checks on your GitHub account itself, like force-pushed commits or a repository the worm made to upload your secrets, stay with those two scanners.

## If it says "Don't open this"

1. **Don't extract it, open it in an editor, or use Git on it.** Keep the original file.
2. **Send the report to your IT or security team** with **Copy the report**, and ask the sender to explain what the flagged files are for.
3. **If you already opened it** and it ran (you switched branches, opened the folder in VS Code, or ran `npm install`), treat the computer as compromised: from a different device, change your passwords and revoke any tokens and SSH keys it held, move any crypto to a new wallet, and get the machine checked.

## The command line

The same checks, for developers and CI. With Rust installed:

```bash
cargo install --git https://github.com/huzaifa207/lookfirst lookfirst
lookfirst ~/Downloads/pack.zip
```

```
lookfirst [--json] PATH...
lookfirst --update
```

`--update` downloads the newest list of known threats (infected package versions, file hashes, campaign strings). The list is signed by the maintainer; anything unsigned or older is thrown away, and the copy built into the program is used if the download fails. Nothing about you or your files is sent.

It exits with `0` when nothing is found, `1` when something is, and `2` when a file couldn't be read, so it can gate a CI job or a script that accepts uploads.

## Limits

- **On other branches, it reads the files that run by themselves.** It compares each branch and tag with the open one, checks every differing file by name, and reads the contents of the ones that can run code (hooks, editor and assistant settings, install scripts). It doesn't read every script on every branch, and it checks branch tips, not old commits.
- **The viewer shows the first 2 MB and 20,000 lines of a file,** and lists up to 100,000 entries.
- **Very large repositories are compared up to 200,000 files,** and Git data in an archive up to 512 MB. The report says when it stopped short.
- **It knows patterns, not intent.** Heavily disguised code can get past it, and a normal project can trip a Check.
- **RAR files aren't supported yet.** It says so instead of guessing.
- **No guarantees.** "No known traps found" means nothing it knows about, not that the files are safe.

## Build it

```bash
cargo test -p lookfirst-core      # the scanner's tests
cargo run -p lookfirst -- PATH     # the CLI
cargo install tauri-cli --version "^2" --locked
cd app && cargo tauri dev          # the desktop app
```

The scanner is `crates/core`, the CLI `crates/cli`, and the app `app/` (Tauri, with a plain HTML window). Only the core's `update_list` touches the network.

## Sources

- [OpenSourceMalware: Lazarus Group uses Git hooks to hide malware](https://opensourcemalware.com/blog/lazarus-group-uses-git-hooks-to-hide-malware)
- [CSO Online: Contagious Interview attackers go full stack to fool developers](https://www.csoonline.com/article/4098699/contagious-interview-attackers-go-full-stack-to-fool-developers.html)
- [Git documentation: githooks](https://git-scm.com/docs/githooks) and [git-config](https://git-scm.com/docs/git-config)
- [How a job offer's Git hook led to LookFirst](https://itshuzaifa.com/writing/contagious-interview-git-hook/)

## License

[MIT](LICENSE)
