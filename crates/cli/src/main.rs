//! lookfirst: check an archive or folder for code that runs by itself, before you open it.

use lookfirst_core::{list_info, scan_path, update_list, Level, Verdict};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
Usage: lookfirst [--json] PATH...
       lookfirst --update

Checks archives (zip, tar, tar.gz/.bz2/.xz, 7z), folders, or single files for code that runs
without anyone choosing to run it: Git hooks and settings, VS Code tasks, Claude Code hooks, npm
install scripts, programs dressed up as documents, and paths that escape the folder.
Nothing is extracted, run, or sent anywhere (--update only downloads).

  --json     print the reports as JSON
  --update   download the latest list of known threats (the only time LookFirst goes online)

Exit status: 0 nothing found, 1 something found, 2 something couldn't be read.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return if args.is_empty() { ExitCode::from(2) } else { ExitCode::SUCCESS };
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        let list = list_info();
        println!("lookfirst {} (threat list {}, {})", env!("CARGO_PKG_VERSION"), list.version, list.updated);
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--update") {
        return match update_list() {
            Ok(list) if list.changed => {
                println!("Updated the list of known threats to version {} ({}).", list.version, list.updated);
                ExitCode::SUCCESS
            }
            Ok(list) => {
                println!("Already up to date: version {} ({}).", list.version, list.updated);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Couldn't update: {e}");
                ExitCode::from(2)
            }
        };
    }
    let json = args.iter().any(|a| a == "--json");
    let reports: Vec<_> = args.iter().filter(|a| *a != "--json").map(|p| scan_path(Path::new(p))).collect();

    if json {
        let out: Vec<_> = reports.iter().map(|r| serde_json::json!({ "verdict": r.verdict(), "report": r })).collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        for report in &reports {
            let verdict = match report.verdict() {
                Verdict::Clear => "no known traps found",
                Verdict::Check => "look closer before opening",
                Verdict::Danger => "DON'T OPEN THIS",
                Verdict::Unreadable => "couldn't be read",
            };
            println!("{}: {verdict} ({} files checked)", report.source, report.files);
            for f in &report.findings {
                let level = match f.level {
                    Level::Danger => "DANGER",
                    Level::Check => "CHECK ",
                };
                let on = f.branch.as_ref().map(|b| format!("  (on {b})")).unwrap_or_default();
                println!("  {level}  {}{on}\n          {}", f.path, f.title);
                if let Some(campaign) = &f.campaign {
                    println!("          Matches a known campaign: {campaign}");
                }
                println!("          {}", f.detail);
            }
            for repo in &report.repos {
                let head = repo.head.as_deref().map(|h| format!(", checked out: {h}")).unwrap_or_default();
                println!("  GIT     {}{head}", repo.path);
                println!(
                    "          branches: {}",
                    if repo.branches.is_empty() { "none".into() } else { repo.branches.join(", ") }
                );
                if !repo.tags.is_empty() {
                    println!("          tags: {}", repo.tags.join(", "));
                }
                if let Some(note) = &repo.note {
                    println!("          {note}");
                }
            }
            for e in &report.errors {
                println!("  ERROR   {e}");
            }
        }
    }

    let verdicts: Vec<_> = reports.iter().map(|r| r.verdict()).collect();
    if verdicts.contains(&Verdict::Unreadable) {
        ExitCode::from(2)
    } else if verdicts.iter().any(|v| *v != Verdict::Clear) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
