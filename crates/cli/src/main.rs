//! lookfirst: check an archive or folder for code that runs by itself, before you open it.

use lookfirst_core::{scan_path, Level, Verdict};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
Usage: lookfirst [--json] PATH...

Checks archives (zip, tar, tar.gz/.bz2/.xz, 7z), folders, or single files for code that runs
without anyone choosing to run it: Git hooks and settings, VS Code tasks, Claude Code hooks, npm
install scripts, programs dressed up as documents, and paths that escape the folder.
Nothing is extracted, run, or sent anywhere.

  --json   print the reports as JSON

Exit status: 0 nothing found, 1 something found, 2 something couldn't be read.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return if args.is_empty() { ExitCode::from(2) } else { ExitCode::SUCCESS };
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("lookfirst {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
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
                println!("  {level}  {}\n          {}\n          {}", f.path, f.title, f.detail);
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
