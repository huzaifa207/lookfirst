//! lookfirst: check an archive or folder for code that runs by itself, before you open it.

use clap::Parser;
use lookfirst_core::{is_address, list_info, scan_path, scan_url, update_list, Level, Verdict};
use std::path::PathBuf;
use std::process::ExitCode;

/// Checks archives (zip, tar, tar.gz/.bz2/.xz, 7z), Git bundles, folders, single files, or a Git
/// repository at an https or ssh address, for code that runs
/// without anyone choosing to run it: Git hooks and settings, VS Code tasks, Claude Code hooks, npm
/// install scripts, programs dressed up as documents, and paths that escape the folder.
/// Nothing is extracted or run. An address is read without cloning (nothing is sent but the requests
/// Git itself makes), and --update downloads; everything else works offline.
///
/// Private repositories: an ssh address uses your own ssh keys; for https, set LOOKFIRST_TOKEN to an
/// access token with read access (it is only sent to github.com, gitlab.com and bitbucket.org, or
/// hosts named in LOOKFIRST_TOKEN_HOST).
///
/// Exit status: 0 nothing found, 1 something found, 2 something couldn't be read.
#[derive(Parser)]
#[command(name = "lookfirst", disable_version_flag = true, arg_required_else_help = true)]
struct Cli {
    /// Archives, folders or files to check, or https://host/owner/repo and git@host:owner/repo addresses
    #[arg(required_unless_present_any = ["update", "version"])]
    paths: Vec<PathBuf>,
    /// Print the reports as JSON
    #[arg(long)]
    json: bool,
    /// Download the latest list of known threats (the only time LookFirst goes online)
    #[arg(long, conflicts_with = "paths")]
    update: bool,
    /// Print the version
    #[arg(short = 'V', long)]
    version: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.version {
        let list = list_info();
        println!("lookfirst {} (threat list {}, {})", env!("CARGO_PKG_VERSION"), list.version, list.updated);
        return ExitCode::SUCCESS;
    }
    if cli.update {
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
    let json = cli.json;
    // A private repository over https: the token is only ever sent to github.com, gitlab.com or
    // bitbucket.org (or hosts named in LOOKFIRST_TOKEN_HOST), never to an address someone else chose.
    let token = std::env::var("LOOKFIRST_TOKEN").ok();
    let reports: Vec<_> = cli
        .paths
        .iter()
        .map(|p| match p.to_str() {
            Some(url) if is_address(url) => scan_url(url, token.as_deref()),
            _ => scan_path(p),
        })
        .collect();

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
