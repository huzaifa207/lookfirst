use super::*;

pub(super) static DOWNLOAD: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\b(curl|wget)\b|invoke-webrequest|\biwr\b|downloadstring|downloadfile|urllib\.request|requests\.get|\bhttps?\.get\(|\bfetch\s*\(|axios\.get",
    )
});
/// Running something, in a shell script, PowerShell, Python or Node.
pub(super) static RUN: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(cmd|powershell|pwsh|python3?|node|iex)\b|chmod\s+\+x|invoke-expression|\biex\b|child_process|\bexecsync\s*\(|\bspawn\s*\(|new\s+function\s*\(|start-process|subprocess|os\.system",
    )
});
pub(super) static HIDDEN: LazyLock<Regex> = LazyLock::new(|| {
    re(r">\s*/dev/null\s+2>&1\s*&|\bnohup\b|\bdisown\b|-windowstyle\s+hidden|windowshide|detached\s*:\s*true")
});
pub(super) static BASE64: LazyLock<Regex> = LazyLock::new(|| {
    re(r"\batob\s*\(|base64\s+(-d|--decode|-D)\b|buffer\.from\([^)]{0,200}base64|b64decode|frombase64string")
});
pub(super) static HOSTING: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"[a-z0-9-]+\.(vercel\.app|netlify\.app|onrender\.com|glitch\.me|herokuapp\.com|workers\.dev|ngrok-free\.app|ngrok\.io|trycloudflare\.com)",
    )
});
/// `node fonts/fa-brand-400.woff`: code hidden in a file that shouldn't be code.
pub(super) static NOT_CODE: LazyLock<Regex> =
    LazyLock::new(|| re(r"\bnode\s+[^\s;&|]+\.(woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|txt|md|css)\b"));
pub(super) static COMMAND: LazyLock<Regex> = LazyLock::new(|| re(r#""command"\s*:\s*"((?:[^"\\]|\\.)*)""#));

pub(super) fn re(pattern: &str) -> Regex {
    Regex::new(&format!("(?i){pattern}")).unwrap()
}

/// What the code in a file does, in plain words: "downloads something, runs it in the background…".
pub(super) fn signs(content: &[u8]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (pattern, sign) in [
        (&*DOWNLOAD, "downloads something"),
        (&*RUN, "runs a program or makes a file executable"),
        (&*HIDDEN, "hides what it runs"),
        (&*BASE64, "decodes hidden (base64) text"),
        (&*HOSTING, "contacts a free hosting address"),
        (&*NOT_CODE, "runs a file that shouldn't be code (a font or image)"),
    ] {
        if pattern.is_match(content) {
            out.push(sign);
        }
    }
    out
}

pub(super) fn describe(signs: &[&str]) -> String {
    match signs {
        [] => String::new(),
        [only] => format!(" It {only}."),
        [rest @ .., last] => format!(" It {}, and {last}.", rest.join(", ")),
    }
}

/// Downloads something and runs it, or runs a file that shouldn't be code.
pub(super) fn alarming(content: &[u8]) -> bool {
    (DOWNLOAD.is_match(content) && RUN.is_match(content)) || NOT_CODE.is_match(content)
}

pub(super) fn clip(text: &str) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match text.char_indices().nth(160) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text,
    }
}

pub(super) fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}
