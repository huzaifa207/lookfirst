use super::*;

pub(super) fn claude_settings(path: &str, content: &[u8]) -> Option<Finding> {
    let json: Option<serde_json::Value> = serde_json::from_slice(content).ok();
    let hooks = match &json {
        Some(json) => match json.get("hooks").and_then(|h| h.as_object()) {
            Some(h) if !h.is_empty() => h,
            _ => return None,
        },
        None if contains(content, "\"hooks\"") => {
            return Some(finding(
                Level::Danger,
                path,
                "This runs commands when an AI coding assistant (Claude Code) works in the folder.",
                "Claude Code settings with hooks (the file isn't valid JSON, so the hooks couldn't be listed).",
            ))
        }
        None => return None,
    };
    let events: Vec<&str> = hooks.keys().map(String::as_str).collect();
    let commands: Vec<String> = serde_json::to_string(hooks)
        .ok()
        .map(|s| COMMAND.captures_iter(s.as_bytes()).take(3).map(|c| clip(&String::from_utf8_lossy(&c[1]))).collect())
        .unwrap_or_default();
    Some(finding(
        Level::Danger,
        path,
        "This runs commands when an AI coding assistant (Claude Code) starts or works in the folder.",
        format!("Claude Code hooks for {}. They run: {}.", events.join(", "), commands.join("; ")),
    ))
}

pub(super) fn mcp_servers(path: &str, content: &[u8]) -> Option<Finding> {
    let json: serde_json::Value = serde_json::from_slice(content).ok()?;
    let servers = json.get("mcpServers").or_else(|| json.get("servers"))?.as_object()?;
    if servers.is_empty() {
        return None;
    }
    let list: Vec<String> = servers
        .iter()
        .take(5)
        .map(|(name, s)| {
            let cmd = s.get("command").and_then(|c| c.as_str()).unwrap_or("a remote server");
            let args: Vec<&str> = s
                .get("args")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            format!("{name}: {}", clip(&format!("{cmd} {}", args.join(" "))))
        })
        .collect();
    Some(finding(
        Level::Check,
        path,
        "This starts programs when an AI assistant connects to the project.",
        format!("MCP servers, which the assistant asks before starting: {}.", list.join("; ")),
    ))
}
