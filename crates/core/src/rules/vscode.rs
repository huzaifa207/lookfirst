use super::*;

pub(super) static FOLDER_OPEN: LazyLock<Regex> = LazyLock::new(|| re(r#""runOn"\s*:\s*"folderOpen""#));

/// The commands of the tasks set to run on folder open, so a payload hidden among dozens of
/// normal tasks is the one shown. Falls back to the first few commands when the file has the
/// comments VS Code allows, which strict JSON doesn't.
pub(super) fn folder_open_commands(content: &[u8]) -> Vec<String> {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(content).ok();
    let tasks =
        parsed.as_ref().and_then(|v| v.pointer("/tasks/tasks").or_else(|| v.get("tasks"))).and_then(|t| t.as_array());
    if let Some(tasks) = tasks {
        let commands: Vec<String> = tasks
            .iter()
            .filter(|task| task.pointer("/runOptions/runOn").and_then(|r| r.as_str()) == Some("folderOpen"))
            .filter_map(|task| {
                let command = task.get("command")?.as_str()?;
                let args: Vec<&str> = task
                    .get("args")
                    .and_then(|a| a.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                    .unwrap_or_default();
                Some(clip(&format!("{command} {}", args.join(" "))))
            })
            .collect();
        if !commands.is_empty() {
            return commands;
        }
    }
    COMMAND.captures_iter(content).take(3).map(|c| clip(&String::from_utf8_lossy(&c[1]))).collect()
}
