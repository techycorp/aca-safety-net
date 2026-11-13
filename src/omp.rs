//! Translation of oh-my-pi (omp) tool calls into the Claude Code tool calls
//! the analyzers check.
//!
//! omp tools take `path` where Claude Code tools take `file_path`, and omp's
//! `eval` tool runs Python or JavaScript cells directly. Each omp call becomes
//! one or more Claude Code calls; the most severe decision among them applies.

use crate::input::HookInput;
use serde_json::{Value, json};

/// Claude Code tool calls that together cover one omp tool call.
pub fn translate(input: &HookInput) -> Vec<HookInput> {
    let args = &input.tool_input;
    match input.tool_name.as_str() {
        "bash" => str_field(args, "command")
            .map(|command| bash(input, command, bash_cwd(input)))
            .into_iter()
            .collect(),
        "read" => str_field(args, "path")
            .map(|path| claude(input, "Read", json!({ "file_path": path })))
            .into_iter()
            .collect(),
        "write" => str_field(args, "path")
            .map(|path| {
                let content = str_field(args, "content").unwrap_or_default();
                claude(
                    input,
                    "Write",
                    json!({ "file_path": path, "content": content }),
                )
            })
            .into_iter()
            .collect(),
        "edit" => paths(args)
            .into_iter()
            .map(|path| {
                claude(
                    input,
                    "Edit",
                    json!({ "file_path": path, "old_string": "", "new_string": "" }),
                )
            })
            .collect(),
        "grep" => path_tool(input, "Grep"),
        "glob" => path_tool(input, "Glob"),
        "eval" => eval(input),
        _ => generic(input),
    }
}

fn claude(input: &HookInput, tool: &str, tool_input: Value) -> HookInput {
    HookInput {
        tool_name: tool.to_string(),
        tool_input,
        cwd: input.cwd.clone(),
        session_id: input.session_id.clone(),
    }
}

fn bash(input: &HookInput, command: &str, cwd: Option<String>) -> HookInput {
    HookInput {
        cwd,
        ..claude(input, "Bash", json!({ "command": command }))
    }
}

/// The bash tool's own `cwd`, resolved against the session's.
fn bash_cwd(input: &HookInput) -> Option<String> {
    match (str_field(&input.tool_input, "cwd"), &input.cwd) {
        (Some(dir), _) if dir.starts_with('/') => Some(dir.to_string()),
        (Some(dir), Some(base)) => Some(format!("{}/{}", base.trim_end_matches('/'), dir)),
        (Some(dir), None) => Some(dir.to_string()),
        (None, base) => base.clone(),
    }
}

fn path_tool(input: &HookInput, tool: &str) -> Vec<HookInput> {
    vec![claude(
        input,
        tool,
        json!({ "path": str_field(&input.tool_input, "path").unwrap_or(".") }),
    )]
}

/// Tools without a dedicated translation: the call as it is, plus one call
/// per entry of a `paths` list.
fn generic(input: &HookInput) -> Vec<HookInput> {
    let mut calls = vec![input.clone()];
    if let Some(list) = input.tool_input.get("paths").and_then(Value::as_array) {
        calls.extend(
            list.iter()
                .filter_map(Value::as_str)
                .map(|path| claude(input, &input.tool_name, json!({ "path": path }))),
        );
    }
    calls
}

/// An eval cell checked as the shell command that would run the same code
/// (`python -c CODE` or `node -e CODE`), plus each IPython shell escape and
/// magic in a Python cell checked as a shell command of its own.
fn eval(input: &HookInput) -> Vec<HookInput> {
    let Some(code) = str_field(&input.tool_input, "code") else {
        return Vec::new();
    };
    let cwd = input.cwd.clone();
    if str_field(&input.tool_input, "language") == Some("js") {
        return vec![bash(input, &format!("node -e {}", shell_quote(code)), cwd)];
    }
    let mut calls = vec![bash(
        input,
        &format!("python -c {}", shell_quote(code)),
        cwd.clone(),
    )];
    calls.extend(
        ipython_shell_commands(code)
            .iter()
            .map(|command| bash(input, command, cwd.clone())),
    );
    calls
}

/// Cell magics whose body is a shell script.
const SHELL_CELL_MAGICS: &[&str] = &["bash", "sh", "zsh", "script", "system", "sx"];

/// Shell commands an IPython cell runs: `!cmd` and `var = !cmd` lines,
/// `%magic args` lines as the command `magic args`, and a cell magic's header
/// the same way, with the body of a shell cell magic as a script.
pub fn ipython_shell_commands(code: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let lines: Vec<&str> = code.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if let Some(cell) = trimmed.strip_prefix("%%") {
            commands.push(cell.trim().to_string());
            let name = cell.split_whitespace().next().unwrap_or_default();
            if SHELL_CELL_MAGICS.contains(&name) {
                commands.push(lines[i + 1..].join("\n"));
            }
            break;
        }
        let escaped = match trimmed.split_once('=') {
            Some((lhs, rhs)) if is_identifier(lhs.trim()) => rhs.trim_start(),
            _ => trimmed,
        };
        if let Some(shell) = escaped.strip_prefix('!') {
            commands.push(shell.trim_start_matches('!').trim().to_string());
        } else if let Some(magic) = escaped.strip_prefix('%') {
            commands.push(magic.trim().to_string());
        }
    }
    commands.retain(|c| !c.is_empty());
    commands
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
        && chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// A single-quoted shell word holding `s` exactly.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// The paths an edit call targets: its `paths` list, else its `path`.
fn paths(args: &Value) -> Vec<String> {
    let listed: Vec<String> = args
        .get("paths")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    if !listed.is_empty() {
        return listed;
    }
    str_field(args, "path")
        .map(|p| vec![p.to_string()])
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn omp(tool: &str, tool_input: Value) -> HookInput {
        HookInput {
            tool_name: tool.to_string(),
            tool_input,
            cwd: Some("/work".to_string()),
            session_id: None,
        }
    }

    #[test]
    fn test_bash_maps_command_and_relative_cwd() {
        let calls = translate(&omp("bash", json!({ "command": "ls", "cwd": "sub" })));
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tool_name, "Bash");
        assert_eq!(calls[0].command(), Some("ls"));
        assert_eq!(calls[0].cwd.as_deref(), Some("/work/sub"));
    }

    #[test]
    fn test_bash_absolute_cwd() {
        let calls = translate(&omp("bash", json!({ "command": "ls", "cwd": "/tmp" })));
        assert_eq!(calls[0].cwd.as_deref(), Some("/tmp"));
    }

    #[test]
    fn test_read_write_map_path_to_file_path() {
        let read = translate(&omp("read", json!({ "path": "a.txt" })));
        assert_eq!(read[0].tool_name, "Read");
        assert_eq!(read[0].file_path(), Some("a.txt"));

        let write = translate(&omp("write", json!({ "path": "b.txt", "content": "x" })));
        assert_eq!(write[0].tool_name, "Write");
        assert_eq!(write[0].as_write().unwrap().content, "x");
    }

    #[test]
    fn test_write_without_content() {
        let write = translate(&omp("write", json!({ "path": "b.txt" })));
        assert_eq!(write[0].as_write().unwrap().content, "");
    }

    #[test]
    fn test_edit_one_call_per_path() {
        let calls = translate(&omp("edit", json!({ "input": "...", "paths": ["a", "b"] })));
        let targets: Vec<_> = calls.iter().filter_map(|c| c.file_path()).collect();
        assert_eq!(targets, vec!["a", "b"]);
        assert!(calls.iter().all(|c| c.as_edit().is_some()));
    }

    #[test]
    fn test_edit_single_path() {
        let calls = translate(&omp("edit", json!({ "path": "a" })));
        assert_eq!(calls[0].file_path(), Some("a"));
    }

    #[test]
    fn test_grep_and_glob_map_to_path_tools() {
        let grep = translate(&omp("grep", json!({ "pattern": "x", "path": "src" })));
        assert_eq!(grep[0].tool_name, "Grep");
        assert_eq!(grep[0].tool_paths(), vec!["src"]);

        let glob = translate(&omp("glob", json!({ "path": "**/*.rs" })));
        assert_eq!(glob[0].tool_name, "Glob");
        assert_eq!(glob[0].tool_paths(), vec!["**/*.rs"]);
    }

    #[test]
    fn test_generic_tool_checks_each_listed_path() {
        let calls = translate(&omp("ast_edit", json!({ "paths": ["a", "b"] })));
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].tool_paths(), vec!["b"]);
    }

    #[test]
    fn test_eval_python_as_python_c() {
        let calls = translate(&omp(
            "eval",
            json!({ "language": "py", "code": "print('hi')" }),
        ));
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].command(), Some(r"python -c 'print('\''hi'\'')'"));
    }

    #[test]
    fn test_eval_js_as_node_e() {
        let calls = translate(&omp("eval", json!({ "language": "js", "code": "1+1" })));
        assert_eq!(calls[0].command(), Some("node -e '1+1'"));
    }

    #[test]
    fn test_eval_without_code() {
        assert!(translate(&omp("eval", json!({ "language": "py" }))).is_empty());
    }

    #[test]
    fn test_ipython_shell_escapes_and_magics() {
        let code = "x = 1\n!ls -la\nout = !whoami\n!!date\n%cat notes.txt\ny = %pwd";
        assert_eq!(
            ipython_shell_commands(code),
            vec!["ls -la", "whoami", "date", "cat notes.txt", "pwd"]
        );
    }

    #[test]
    fn test_ipython_shell_cell_magic_body() {
        let code = "%%bash\ncat secrets.txt\necho done";
        assert_eq!(
            ipython_shell_commands(code),
            vec!["bash", "cat secrets.txt\necho done"]
        );
    }

    #[test]
    fn test_ipython_other_cell_magic_header_only() {
        assert_eq!(
            ipython_shell_commands("%%writefile out.txt\nhello"),
            vec!["writefile out.txt"]
        );
    }

    #[test]
    fn test_ipython_plain_python_has_no_commands() {
        assert!(ipython_shell_commands("a = b % c\nif a != b: pass").is_empty());
    }

    #[test]
    fn test_shell_quote_plain_and_with_quotes() {
        assert_eq!(shell_quote("abc"), "'abc'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
