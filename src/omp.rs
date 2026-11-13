//! Translation of oh-my-pi (omp) tool calls into the Claude Code tool calls
//! the analyzers check.
//!
//! omp tools take `path` where Claude Code tools take `file_path`, and omp's
//! `eval` tool runs Python or JavaScript cells directly. Each omp call becomes
//! one or more Claude Code calls; the most severe decision among them applies.

use crate::input::HookInput;
use serde_json::{Value, json};

/// Claude Code tool calls that together cover one omp tool call, or why the
/// call can't be checked: a known tool without the fields omp is known to send.
pub fn translate(input: &HookInput) -> Result<Vec<HookInput>, String> {
    let args = &input.tool_input;
    match input.tool_name.as_str() {
        "bash" => {
            let command = required(input, "command")?;
            Ok(vec![bash(input, command, bash_cwd(input))])
        }
        "read" => {
            let path = required(input, "path")?;
            Ok(vec![claude(input, "Read", json!({ "file_path": path }))])
        }
        "write" => {
            let path = required(input, "path")?;
            let content = str_field(args, "content").unwrap_or_default();
            Ok(vec![claude(
                input,
                "Write",
                json!({ "file_path": path, "content": content }),
            )])
        }
        "edit" => {
            let targets = paths(args);
            if targets.is_empty() {
                return Err(format_changed(input, "has no `path` or `paths` field"));
            }
            Ok(targets
                .into_iter()
                .map(|path| {
                    claude(
                        input,
                        "Edit",
                        json!({ "file_path": path, "old_string": "", "new_string": "" }),
                    )
                })
                .collect())
        }
        "grep" => Ok(path_tool(input, "Grep")),
        "glob" => Ok(path_tool(input, "Glob")),
        "eval" => eval(input),
        _ => Ok(generic(input)),
    }
}

fn required<'a>(input: &'a HookInput, field: &str) -> Result<&'a str, String> {
    str_field(&input.tool_input, field)
        .ok_or_else(|| format_changed(input, &format!("has no `{field}` field")))
}

fn format_changed(input: &HookInput, problem: &str) -> String {
    format!(
        "omp's `{}` call {problem}. omp's tool-call format may have changed; aca-safety-net needs an update to check it",
        input.tool_name
    )
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
/// (`python -c CODE` or `node -e CODE`), plus what each IPython shell escape
/// and magic in a Python cell does.
fn eval(input: &HookInput) -> Result<Vec<HookInput>, String> {
    let code = required(input, "code")?;
    let cwd = input.cwd.clone();
    match str_field(&input.tool_input, "language") {
        Some("js") => Ok(vec![bash(
            input,
            &format!("node -e {}", shell_quote(code)),
            cwd,
        )]),
        Some("py") | None => Ok(python_cell(input, code, cwd)),
        Some(other) => Err(format_changed(
            input,
            &format!("has unknown language `{other}`"),
        )),
    }
}

fn python_cell(input: &HookInput, code: &str, cwd: Option<String>) -> Vec<HookInput> {
    let mut calls = vec![bash(
        input,
        &format!("python -c {}", shell_quote(code)),
        cwd.clone(),
    )];
    calls.extend(
        ipython_effects(code)
            .into_iter()
            .map(|effect| match effect {
                Effect::Shell(command) => bash(input, &command, cwd.clone()),
                Effect::WriteFile { path, content } => claude(
                    input,
                    "Write",
                    json!({ "file_path": path, "content": content }),
                ),
            }),
    );
    calls
}

/// What an IPython escape or magic line does, as something the analyzers check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Runs, or reads like, this shell command.
    Shell(String),
    /// Writes `content` to `path`.
    WriteFile { path: String, content: String },
}

/// Cell magics whose body omp runs as a shell script.
const SHELL_CELL_MAGICS: &[&str] = &["bash", "sh", "script"];

/// The effects of the `!cmd`, `var = !cmd`, `%magic` and `%%magic` lines in a
/// Python cell. A cell magic consumes the rest of the cell.
pub fn ipython_effects(code: &str) -> Vec<Effect> {
    let mut effects = Vec::new();
    let lines: Vec<&str> = code.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if let Some(cell) = trimmed.strip_prefix("%%") {
            let (name, args) = split_head(cell);
            effects.extend(cell_magic_effect(name, args, lines[i + 1..].join("\n")));
            break;
        }
        let escaped = match trimmed.split_once('=') {
            Some((lhs, rhs)) if is_identifier(lhs.trim()) => rhs.trim_start(),
            _ => trimmed,
        };
        if let Some(shell) = escaped.strip_prefix('!') {
            effects.push(Effect::Shell(
                shell.trim_start_matches('!').trim().to_string(),
            ));
        } else if let Some(magic) = escaped.strip_prefix('%') {
            let (name, args) = split_head(magic);
            effects.extend(line_magic_effect(name, args));
        }
    }
    effects.retain(|e| !matches!(e, Effect::Shell(c) if c.is_empty()));
    effects
}

fn split_head(text: &str) -> (&str, &str) {
    let text = text.trim();
    match text.split_once(char::is_whitespace) {
        Some((name, args)) => (name, args.trim()),
        None => (text, ""),
    }
}

/// omp's line magics: `%env` returns all variables or the named one, `%load`
/// reads and runs a file, `%run` runs a Python file, `%set_env` and
/// `%env K=V` only set a variable. Others are checked as the command they name.
fn line_magic_effect(name: &str, args: &str) -> Option<Effect> {
    let command = match name {
        "env" if args.contains('=') => return None,
        "set_env" => return None,
        "env" => format!("printenv {args}"),
        "load" => format!("cat {args}"),
        "run" => format!("python {args}"),
        _ => format!("{name} {args}"),
    };
    Some(Effect::Shell(command.trim().to_string()))
}

/// omp's cell magics: `%%bash` runs the body as a shell script and
/// `%%writefile PATH` writes the body to PATH. The other cell magics run the
/// body as Python, which the whole-cell check covers.
fn cell_magic_effect(name: &str, args: &str, body: String) -> Option<Effect> {
    if SHELL_CELL_MAGICS.contains(&name) {
        return Some(Effect::Shell(body));
    }
    if name == "writefile" {
        let path = args.split_whitespace().last().unwrap_or_default();
        return Some(Effect::WriteFile {
            path: path.to_string(),
            content: body,
        });
    }
    None
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

    fn checked(input: &HookInput) -> Vec<HookInput> {
        translate(input).unwrap()
    }

    fn refusal(tool: &str, tool_input: Value) -> String {
        translate(&omp(tool, tool_input)).unwrap_err()
    }

    #[test]
    fn test_bash_maps_command_and_relative_cwd() {
        let calls = checked(&omp("bash", json!({ "command": "ls", "cwd": "sub" })));
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tool_name, "Bash");
        assert_eq!(calls[0].command(), Some("ls"));
        assert_eq!(calls[0].cwd.as_deref(), Some("/work/sub"));
    }

    #[test]
    fn test_bash_absolute_cwd() {
        let calls = checked(&omp("bash", json!({ "command": "ls", "cwd": "/tmp" })));
        assert_eq!(calls[0].cwd.as_deref(), Some("/tmp"));
    }

    #[test]
    fn test_read_write_map_path_to_file_path() {
        let read = checked(&omp("read", json!({ "path": "a.txt" })));
        assert_eq!(read[0].tool_name, "Read");
        assert_eq!(read[0].file_path(), Some("a.txt"));

        let write = checked(&omp("write", json!({ "path": "b.txt", "content": "x" })));
        assert_eq!(write[0].tool_name, "Write");
        assert_eq!(write[0].as_write().unwrap().content, "x");
    }

    #[test]
    fn test_write_without_content() {
        let write = checked(&omp("write", json!({ "path": "b.txt" })));
        assert_eq!(write[0].as_write().unwrap().content, "");
    }

    #[test]
    fn test_edit_one_call_per_path() {
        let calls = checked(&omp("edit", json!({ "input": "...", "paths": ["a", "b"] })));
        let targets: Vec<_> = calls.iter().filter_map(|c| c.file_path()).collect();
        assert_eq!(targets, vec!["a", "b"]);
        assert!(calls.iter().all(|c| c.as_edit().is_some()));
    }

    #[test]
    fn test_edit_single_path() {
        let calls = checked(&omp("edit", json!({ "path": "a" })));
        assert_eq!(calls[0].file_path(), Some("a"));
    }

    #[test]
    fn test_grep_and_glob_map_to_path_tools() {
        let grep = checked(&omp("grep", json!({ "pattern": "x", "path": "src" })));
        assert_eq!(grep[0].tool_name, "Grep");
        assert_eq!(grep[0].tool_paths(), vec!["src"]);

        let glob = checked(&omp("glob", json!({ "path": "**/*.rs" })));
        assert_eq!(glob[0].tool_name, "Glob");
        assert_eq!(glob[0].tool_paths(), vec!["**/*.rs"]);
    }

    #[test]
    fn test_generic_tool_checks_each_listed_path() {
        let calls = checked(&omp("ast_edit", json!({ "paths": ["a", "b"] })));
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].tool_paths(), vec!["b"]);
    }

    #[test]
    fn test_eval_python_as_python_c() {
        let calls = checked(&omp(
            "eval",
            json!({ "language": "py", "code": "print('hi')" }),
        ));
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].command(), Some(r"python -c 'print('\''hi'\'')'"));
    }

    #[test]
    fn test_eval_js_as_node_e() {
        let calls = checked(&omp("eval", json!({ "language": "js", "code": "1+1" })));
        assert_eq!(calls[0].command(), Some("node -e '1+1'"));
    }

    #[test]
    fn test_eval_without_language_is_python() {
        let calls = checked(&omp("eval", json!({ "code": "1" })));
        assert_eq!(calls[0].command(), Some("python -c '1'"));
    }

    #[test]
    fn test_known_tool_missing_its_field_is_refused() {
        let cases = [
            (
                "bash",
                json!({ "cmd": "ls" }),
                "`bash` call has no `command` field",
            ),
            (
                "read",
                json!({ "file_path": "a" }),
                "`read` call has no `path` field",
            ),
            (
                "write",
                json!({ "content": "x" }),
                "`write` call has no `path` field",
            ),
            (
                "edit",
                json!({ "input": "x" }),
                "`edit` call has no `path` or `paths` field",
            ),
            (
                "eval",
                json!({ "language": "py" }),
                "`eval` call has no `code` field",
            ),
        ];
        for (tool, input, expected) in cases {
            let reason = refusal(tool, input);
            assert!(reason.contains(expected), "{reason}");
            assert!(
                reason.contains("aca-safety-net needs an update"),
                "{reason}"
            );
        }
    }

    #[test]
    fn test_field_of_wrong_type_is_refused() {
        assert!(refusal("bash", json!({ "command": ["ls"] })).contains("no `command` field"));
    }

    #[test]
    fn test_eval_unknown_language_is_refused() {
        assert!(
            refusal("eval", json!({ "language": "rb", "code": "1" }))
                .contains("unknown language `rb`")
        );
    }

    #[test]
    fn test_optional_fields_may_be_missing() {
        assert_eq!(
            checked(&omp("grep", json!({ "pattern": "x" })))[0].tool_paths(),
            vec!["."]
        );
        assert_eq!(checked(&omp("glob", json!({})))[0].tool_paths(), vec!["."]);
        assert_eq!(
            checked(&omp("bash", json!({ "command": "ls" })))[0]
                .cwd
                .as_deref(),
            Some("/work")
        );
    }

    fn shell(c: &str) -> Effect {
        Effect::Shell(c.to_string())
    }

    #[test]
    fn test_ipython_shell_escapes() {
        let code = "x = 1\n!ls -la\nout = !whoami\n!!date";
        assert_eq!(
            ipython_effects(code),
            vec![shell("ls -la"), shell("whoami"), shell("date")]
        );
    }

    #[test]
    fn test_ipython_env_magic_reads_as_printenv() {
        assert_eq!(ipython_effects("%env"), vec![shell("printenv")]);
        assert_eq!(
            ipython_effects("v = %env HOME"),
            vec![shell("printenv HOME")]
        );
    }

    #[test]
    fn test_ipython_env_assignment_is_not_a_read() {
        assert!(ipython_effects("%env A=1\n%set_env A 1").is_empty());
    }

    #[test]
    fn test_ipython_load_and_run_read_their_file() {
        assert_eq!(
            ipython_effects("%load a.py\n%run b.py x"),
            vec![shell("cat a.py"), shell("python b.py x")]
        );
    }

    #[test]
    fn test_ipython_other_line_magic_as_command() {
        assert_eq!(ipython_effects("%ls -a"), vec![shell("ls -a")]);
    }

    #[test]
    fn test_ipython_bash_cell_body_is_shell() {
        assert_eq!(
            ipython_effects("%%bash\ncat secrets.txt\necho done"),
            vec![shell("cat secrets.txt\necho done")]
        );
    }

    #[test]
    fn test_ipython_writefile_cell_is_a_write() {
        assert_eq!(
            ipython_effects("%%writefile -a out.txt\nhello"),
            vec![Effect::WriteFile {
                path: "out.txt".to_string(),
                content: "hello".to_string()
            }]
        );
    }

    #[test]
    fn test_ipython_python_cell_magic_has_no_effect() {
        assert!(ipython_effects("%%capture c\nprint(1)").is_empty());
    }

    #[test]
    fn test_ipython_plain_python_has_no_effects() {
        assert!(ipython_effects("a = b % c\nif a != b: pass").is_empty());
    }

    #[test]
    fn test_shell_quote_plain_and_with_quotes() {
        assert_eq!(shell_quote("abc"), "'abc'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
