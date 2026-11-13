//! The binary in omp mode (`--agent omp`), fed omp tool calls.

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::{Value, json};
use std::io::Write;
use tempfile::NamedTempFile;

const TEST_CONFIG: &str = r#"
sensitive_files = ['\.env\b', 'id_rsa', 'credentials']
allowed_files = ['\.env\.example']
read_commands = '\b(cat|head|tail|less|grep|rg|sed|awk)\b'

[[deny]]
tool = "Bash"
pattern = '^\s*printenv'
reason = "Exposes environment variables"
"#;

fn config() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(TEST_CONFIG.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

fn run(tool: &str, tool_input: Value) -> i32 {
    let cfg = config();
    let event = json!({ "tool_name": tool, "tool_input": tool_input, "cwd": "/work" });
    let output = cargo_bin_cmd!("aca-safety-net")
        .env("ACO_SAFETY_NET_CONFIG", cfg.path())
        .args(["--agent", "omp"])
        .write_stdin(event.to_string())
        .output()
        .unwrap();
    output.status.code().unwrap()
}

fn assert_blocked(tool: &str, tool_input: Value) {
    assert_eq!(run(tool, tool_input.clone()), 2, "{tool} {tool_input}");
}

fn assert_allowed(tool: &str, tool_input: Value) {
    assert_eq!(run(tool, tool_input.clone()), 0, "{tool} {tool_input}");
}

#[test]
fn read_sensitive_blocked() {
    assert_blocked("read", json!({ "path": "/work/.env" }));
}

#[test]
fn read_normal_allowed() {
    assert_allowed("read", json!({ "path": "/work/src/main.rs" }));
    assert_allowed("read", json!({ "path": "/work/.env.example" }));
}

#[test]
fn write_sensitive_blocked() {
    assert_blocked("write", json!({ "path": "/work/.env", "content": "X=1" }));
}

#[test]
fn edit_any_sensitive_path_blocked() {
    assert_blocked(
        "edit",
        json!({ "input": "…", "paths": ["/work/a.rs", "/work/.env"] }),
    );
    assert_allowed("edit", json!({ "input": "…", "paths": ["/work/a.rs"] }));
}

#[test]
fn bash_rules_apply() {
    assert_blocked("bash", json!({ "command": "cat .env" }));
    assert_blocked("bash", json!({ "command": "printenv" }));
    assert_blocked("bash", json!({ "command": "infisical export" }));
    assert_allowed("bash", json!({ "command": "ls -la", "cwd": "src" }));
}

#[test]
fn grep_and_glob_sensitive_paths_blocked() {
    assert_blocked("grep", json!({ "pattern": "KEY", "path": "/work/.env" }));
    assert_blocked("glob", json!({ "path": "/work/**/credentials" }));
    assert_allowed("grep", json!({ "pattern": "fn main", "path": "/work/src" }));
}

#[test]
fn eval_python_exec_of_blocked_tool_blocked() {
    assert_blocked(
        "eval",
        json!({ "language": "py", "code": "import os\nos.system(\"infisical export\")" }),
    );
}

#[test]
fn eval_js_exec_of_blocked_tool_blocked() {
    assert_blocked(
        "eval",
        json!({ "language": "js", "code": "require('child_process').execSync('infisical export')" }),
    );
}

#[test]
fn eval_ipython_shell_escape_blocked() {
    assert_blocked(
        "eval",
        json!({ "language": "py", "code": "x = 1\n!cat .env" }),
    );
    assert_blocked(
        "eval",
        json!({ "language": "py", "code": "out = !printenv" }),
    );
}

#[test]
fn eval_env_magic_blocked() {
    assert_blocked("eval", json!({ "language": "py", "code": "%env" }));
    assert_blocked("eval", json!({ "language": "py", "code": "v = %env HOME" }));
}

#[test]
fn eval_load_and_run_of_sensitive_file_blocked() {
    assert_blocked("eval", json!({ "language": "py", "code": "%load .env" }));
}

#[test]
fn eval_writefile_to_sensitive_path_blocked() {
    assert_blocked(
        "eval",
        json!({ "language": "py", "code": "%%writefile .env\nX=1" }),
    );
}

#[test]
fn eval_env_assignment_allowed() {
    assert_allowed("eval", json!({ "language": "py", "code": "%env DEBUG=1" }));
}

#[test]
fn eval_shell_cell_magic_body_blocked() {
    assert_blocked(
        "eval",
        json!({ "language": "py", "code": "%%bash\necho hi\ncat .env" }),
    );
}

#[test]
fn eval_plain_code_allowed() {
    assert_allowed("eval", json!({ "language": "py", "code": "print(1 + 1)" }));
    assert_allowed(
        "eval",
        json!({ "language": "js", "code": "console.log('it\\'s fine')" }),
    );
}

#[test]
fn unknown_tool_without_paths_allowed() {
    assert_allowed("todo", json!({ "items": ["x"] }));
}

#[test]
fn unknown_tool_sensitive_path_blocked() {
    assert_blocked("ast_edit", json!({ "paths": ["/work/.env"] }));
}

#[test]
fn unparseable_input_blocked_in_omp_mode() {
    let cfg = config();
    cargo_bin_cmd!("aca-safety-net")
        .env("ACO_SAFETY_NET_CONFIG", cfg.path())
        .args(["--agent", "omp"])
        .write_stdin("not json")
        .assert()
        .code(2);
}

#[test]
fn unparseable_input_allowed_in_claude_mode() {
    let cfg = config();
    cargo_bin_cmd!("aca-safety-net")
        .env("ACO_SAFETY_NET_CONFIG", cfg.path())
        .write_stdin("not json")
        .assert()
        .code(0);
}
