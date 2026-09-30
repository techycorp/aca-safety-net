//! ACO Safety Net - Claude Code security hook entry point.

use aca_safety_net::analysis::{analyze_bash, analyze_edit, analyze_read, analyze_write};
use aca_safety_net::audit::AuditLogger;
use aca_safety_net::config::Config;
use aca_safety_net::decision::Decision;
use aca_safety_net::input::HookInput;
use aca_safety_net::output::format_response;

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Read JSON from stdin
    let mut input_str = String::new();
    if io::stdin().read_to_string(&mut input_str).is_err() {
        return ExitCode::SUCCESS; // Fail-open on read error
    }

    // Parse input
    let hook_input = match HookInput::parse(&input_str) {
        Ok(v) => v,
        Err(_) => return ExitCode::SUCCESS, // Fail-open on parse error
    };

    // Load config
    let cwd = hook_input.cwd.as_deref().map(Path::new);
    let config = match Config::load(cwd) {
        Ok(c) => c,
        Err(_) => return ExitCode::SUCCESS, // Fail-open if no config
    };

    // Compile config patterns
    let compiled = match config.compile() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config error: {}", e);
            return ExitCode::SUCCESS; // Fail-open on config error
        }
    };
    for warning in &compiled.warnings {
        eprintln!("aca-safety-net config warning: {}", warning);
    }

    // Analyze based on tool type
    let decision = match hook_input.tool_name.as_str() {
        "Bash" => {
            if let Some(bash_input) = hook_input.as_bash() {
                analyze_bash(&bash_input, &compiled, hook_input.cwd.as_deref())
            } else {
                Decision::allow()
            }
        }
        "Read" => {
            if let Some(read_input) = hook_input.as_read() {
                analyze_read(&read_input, &compiled)
            } else {
                Decision::allow()
            }
        }
        "Edit" => {
            if let Some(edit_input) = hook_input.as_edit() {
                analyze_edit(&edit_input, &compiled)
            } else {
                Decision::allow()
            }
        }
        "Write" => {
            if let Some(write_input) = hook_input.as_write() {
                analyze_write(&write_input, &compiled)
            } else {
                Decision::allow()
            }
        }
        // Other tools pass through
        _ => Decision::allow(),
    };

    // Audit logging (if enabled)
    if compiled.raw.audit.enabled
        && let Some(path) = &compiled.raw.audit.path
        && let Ok(mut logger) = AuditLogger::open(Path::new(path))
    {
        let _ = logger.log_decision(&hook_input, &decision);
    }

    // Output result
    match &decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Block(_) => {
            if let Some(msg) = format_response(&decision) {
                eprintln!("{}", msg);
            }
            ExitCode::from(2)
        }
        Decision::Ask(_) => {
            // Ask decisions output JSON to stdout for Claude Code to parse
            if let Some(json) = format_response(&decision) {
                let _ = io::stdout().write_all(json.as_bytes());
                let _ = io::stdout().write_all(b"\n");
            }
            ExitCode::SUCCESS
        }
    }
}
