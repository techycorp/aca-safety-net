//! ACO Safety Net - security hook entry point for Claude Code and oh-my-pi.
//!
//! `aca-safety-net` reads a Claude Code PreToolUse event on stdin.
//! `aca-safety-net --agent omp` reads an omp tool call (`tool_name`,
//! `tool_input`, `cwd`) sent by the omp hook shim, and blocks when it cannot
//! parse one.

use aca_safety_net::analysis::{analyze, most_severe};
use aca_safety_net::audit::AuditLogger;
use aca_safety_net::config::Config;
use aca_safety_net::decision::Decision;
use aca_safety_net::input::HookInput;
use aca_safety_net::omp;
use aca_safety_net::output::format_response;

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let omp_mode = is_omp_mode(std::env::args().skip(1));

    let mut input_str = String::new();
    if io::stdin().read_to_string(&mut input_str).is_err() {
        return unreadable(omp_mode, "could not read hook input");
    }

    let hook_input = match HookInput::parse(&input_str) {
        Ok(v) => v,
        Err(_) => return unreadable(omp_mode, "could not parse hook input"),
    };

    let cwd = hook_input.cwd.as_deref().map(Path::new);
    let config = match Config::load(cwd) {
        Ok(c) => c,
        Err(_) => return ExitCode::SUCCESS, // Fail-open if no config
    };

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

    let decision = if omp_mode {
        most_severe(
            omp::translate(&hook_input)
                .iter()
                .map(|call| analyze(call, &compiled)),
        )
    } else {
        analyze(&hook_input, &compiled)
    };

    if compiled.raw.audit.enabled
        && let Some(path) = &compiled.raw.audit.path
        && let Ok(mut logger) = AuditLogger::open(Path::new(path))
    {
        let _ = logger.log_decision(&hook_input, &decision);
    }

    match &decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Block(_) => {
            if let Some(msg) = format_response(&decision) {
                eprintln!("{}", msg);
            }
            ExitCode::from(2)
        }
        Decision::Ask(_) => {
            if let Some(json) = format_response(&decision) {
                let _ = io::stdout().write_all(json.as_bytes());
                let _ = io::stdout().write_all(b"\n");
            }
            ExitCode::SUCCESS
        }
    }
}

fn is_omp_mode(mut args: impl Iterator<Item = String>) -> bool {
    while let Some(arg) = args.next() {
        if arg == "--agent=omp" || (arg == "--agent" && args.next().as_deref() == Some("omp")) {
            return true;
        }
    }
    false
}

/// Claude Code input that cannot be read is allowed; omp input is blocked.
fn unreadable(omp_mode: bool, what: &str) -> ExitCode {
    if omp_mode {
        eprintln!("BLOCKED: aca-safety-net {}", what);
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
