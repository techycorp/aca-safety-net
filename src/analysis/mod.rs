//! Tool analysis entry points.

mod bash;
mod edit;
mod path_tool;
mod read;
mod write;

pub use bash::analyze_bash;
pub use edit::analyze_edit;
pub use path_tool::analyze_path_tool;
pub use read::analyze_read;
pub use write::analyze_write;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::input::HookInput;

/// Analyze a Claude Code tool invocation with the analyzer for its tool.
pub fn analyze(input: &HookInput, config: &CompiledConfig) -> Decision {
    match input.tool_name.as_str() {
        "Bash" => input.as_bash().map_or_else(Decision::allow, |b| {
            analyze_bash(&b, config, input.cwd.as_deref())
        }),
        "Read" => input
            .as_read()
            .map_or_else(Decision::allow, |r| analyze_read(&r, config)),
        "Edit" => input
            .as_edit()
            .map_or_else(Decision::allow, |e| analyze_edit(&e, config)),
        "Write" => input
            .as_write()
            .map_or_else(Decision::allow, |w| analyze_write(&w, config)),
        other => analyze_path_tool(other, &input.tool_paths(), config),
    }
}

/// The most severe of several decisions: the first block, else the first
/// ask, else allow.
pub fn most_severe(decisions: impl IntoIterator<Item = Decision>) -> Decision {
    let mut ask = None;
    for decision in decisions {
        match decision {
            Decision::Block(_) => return decision,
            Decision::Ask(_) if ask.is_none() => ask = Some(decision),
            _ => {}
        }
    }
    ask.unwrap_or_else(Decision::allow)
}
