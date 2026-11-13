//! ACO Safety Net - Claude Code and oh-my-pi security hook.
//!
//! A Rust-based PreToolUse hook for Claude Code that blocks access to
//! sensitive files, dangerous commands, and environment variable exposure.

pub mod analysis;
pub mod audit;
pub mod config;
pub mod decision;
pub mod input;
pub mod omp;
pub mod output;
pub mod rules;
pub mod shell;

pub use analysis::{analyze_bash, analyze_edit, analyze_read, analyze_write};
pub use config::{CompiledConfig, Config};
pub use decision::Decision;
pub use input::HookInput;
pub use output::format_response;
