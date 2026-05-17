//! Built-in and custom rules for command analysis.

mod aws;
mod azure;
mod custom;
mod direnv;
mod env;
mod find;
mod gcloud;
mod git;
mod heroku;
mod infisical;
mod kubectl;
mod mise;
mod parallel;
mod pipenv;
mod rm;
mod sensitive_files;
mod shadowenv;
pub(crate) mod substitution;
mod uv;
mod xargs;

pub use aws::analyze_aws;
pub use azure::analyze_azure;
pub use custom::check_custom_rules;
pub use direnv::{analyze_direnv, analyze_direnv_raw};
pub use env::{analyze_env, analyze_env_raw};
pub use find::analyze_find;
pub use gcloud::{analyze_gcloud, analyze_gcloud_raw};
pub use git::analyze_git;
pub use heroku::analyze_heroku;
pub use infisical::{analyze_infisical, analyze_infisical_raw};
pub use kubectl::analyze_kubectl;
pub use mise::{analyze_mise, analyze_mise_raw};
pub use parallel::analyze_parallel;
pub use pipenv::analyze_pipenv;
pub use rm::analyze_rm;
pub use sensitive_files::{check_git_add_sensitive, check_sensitive_path};
pub use shadowenv::{analyze_shadowenv, analyze_shadowenv_raw};
pub use uv::analyze_uv;
pub use xargs::analyze_xargs;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::{Token, split_commands, strip_wrappers, tokenize};

/// Analyze a command and return a decision.
pub fn analyze_command(command: &str, config: &CompiledConfig, cwd: Option<&str>) -> Decision {
    // These analyzers need the full raw command to detect $(...) substitution bypasses
    let decision = analyze_kubectl(command);
    if decision.is_blocked() {
        return decision;
    }

    let decision = analyze_gcloud_raw(command);
    if decision.is_blocked() {
        return decision;
    }

    let decision = analyze_direnv_raw(command);
    if decision.is_blocked() {
        return decision;
    }

    // mise must run before env: `mise env` matches both regexes, and we
    // want the more specific tool-name reason rather than the generic env one.
    let decision = analyze_mise_raw(command);
    if decision.is_blocked() {
        return decision;
    }

    let decision = analyze_shadowenv_raw(command);
    if decision.is_blocked() {
        return decision;
    }

    let decision = analyze_infisical_raw(command);
    if decision.is_blocked() {
        return decision;
    }

    let decision = analyze_env_raw(command);
    if decision.is_blocked() {
        return decision;
    }

    // Split command on operators
    let segments = split_commands(command);

    for segment in &segments {
        // Strip wrappers to get actual command
        let stripped = strip_wrappers(&segment.command);
        let tokens = tokenize(&stripped);

        // Get command name
        let cmd_name = tokens.iter().find_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        });

        let Some(cmd_name) = cmd_name else {
            continue;
        };

        // Check built-in rules based on command
        let decision = match cmd_name {
            "git" => analyze_git(&tokens, config),
            "rm" => analyze_rm(&tokens, config, cwd),
            "find" => analyze_find(&tokens, config),
            "xargs" => analyze_xargs(&tokens, config),
            "parallel" => analyze_parallel(&tokens, config),
            "heroku" => analyze_heroku(&tokens, config),
            "aws" => analyze_aws(&tokens, config),
            "az" => analyze_azure(&tokens, config),
            "gcloud" => analyze_gcloud(&tokens, config),
            "uv" => analyze_uv(&tokens, config),
            "direnv" => analyze_direnv(&tokens, config),
            "env" | "printenv" | "gprintenv" => analyze_env(&tokens, config),
            "infisical" => analyze_infisical(&tokens, config),
            "mise" => analyze_mise(&tokens, config),
            "pipenv" => analyze_pipenv(&tokens, config),
            "shadowenv" => analyze_shadowenv(&tokens, config),
            _ => Decision::Allow,
        };

        if decision.is_blocked() {
            return decision;
        }
    }

    Decision::Allow
}
