//! Built-in and custom rules for command analysis.

mod argv;
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
mod pipenv;
mod rm;
mod sensitive_files;
mod shadowenv;
mod ssh;
mod tool_gate;
mod uv;

pub use aws::analyze_aws;
pub use azure::analyze_azure;
pub use custom::check_custom_rules;
pub use direnv::analyze_direnv_raw;
pub use env::analyze_env_raw;
pub use find::analyze_find;
pub use gcloud::analyze_gcloud;
pub use git::analyze_git;
pub use heroku::analyze_heroku;
pub use infisical::analyze_infisical_raw;
pub use kubectl::analyze_kubectl;
pub use mise::analyze_mise_raw;
pub use pipenv::analyze_pipenv;
pub use rm::analyze_rm;
pub use sensitive_files::{check_git_add_sensitive, check_sensitive_path, check_strict_mentions};
pub use shadowenv::analyze_shadowenv_raw;
pub use ssh::{check_ssh_bash_write, check_ssh_write};
pub use uv::analyze_uv;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;
use crate::shell::{split_commands, strip_wrappers, tokenize};

/// Analyze a command and return a decision.
///
/// The command is parsed once into the places where the shell would run a
/// program (`ExecSites`), and every tool rule checks those. ssh keeps its own
/// text and per-segment checks.
pub fn analyze_command(command: &str, config: &CompiledConfig, cwd: Option<&str>) -> Decision {
    let sites = ExecSites::parse(command);

    // mise must run before env: both block `mise env`, and we want the more
    // specific tool-name reason rather than the generic env one.
    let checks: [&dyn Fn() -> Decision; 15] = [
        &|| analyze_kubectl(&sites),
        &|| analyze_gcloud(&sites),
        &|| analyze_aws(&sites),
        &|| analyze_azure(&sites),
        &|| analyze_heroku(&sites),
        &|| analyze_direnv_raw(&sites, config),
        &|| analyze_mise_raw(&sites, config),
        &|| analyze_shadowenv_raw(&sites, config),
        &|| analyze_infisical_raw(&sites),
        &|| analyze_env_raw(&sites),
        &|| analyze_uv(&sites),
        &|| analyze_pipenv(&sites),
        &|| analyze_git(&sites, config),
        &|| analyze_rm(&sites, config, cwd),
        &|| analyze_find(&sites),
    ];
    for check in checks {
        let decision = check();
        if decision.is_blocked() {
            return decision;
        }
    }

    let decision = ssh::analyze_ssh_raw(command, config);
    if decision.is_blocked() {
        return decision;
    }

    for segment in &split_commands(command) {
        let tokens = tokenize(&strip_wrappers(&segment.command));
        let decision = ssh::analyze_ssh_segment(&tokens, config);
        if decision.is_blocked() {
            return decision;
        }
    }

    Decision::Allow
}
