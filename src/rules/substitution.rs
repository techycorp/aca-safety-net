//! Shared logic for detecting unsafe use of sensitive commands inside `$(...)`.
//!
//! Both kubectl and gcloud have dangerous subcommands that output secrets to
//! stdout. When these appear inside command substitutions, they can still leak
//! secrets depending on how the substitution is used. This module provides a
//! common analysis function used by both rules.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::decision::Decision;
use crate::shell::{Token, split_commands, tokenize};

/// Commands that print their arguments or stdin to stdout.
static PRINT_COMMANDS: &[&str] = &[
    "echo", "printf", "cat", "tee", "less", "more", "head", "tail", "bat", "strings", "xxd",
    "hexdump",
];

/// Matches bare variable assignments after `$(...)` has been stripped.
/// Covers: `VAR=`, `VAR=""`, `export VAR=`, `local VAR=`, `readonly VAR=`
static VARIABLE_ASSIGNMENT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"^(export\s+|local\s+|readonly\s+)?[A-Za-z_][A-Za-z0-9_]*=["']?\s*$"#).unwrap()
});

/// Strip all `$(...)` command substitutions from a string, handling nesting.
pub fn strip_command_substitutions(s: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if i + 1 < chars.len() && chars[i] == '$' && chars[i + 1] == '(' {
            i += 2; // consume '$('
            let mut depth = 1;
            while i < chars.len() && depth > 0 {
                if chars[i] == '(' {
                    depth += 1;
                } else if chars[i] == ')' {
                    depth -= 1;
                }
                i += 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    result
}

/// How a `$(sensitive-command ...)` substitution is used within its segment.
enum SubstitutionContext {
    /// `$()` at position 0 — output executed as a shell command.
    AsCommand,
    /// `$()` argument to a known print command (echo, printf, cat, …).
    PrintCommand,
    /// `$()` used as herestring input: `cmd <<< $(...)`.
    Herestring,
    /// `$()` assigned to a variable: `VAR=$(...)`.
    VariableAssignment,
    /// `$()` inside eval/bash -c/sh -c — output executed as shell code.
    DangerousWrapper,
    /// `$()` safely consumed as an argument to a non-print command.
    SafeArgument,
}

/// Classify how a substitution is used within a single command segment.
fn classify_segment(segment_cmd: &str) -> SubstitutionContext {
    let trimmed = segment_cmd.trim();

    // $() at position 0: output executed as a shell command.
    if trimmed.starts_with("$(") {
        return SubstitutionContext::AsCommand;
    }

    // Herestring: `cmd <<< $(...)` feeds output to stdin.
    if trimmed.contains("<<<") {
        return SubstitutionContext::Herestring;
    }

    // Strip substitutions to reveal the outer command or bare assignment.
    let stripped = strip_command_substitutions(trimmed);
    let stripped = stripped.trim();

    // Variable assignment: `VAR=$(...)`, `export VAR=$(...)`, etc.
    if VARIABLE_ASSIGNMENT_RE.is_match(stripped) {
        return SubstitutionContext::VariableAssignment;
    }

    // Find the outer command name.
    let tokens = tokenize(stripped);
    let outer_cmd = tokens.iter().find_map(|t| match t {
        Token::Word(w) if !w.starts_with('-') && !w.contains('=') => Some(w.as_str()),
        _ => None,
    });

    if let Some(cmd) = outer_cmd {
        if PRINT_COMMANDS.contains(&cmd) {
            return SubstitutionContext::PrintCommand;
        }
        if matches!(cmd, "eval" | "bash" | "sh" | "zsh" | "dash") {
            return SubstitutionContext::DangerousWrapper;
        }
    }

    SubstitutionContext::SafeArgument
}

/// Analyze a raw command string for unsafe use of a sensitive command pattern
/// inside `$(...)` substitutions.
///
/// Blocks if:
/// - The pattern appears outside any `$(...)` (standalone)
/// - The pattern appears inside `$(...)` but the substitution is used unsafely:
///   print command, herestring, variable assignment, dangerous wrapper, or as a command
///
/// Allows if every occurrence is inside `$(...)` used as a safe argument.
pub fn check_substitution_safety(
    raw_command: &str,
    pattern: &Regex,
    rule: &str,
    standalone_reason: &str,
) -> Decision {
    // Fast path: pattern not present at all.
    if !pattern.is_match(raw_command) {
        return Decision::allow();
    }

    // Check for standalone occurrences (outside any $(...)).
    let stripped_full = strip_command_substitutions(raw_command);
    if pattern.is_match(&stripped_full) {
        return Decision::block(rule, standalone_reason);
    }

    // All occurrences are inside $(). Check each segment for unsafe usage.
    for segment in split_commands(raw_command) {
        if !pattern.is_match(&segment.command) {
            continue;
        }
        // Skip segments where the pattern is standalone (caught above).
        let seg_stripped = strip_command_substitutions(&segment.command);
        if pattern.is_match(&seg_stripped) {
            continue;
        }

        match classify_segment(&segment.command) {
            SubstitutionContext::SafeArgument => {}
            SubstitutionContext::AsCommand => {
                return Decision::block(
                    rule,
                    "command output used as a shell command exposes secret value",
                );
            }
            SubstitutionContext::PrintCommand => {
                return Decision::block(
                    rule,
                    "command output passed to a print command exposes secret to stdout",
                );
            }
            SubstitutionContext::Herestring => {
                return Decision::block(
                    rule,
                    "command output in herestring exposes secret to stdout",
                );
            }
            SubstitutionContext::VariableAssignment => {
                return Decision::block(
                    rule,
                    "command output assigned to a variable will likely be exposed later",
                );
            }
            SubstitutionContext::DangerousWrapper => {
                return Decision::block(
                    rule,
                    "command inside eval/bash -c/sh -c executes secret value as shell code",
                );
            }
        }
    }

    Decision::allow()
}
