//! Response formatting for hook output.

use crate::decision::{AskInfo, BlockInfo, Decision};
use serde::Serialize;

/// JSON response for blocked operations.
#[derive(Debug, Serialize)]
pub struct BlockResponse {
    pub blocked: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// JSON response for ask operations (Claude Code hook format).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AskResponse {
    pub hook_specific_output: HookSpecificOutput,
}

/// The hook-specific output for PreToolUse hooks.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    /// Must be "PreToolUse" for this hook type.
    pub hook_event_name: &'static str,
    /// Must be "ask" to trigger user approval prompt.
    pub permission_decision: &'static str,
    /// Message shown to the user.
    pub permission_decision_reason: String,
}

/// Format a decision as output for stderr.
pub fn format_response(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Block(info) => Some(format_block_message(info)),
        Decision::Ask(info) => Some(format_ask_json(info)),
    }
}

fn format_block_message(info: &BlockInfo) -> String {
    let mut msg = format!("BLOCKED: {}", info.reason);
    if let Some(details) = &info.details {
        msg.push_str(&format!(" ({})", details));
    }
    msg.push_str("\n\nYOU ABSOLUTELY MUST NOT ATTEMPT TO READ THE TARGET FILE/SECRET/TOKEN VIA WORKAROUNDS. CONSULT THE USER IF YOU ARE CERTAIN THE TARGET FILE/SECRET/TOKEN NEEDS TO BE VERIFIED, ONLY AFTER EXHAUSTIVE DEBUGGING THAT RESULTS IN THIS CERTAINTY.");
    msg.push_str("\n\nIF YOU THINK THIS BLOCK IS A MISTAKE, DO NOT REWORD OR OBFUSCATE THE COMMAND TO GET PAST IT. ASK THE USER TO RUN IT.");
    msg
}

fn format_ask_json(info: &AskInfo) -> String {
    let mut reason = info.reason.clone();
    if let Some(suggestion) = &info.suggestion {
        reason.push_str(&format!("\n\nSuggestion: {}", suggestion));
    }
    let response = AskResponse {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse",
            permission_decision: "ask",
            permission_decision_reason: reason,
        },
    };
    // Claude Code expects JSON on stdout for ask decisions
    serde_json::to_string(&response).unwrap_or_else(|_| {
        // Fallback to simple format if JSON serialization fails
        format!(
            r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"{}"}}}}"#,
            info.reason
        )
    })
}

/// Format a decision as JSON (for future use).
#[allow(dead_code)]
pub fn format_json_response(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Block(info) => {
            let response = BlockResponse {
                blocked: true,
                reason: info.reason.clone(),
                rule: Some(info.rule.clone()),
                details: info.details.clone(),
            };
            serde_json::to_string(&response).ok()
        }
        Decision::Ask(info) => Some(format_ask_json(info)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_allow() {
        let decision = Decision::allow();
        assert!(format_response(&decision).is_none());
    }

    #[test]
    fn test_format_block() {
        let decision = Decision::block("test.rule", "test reason");
        let msg = format_response(&decision).unwrap();
        assert!(msg.contains("BLOCKED"));
        assert!(msg.contains("test reason"));
        assert!(msg.contains("DO NOT REWORD OR OBFUSCATE"));
    }

    #[test]
    fn test_format_block_with_details() {
        let decision = Decision::Block(
            BlockInfo::new("test.rule", "test reason").with_details("matched .env"),
        );
        let msg = format_response(&decision).unwrap();
        assert!(msg.contains("matched .env"));
    }

    #[test]
    fn test_json_response() {
        let decision = Decision::block("test.rule", "test reason");
        let json = format_json_response(&decision).unwrap();
        assert!(json.contains("\"blocked\":true"));
        assert!(json.contains("test reason"));
    }

    #[test]
    fn test_format_ask() {
        let decision = Decision::ask("deps.cargo_toml", "Editing dependency file");
        let msg = format_response(&decision).unwrap();
        assert!(msg.contains("\"permissionDecision\":\"ask\""));
        assert!(msg.contains("Editing dependency file"));
    }

    #[test]
    fn test_format_ask_with_suggestion() {
        let decision = Decision::Ask(
            crate::decision::AskInfo::new("deps.cargo_toml", "Editing Cargo.toml")
                .with_suggestion("Use 'cargo add' instead"),
        );
        let msg = format_response(&decision).unwrap();
        assert!(msg.contains("\"permissionDecision\":\"ask\""));
        assert!(msg.contains("cargo add"));
    }

    #[test]
    fn test_ask_response_structure() {
        let decision = Decision::ask("deps.cargo_toml", "Test reason");
        let json = format_response(&decision).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify the full Claude Code hook structure
        assert!(parsed.get("hookSpecificOutput").is_some());
        let output = &parsed["hookSpecificOutput"];
        assert_eq!(output["hookEventName"], "PreToolUse");
        assert_eq!(output["permissionDecision"], "ask");
        assert_eq!(output["permissionDecisionReason"], "Test reason");
    }
}
