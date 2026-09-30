//! Input parsing for Claude Code hook invocations.

use serde::Deserialize;
use thiserror::Error;

/// Errors that can occur when parsing hook input.
#[derive(Debug, Error)]
pub enum InputError {
    #[error("failed to parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

/// The raw input from Claude Code's PreToolUse hook.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    /// The tool being invoked (e.g., "Bash", "Read", "Write").
    pub tool_name: String,

    /// The tool's input parameters as raw JSON.
    pub tool_input: serde_json::Value,

    /// Current working directory (optional).
    #[serde(default)]
    pub cwd: Option<String>,

    /// Session ID for audit logging (optional).
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Parsed input for the Bash tool.
#[derive(Debug, Clone)]
pub struct BashInput {
    /// The command to execute.
    pub command: String,
    /// Optional timeout in milliseconds.
    pub timeout: Option<u64>,
    /// Optional description.
    pub description: Option<String>,
}

/// Parsed input for the Read tool.
#[derive(Debug, Clone)]
pub struct ReadInput {
    /// The file path to read.
    pub file_path: String,
    /// Optional line offset.
    pub offset: Option<u64>,
    /// Optional line limit.
    pub limit: Option<u64>,
}

/// Parsed input for the Write tool.
#[derive(Debug, Clone)]
pub struct WriteInput {
    /// The file path to write.
    pub file_path: String,
    /// The content to write.
    pub content: String,
}

/// Parsed input for the Edit tool.
#[derive(Debug, Clone)]
pub struct EditInput {
    /// The file path to edit.
    pub file_path: String,
    /// The old string to replace.
    pub old_string: String,
    /// The new string.
    pub new_string: String,
}

impl HookInput {
    /// Parse from JSON string.
    pub fn parse(json: &str) -> Result<Self, InputError> {
        Ok(serde_json::from_str(json)?)
    }

    /// Try to extract as Bash input.
    pub fn as_bash(&self) -> Option<BashInput> {
        if self.tool_name != "Bash" {
            return None;
        }
        let command = self.tool_input.get("command")?.as_str()?.to_string();
        let timeout = self.tool_input.get("timeout").and_then(|v| v.as_u64());
        let description = self
            .tool_input
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from);
        Some(BashInput {
            command,
            timeout,
            description,
        })
    }

    /// Try to extract as Read input.
    pub fn as_read(&self) -> Option<ReadInput> {
        if self.tool_name != "Read" {
            return None;
        }
        let file_path = self.tool_input.get("file_path")?.as_str()?.to_string();
        let offset = self.tool_input.get("offset").and_then(|v| v.as_u64());
        let limit = self.tool_input.get("limit").and_then(|v| v.as_u64());
        Some(ReadInput {
            file_path,
            offset,
            limit,
        })
    }

    /// Try to extract as Write input.
    pub fn as_write(&self) -> Option<WriteInput> {
        if self.tool_name != "Write" {
            return None;
        }
        let file_path = self.tool_input.get("file_path")?.as_str()?.to_string();
        let content = self.tool_input.get("content")?.as_str()?.to_string();
        Some(WriteInput { file_path, content })
    }

    /// Try to extract as Edit input.
    pub fn as_edit(&self) -> Option<EditInput> {
        if self.tool_name != "Edit" {
            return None;
        }
        let file_path = self.tool_input.get("file_path")?.as_str()?.to_string();
        let old_string = self.tool_input.get("old_string")?.as_str()?.to_string();
        let new_string = self.tool_input.get("new_string")?.as_str()?.to_string();
        Some(EditInput {
            file_path,
            old_string,
            new_string,
        })
    }

    /// Paths and path globs in the input of a tool without a dedicated
    /// analyzer (Grep, Glob, NotebookEdit, ...). Grep's `pattern` is a
    /// content regex, so only Glob's `pattern` counts as a path.
    pub fn tool_paths(&self) -> Vec<String> {
        let mut keys = vec!["file_path", "path", "notebook_path", "glob"];
        if self.tool_name == "Glob" {
            keys.push("pattern");
        }
        keys.iter()
            .filter_map(|k| self.tool_input.get(*k).and_then(|v| v.as_str()))
            .map(String::from)
            .collect()
    }

    /// Get the primary path being accessed (for any file-based tool).
    pub fn file_path(&self) -> Option<&str> {
        self.tool_input.get("file_path").and_then(|v| v.as_str())
    }

    /// Get the command (for Bash tool).
    pub fn command(&self) -> Option<&str> {
        self.tool_input.get("command").and_then(|v| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bash_input() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
        let input = HookInput::parse(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        let bash = input.as_bash().unwrap();
        assert_eq!(bash.command, "ls -la");
    }

    #[test]
    fn test_parse_read_input() {
        let json = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
        let input = HookInput::parse(json).unwrap();
        assert_eq!(input.tool_name, "Read");
        let read = input.as_read().unwrap();
        assert_eq!(read.file_path, "/etc/passwd");
    }

    #[test]
    fn test_parse_with_cwd() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"pwd"},"cwd":"/home/user"}"#;
        let input = HookInput::parse(json).unwrap();
        assert_eq!(input.cwd, Some("/home/user".to_string()));
    }

    #[test]
    fn test_wrong_tool_type() {
        let json = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/passwd"}}"#;
        let input = HookInput::parse(json).unwrap();
        assert!(input.as_bash().is_none());
    }
}
