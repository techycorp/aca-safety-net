//! Split shell commands on operators (&&, ||, |, ;, &).

/// Shell operators that separate commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    /// && - run next if previous succeeds
    And,
    /// || - run next if previous fails
    Or,
    /// | - pipe stdout to next command
    Pipe,
    /// ; - run sequentially
    Semicolon,
    /// & - run in background
    Background,
}

/// A segment of a shell command.
#[derive(Debug, Clone)]
pub struct CommandSegment {
    /// The command text.
    pub command: String,
    /// The operator that follows this segment (None for last segment).
    pub operator: Option<Operator>,
}

/// Split a command line into segments on shell operators.
///
/// Respects quoting (', ", $'...') and escapes.
pub fn split_commands(input: &str) -> Vec<CommandSegment> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    while let Some(c) = chars.next() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        if c == '\\' && !in_single_quote {
            escape_next = true;
            current.push(c);
            continue;
        }

        if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            current.push(c);
            continue;
        }

        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            current.push(c);
            continue;
        }

        if in_single_quote || in_double_quote {
            current.push(c);
            continue;
        }

        // Check for operators
        match c {
            '&' => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                    let trimmed = current.trim().to_string();
                    if !trimmed.is_empty() {
                        segments.push(CommandSegment {
                            command: trimmed,
                            operator: Some(Operator::And),
                        });
                    }
                    current.clear();
                } else {
                    // Background operator - but only if at end or followed by space/newline
                    // For simplicity, treat as background
                    let trimmed = current.trim().to_string();
                    if !trimmed.is_empty() {
                        segments.push(CommandSegment {
                            command: trimmed,
                            operator: Some(Operator::Background),
                        });
                    }
                    current.clear();
                }
            }
            '|' => {
                if chars.peek() == Some(&'|') {
                    chars.next();
                    let trimmed = current.trim().to_string();
                    if !trimmed.is_empty() {
                        segments.push(CommandSegment {
                            command: trimmed,
                            operator: Some(Operator::Or),
                        });
                    }
                    current.clear();
                } else {
                    let trimmed = current.trim().to_string();
                    if !trimmed.is_empty() {
                        segments.push(CommandSegment {
                            command: trimmed,
                            operator: Some(Operator::Pipe),
                        });
                    }
                    current.clear();
                }
            }
            ';' | '\n' => {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    segments.push(CommandSegment {
                        command: trimmed,
                        operator: Some(Operator::Semicolon),
                    });
                }
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }

    // Add final segment
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        segments.push(CommandSegment {
            command: trimmed,
            operator: None,
        });
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_newline_separates_commands() {
        let segments = split_commands("echo hi\ncat .env");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[1].command, "cat .env");
    }

    #[test]
    fn test_quoted_newline_stays_in_command() {
        let segments = split_commands("echo 'a\nb'");
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn test_simple_command() {
        let segments = split_commands("ls -la");
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].command, "ls -la");
        assert_eq!(segments[0].operator, None);
    }

    #[test]
    fn test_and_operator() {
        let segments = split_commands("cd /tmp && ls");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].command, "cd /tmp");
        assert_eq!(segments[0].operator, Some(Operator::And));
        assert_eq!(segments[1].command, "ls");
    }

    #[test]
    fn test_or_operator() {
        let segments = split_commands("test -f file || touch file");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].operator, Some(Operator::Or));
    }

    #[test]
    fn test_pipe() {
        let segments = split_commands("cat file | grep pattern");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].operator, Some(Operator::Pipe));
    }

    #[test]
    fn test_semicolon() {
        let segments = split_commands("echo a; echo b");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].operator, Some(Operator::Semicolon));
    }

    #[test]
    fn test_quoted_operators() {
        let segments = split_commands("echo '&&' && ls");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].command, "echo '&&'");
    }

    #[test]
    fn test_double_quoted() {
        let segments = split_commands("echo \"a && b\" && ls");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].command, "echo \"a && b\"");
    }

    #[test]
    fn test_escaped_operator() {
        let segments = split_commands("echo a \\&\\& b");
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn test_complex_chain() {
        let segments = split_commands("a && b || c; d | e");
        assert_eq!(segments.len(), 5);
    }
}
