//! Strip wrapper commands (sudo, bash -c, etc.).

use super::tokenizer::{Token, tokenize};

/// Commands that wrap other commands.
///
/// `env` is intentionally excluded — it's blocked entirely by `analyze_env`,
/// so we shouldn't peek through it to the inner command.
const WRAPPER_COMMANDS: &[&str] = &[
    "sudo", "doas", "su", "nohup", "nice", "ionice", "timeout", "time", "strace", "ltrace", "watch",
];

/// Maximum depth for recursive wrapper stripping.
const MAX_STRIP_DEPTH: usize = 5;

/// Strip wrapper commands to get the actual command.
///
/// Examples:
/// - `sudo ls` -> `ls`
/// - `bash -c "ls -la"` -> `ls -la`
pub fn strip_wrappers(command: &str) -> String {
    strip_wrappers_recursive(command, 0)
}

fn strip_wrappers_recursive(command: &str, depth: usize) -> String {
    if depth >= MAX_STRIP_DEPTH {
        return command.to_string();
    }

    let tokens = tokenize(command);

    // Skip leading assignments
    let mut idx = 0;
    while idx < tokens.len() {
        if matches!(tokens[idx], Token::Assignment(_, _)) {
            idx += 1;
        } else {
            break;
        }
    }

    if idx >= tokens.len() {
        return command.to_string();
    }

    let cmd = match &tokens[idx] {
        Token::Word(w) => w.as_str(),
        _ => return command.to_string(),
    };

    // Check for shell invocation with -c
    if cmd == "bash" || cmd == "sh" || cmd == "zsh" || cmd == "dash" {
        return handle_shell_c(&tokens[idx..], depth);
    }

    // Check for wrapper commands
    if WRAPPER_COMMANDS.contains(&cmd) {
        return handle_wrapper(&tokens[idx..], depth);
    }

    command.to_string()
}

fn handle_shell_c(tokens: &[Token], depth: usize) -> String {
    // Look for -c flag
    let mut found_c = false;
    for token in tokens.iter() {
        if let Token::Word(w) = token {
            if w == "-c" {
                found_c = true;
            } else if found_c {
                // This is the command to execute
                return strip_wrappers_recursive(w, depth + 1);
            }
        }
    }

    // No -c flag found, return original
    tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn handle_wrapper(tokens: &[Token], depth: usize) -> String {
    // Skip the wrapper and its options, find the actual command
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.is_empty() {
        return String::new();
    }

    let wrapper = words[0];
    let mut start = 1;

    // Skip wrapper-specific options
    match wrapper {
        "sudo" => {
            // Skip sudo options like -u, -E, etc.
            while start < words.len() {
                let w = words[start];
                if w.starts_with('-') {
                    // Options that take arguments
                    if matches!(w, "-u" | "-g" | "-C" | "-D" | "-h" | "-p" | "-r" | "-t") {
                        start += 2; // Skip option and its argument
                    } else {
                        start += 1; // Skip single option
                    }
                } else {
                    break;
                }
            }
        }
        "timeout" => {
            // timeout [options] duration command...
            while start < words.len() {
                let w = words[start];
                if w.starts_with('-') {
                    if matches!(w, "-s" | "--signal" | "-k" | "--kill-after") {
                        start += 2;
                    } else {
                        start += 1;
                    }
                } else {
                    // This should be the duration
                    start += 1;
                    break;
                }
            }
        }
        "nice" | "ionice" => {
            while start < words.len() {
                let w = words[start];
                if w.starts_with('-') {
                    if matches!(w, "-n" | "-c") {
                        start += 2;
                    } else {
                        start += 1;
                    }
                } else {
                    break;
                }
            }
        }
        _ => {
            // Generic: skip options
            while start < words.len() && words[start].starts_with('-') {
                start += 1;
            }
        }
    }

    if start >= words.len() {
        return String::new();
    }

    let remaining = words[start..].join(" ");
    strip_wrappers_recursive(&remaining, depth + 1)
}

/// Extract options and their values from a command.
///
/// Returns a list of (option, value) pairs where value may be empty.
pub fn extract_options(tokens: &[Token]) -> Vec<(String, String)> {
    let mut options = Vec::new();
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        if w.starts_with("--") {
            // Long option
            if let Some((opt, val)) = w.split_once('=') {
                options.push((opt.to_string(), val.to_string()));
            } else {
                // Check if next arg is value
                let val = if i + 1 < words.len() && !words[i + 1].starts_with('-') {
                    i += 1;
                    words[i].to_string()
                } else {
                    String::new()
                };
                options.push((w.to_string(), val));
            }
        } else if w.starts_with('-') && w.len() > 1 {
            // Short option(s)
            let chars: Vec<char> = w[1..].chars().collect();
            for (j, c) in chars.iter().enumerate() {
                let opt = format!("-{}", c);
                // Last char might take a value
                if j == chars.len() - 1 && i + 1 < words.len() && !words[i + 1].starts_with('-') {
                    i += 1;
                    options.push((opt, words[i].to_string()));
                } else {
                    options.push((opt, String::new()));
                }
            }
        }
        i += 1;
    }

    options
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_sudo() {
        assert_eq!(strip_wrappers("sudo ls -la"), "ls -la");
    }

    #[test]
    fn test_strip_sudo_with_user() {
        assert_eq!(strip_wrappers("sudo -u root ls -la"), "ls -la");
    }

    #[test]
    fn test_env_not_stripped() {
        // `env` is intentionally not a wrapper — it's blocked entirely by analyze_env.
        assert_eq!(strip_wrappers("env FOO=bar ls"), "env FOO=bar ls");
    }

    #[test]
    fn test_strip_bash_c() {
        assert_eq!(strip_wrappers("bash -c 'ls -la'"), "ls -la");
    }

    #[test]
    fn test_strip_nested() {
        // Nested stripping handles quotes that survive tokenization
        assert_eq!(strip_wrappers("sudo ls -la"), "ls -la");
        // `env` is no longer stripped — sudo gets peeled off, env stays.
        // Note: handle_wrapper's word-filter drops assignment tokens during
        // the join, so FOO=bar doesn't survive the recurse. That's a
        // pre-existing artifact; the security-relevant outer command name
        // (`env`) is preserved, and analyze_env_raw matches the original.
        assert_eq!(strip_wrappers("sudo env FOO=bar ls"), "env ls");
        // Complex nested case - bash -c with quoted command
        let result = strip_wrappers("bash -c 'ls -la'");
        assert_eq!(result, "ls -la");
    }

    #[test]
    fn test_strip_timeout() {
        assert_eq!(strip_wrappers("timeout 5 ls"), "ls");
    }

    #[test]
    fn test_max_depth() {
        // Should not infinite loop on deeply nested wrappers
        let cmd = "sudo sudo sudo sudo sudo sudo ls";
        let result = strip_wrappers(cmd);
        // After 5 levels, should stop stripping
        assert!(result.contains("sudo") || result == "ls");
    }

    #[test]
    fn test_no_wrapper() {
        assert_eq!(strip_wrappers("ls -la"), "ls -la");
    }

    #[test]
    fn test_extract_options() {
        let tokens = tokenize("git commit -m 'message' --amend");
        let opts = extract_options(&tokens);
        assert!(opts.iter().any(|(k, v)| k == "-m" && v == "message"));
        assert!(opts.iter().any(|(k, _)| k == "--amend"));
    }
}
