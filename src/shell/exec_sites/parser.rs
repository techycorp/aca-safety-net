//! Quote-aware shell parser that finds simple commands and their command words.
//!
//! Covers POSIX sh, bash and the common zsh syntax: separators and newlines,
//! subshells, `case`/`for`/`function` headers, assignments, redirections,
//! heredocs, quoting (`'..'`, `".."`, `$'..'`, `$".."`, `\`), and
//! substitutions (`$(..)`, backticks, `<(..)`, `>(..)`), which are parsed
//! recursively wherever they appear.

use std::collections::HashMap;

use super::commands::{self, Cx, StdinUse};
use super::{Site, Word};

/// Maximum nesting of substitutions, parameter expansions and re-parsed strings.
pub const MAX_DEPTH: usize = 12;

#[derive(Debug)]
pub struct ParseError;

type PResult<T> = Result<T, ParseError>;

/// Parse `text` as a shell script and append its sites. On a parse error the
/// whole text is also added as an [`Site::Anywhere`] site.
pub fn parse_script_into(text: &str, depth: usize, comments: bool, sites: &mut Vec<Site>) {
    if depth > MAX_DEPTH {
        sites.push(Site::Anywhere(text.to_string()));
        return;
    }
    let mut p = Parser {
        src: text.chars().collect(),
        pos: 0,
        depth,
        comments,
        sites,
        heredocs: Vec::new(),
        stdin_use: HashMap::new(),
        next_serial: 0,
    };
    if p.parse_list(Stop::Eof).is_err() {
        p.sites.push(Site::Anywhere(text.to_string()));
    }
}

struct Parser<'s> {
    src: Vec<char>,
    pos: usize,
    depth: usize,
    comments: bool,
    sites: &'s mut Vec<Site>,
    /// Heredocs whose bodies start at the next newline.
    heredocs: Vec<Heredoc>,
    /// How each finished command (by serial) consumes its stdin.
    stdin_use: HashMap<usize, StdinUse>,
    next_serial: usize,
}

struct Heredoc {
    delim: String,
    quoted: bool,
    strip_tabs: bool,
    serial: usize,
}

struct Cmd {
    serial: usize,
    start: usize,
    words: Vec<Word>,
    herestrings: Vec<String>,
}

/// The commands of the pipeline being built, for `... | sh`.
struct Pipe {
    start: usize,
    serials: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    /// After `for`/`select`: words up to the next separator are data.
    ForHeader,
    /// After `case`: the subject word.
    CaseWord,
    /// After the case subject: `in`.
    CaseIn,
    /// Case patterns, up to `)`.
    CasePattern,
    /// After `function`: the function name.
    FuncName,
}

#[derive(Debug, PartialEq, Eq)]
enum Ctx {
    Paren,
    Case,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    Eof,
    /// Inside `$(`, `<(` or `>(`: return after the closing `)`.
    Paren,
}

const RESERVED: &[&str] = &[
    "!", "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "{", "}", "coproc",
];

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.src.get(self.pos + n).copied()
    }

    fn slice(&self, from: usize, to: usize) -> String {
        self.src[from..to].iter().collect()
    }

    fn enter(&mut self) -> PResult<()> {
        if self.depth >= MAX_DEPTH {
            return Err(ParseError);
        }
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.depth -= 1;
    }

    fn new_cmd(&mut self) -> Cmd {
        let serial = self.next_serial;
        self.next_serial += 1;
        Cmd {
            serial,
            start: self.pos,
            words: Vec::new(),
            herestrings: Vec::new(),
        }
    }

    fn script(&mut self, text: &str) {
        parse_script_into(text, self.depth + 1, self.comments, self.sites);
    }

    fn parse_list(&mut self, stop: Stop) -> PResult<()> {
        let mut mode = Mode::Normal;
        let mut ctx: Vec<Ctx> = Vec::new();
        let mut cmd = self.new_cmd();
        let mut pipe: Option<Pipe> = None;

        loop {
            self.skip_blanks();
            let Some(c) = self.peek() else {
                break;
            };
            match c {
                '#' if self.comments => self.skip_comment(),
                '\n' => {
                    self.pos += 1;
                    if !matches!(mode, Mode::CaseWord | Mode::CaseIn | Mode::CasePattern) {
                        self.finish(&mut cmd, &mut pipe, false);
                        if mode != Mode::FuncName {
                            mode = Mode::Normal;
                        }
                    }
                    self.read_heredoc_bodies();
                }
                ';' | '&' | '|' => {
                    if c == '&' && self.peek_at(1) == Some('>') {
                        self.redirect(&mut cmd)?;
                        continue;
                    }
                    let op = self.read_op();
                    if mode == Mode::CasePattern {
                        continue;
                    }
                    self.finish(&mut cmd, &mut pipe, op == "|" || op == "|&");
                    if matches!(op, ";;" | ";&" | ";;&") && ctx.last() == Some(&Ctx::Case) {
                        mode = Mode::CasePattern;
                    } else {
                        mode = Mode::Normal;
                    }
                }
                '(' => {
                    self.pos += 1;
                    if mode == Mode::CasePattern {
                        continue;
                    }
                    self.finish(&mut cmd, &mut pipe, false);
                    ctx.push(Ctx::Paren);
                    mode = Mode::Normal;
                }
                ')' => {
                    self.pos += 1;
                    if mode == Mode::CasePattern {
                        mode = Mode::Normal;
                        continue;
                    }
                    self.finish(&mut cmd, &mut pipe, false);
                    mode = Mode::Normal;
                    if ctx.last() == Some(&Ctx::Paren) {
                        ctx.pop();
                    } else if ctx.contains(&Ctx::Paren) || stop != Stop::Paren {
                        return Err(ParseError);
                    } else {
                        return Ok(());
                    }
                }
                '<' | '>' if self.peek_at(1) != Some('(') => self.redirect(&mut cmd)?,
                _ => {
                    let before = self.pos;
                    let w = self.read_word()?;
                    if self.pos == before {
                        return Err(ParseError);
                    }
                    if is_fd_prefix(&w)
                        && matches!(self.peek(), Some('<' | '>'))
                        && self.peek_at(1) != Some('(')
                    {
                        self.redirect(&mut cmd)?;
                        continue;
                    }
                    match mode {
                        Mode::ForHeader => {}
                        Mode::CaseWord => mode = Mode::CaseIn,
                        Mode::CaseIn => mode = Mode::CasePattern,
                        Mode::CasePattern => {
                            if w.text == "esac" && !w.quoted {
                                if ctx.last() == Some(&Ctx::Case) {
                                    ctx.pop();
                                }
                                mode = Mode::Normal;
                            }
                        }
                        Mode::FuncName => mode = Mode::Normal,
                        Mode::Normal => {
                            if cmd.words.is_empty() {
                                if let Some(v) = w.assign_value() {
                                    let v = v.to_string();
                                    self.script(&v);
                                    continue;
                                }
                                if !w.quoted && !w.dynamic {
                                    match w.text.as_str() {
                                        "for" | "select" => {
                                            mode = Mode::ForHeader;
                                            continue;
                                        }
                                        "case" => {
                                            ctx.push(Ctx::Case);
                                            mode = Mode::CaseWord;
                                            continue;
                                        }
                                        "function" => {
                                            mode = Mode::FuncName;
                                            continue;
                                        }
                                        "esac" => {
                                            if ctx.last() == Some(&Ctx::Case) {
                                                ctx.pop();
                                            }
                                            continue;
                                        }
                                        t if RESERVED.contains(&t) => continue,
                                        _ => {}
                                    }
                                }
                            }
                            cmd.words.push(w);
                        }
                    }
                }
            }
        }

        self.finish(&mut cmd, &mut pipe, false);
        self.read_heredoc_bodies();
        if stop == Stop::Paren {
            return Err(ParseError);
        }
        Ok(())
    }

    /// End the current simple command and analyze it.
    fn finish(&mut self, cmd: &mut Cmd, pipe: &mut Option<Pipe>, into_pipe: bool) {
        let fresh = self.new_cmd();
        let done = std::mem::replace(cmd, fresh);
        if !done.words.is_empty() {
            let stdin = {
                let mut cx = Cx::new(self.sites, self.depth, self.comments);
                commands::analyze(&done.words, &done.herestrings, &mut cx)
            };
            if stdin != StdinUse::None {
                self.stdin_use.insert(done.serial, stdin);
                if let Some(p) = pipe.as_ref() {
                    let left = self.slice(p.start, done.start);
                    if let Some(site) = stdin.site(left) {
                        self.sites.push(site);
                    }
                    for s in &p.serials {
                        self.stdin_use.insert(*s, stdin);
                    }
                }
            }
        }
        if into_pipe {
            let p = pipe.get_or_insert(Pipe {
                start: done.start,
                serials: Vec::new(),
            });
            p.serials.push(done.serial);
        } else {
            *pipe = None;
        }
    }

    fn skip_blanks(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' {
                self.pos += 1;
            } else if c == '\\' && self.peek_at(1) == Some('\n') {
                self.pos += 2;
            } else {
                break;
            }
        }
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.pos += 1;
        }
    }

    fn read_op(&mut self) -> &'static str {
        let c = self.peek();
        let n1 = self.peek_at(1);
        let n2 = self.peek_at(2);
        let op = match (c, n1, n2) {
            (Some(';'), Some(';'), Some('&')) => ";;&",
            (Some(';'), Some(';'), _) => ";;",
            (Some(';'), Some('&'), _) => ";&",
            (Some(';'), _, _) => ";",
            (Some('&'), Some('&'), _) => "&&",
            (Some('&'), _, _) => "&",
            (Some('|'), Some('|'), _) => "||",
            (Some('|'), Some('&'), _) => "|&",
            _ => "|",
        };
        self.pos += op.len();
        op
    }

    fn read_redirect_op(&mut self) -> &'static str {
        let c = self.peek();
        let n1 = self.peek_at(1);
        let n2 = self.peek_at(2);
        let op = match (c, n1, n2) {
            (Some('&'), Some('>'), Some('>')) => "&>>",
            (Some('&'), Some('>'), _) => "&>",
            (Some('<'), Some('<'), Some('<')) => "<<<",
            (Some('<'), Some('<'), Some('-')) => "<<-",
            (Some('<'), Some('<'), _) => "<<",
            (Some('<'), Some('>'), _) => "<>",
            (Some('<'), Some('&'), _) => "<&",
            (Some('<'), _, _) => "<",
            (Some('>'), Some('>'), _) => ">>",
            (Some('>'), Some('&'), _) => ">&",
            (Some('>'), Some('|'), _) => ">|",
            _ => ">",
        };
        self.pos += op.len();
        op
    }

    fn redirect(&mut self, cmd: &mut Cmd) -> PResult<()> {
        let op = self.read_redirect_op();
        self.skip_blanks();
        match self.peek() {
            None | Some('\n' | ';' | '&' | '|' | '(' | ')') => return Err(ParseError),
            Some('<' | '>') if self.peek_at(1) != Some('(') => return Err(ParseError),
            _ => {}
        }
        let before = self.pos;
        let target = self.read_word()?;
        if self.pos == before {
            return Err(ParseError);
        }
        match op {
            "<<" | "<<-" => self.heredocs.push(Heredoc {
                delim: target.text,
                quoted: target.quoted,
                strip_tabs: op == "<<-",
                serial: cmd.serial,
            }),
            "<<<" => cmd.herestrings.push(target.text),
            _ => {}
        }
        Ok(())
    }

    fn read_heredoc_bodies(&mut self) {
        let pending = std::mem::take(&mut self.heredocs);
        for h in pending {
            let mut body = String::new();
            while self.pos < self.src.len() {
                let eol = self.src[self.pos..]
                    .iter()
                    .position(|&c| c == '\n')
                    .map_or(self.src.len(), |i| self.pos + i);
                let line = self.slice(self.pos, eol);
                self.pos = (eol + 1).min(self.src.len());
                let check = if h.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if check == h.delim {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if !h.quoted {
                self.scan_expansions(&body);
            }
            if let Some(site) = self.stdin_use.get(&h.serial).and_then(|u| u.site(body)) {
                self.sites.push(site);
            }
        }
    }

    /// Parse the substitutions in text that is expanded like a double-quoted string.
    fn scan_expansions(&mut self, text: &str) {
        if self.depth + 1 > MAX_DEPTH {
            self.sites.push(Site::Anywhere(text.to_string()));
            return;
        }
        let mut p = Parser {
            src: text.chars().collect(),
            pos: 0,
            depth: self.depth + 1,
            comments: self.comments,
            sites: &mut *self.sites,
            heredocs: Vec::new(),
            stdin_use: HashMap::new(),
            next_serial: 0,
        };
        let mut w = Word::default();
        if p.read_dquote(&mut w, None).is_err() {
            p.sites.push(Site::Anywhere(text.to_string()));
        }
    }

    fn read_word(&mut self) -> PResult<Word> {
        let mut w = Word::default();
        // Only unquoted literal characters so far; needed for `NAME=` detection.
        let mut pure = true;
        let mut open_brace = false;
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | ')' => break,
                '(' => {
                    if w.assign == Some(w.text.len()) {
                        self.pos += 1;
                        self.read_array(&mut w)?;
                        pure = false;
                        continue;
                    }
                    break;
                }
                '<' | '>' => {
                    if self.peek_at(1) != Some('(') {
                        break;
                    }
                    self.pos += 2;
                    let opener = if c == '<' { "<(" } else { ">(" };
                    self.read_cmd_sub(&mut w, opener)?;
                    pure = false;
                }
                '\\' => {
                    pure = false;
                    match self.peek_at(1) {
                        Some('\n') => self.pos += 2,
                        Some(n) => {
                            w.text.push(n);
                            w.quoted = true;
                            self.pos += 2;
                        }
                        None => {
                            w.text.push('\\');
                            self.pos += 1;
                        }
                    }
                }
                '\'' => {
                    pure = false;
                    w.quoted = true;
                    self.pos += 1;
                    self.read_single(&mut w)?;
                }
                '"' => {
                    pure = false;
                    w.quoted = true;
                    self.pos += 1;
                    self.read_dquote(&mut w, Some('"'))?;
                }
                '$' => {
                    pure = false;
                    self.read_dollar(&mut w, false)?;
                }
                '`' => {
                    pure = false;
                    self.read_backtick(&mut w)?;
                }
                '=' => {
                    if w.assign.is_none() && pure && is_assign_name(&w.text) {
                        w.assign = Some(w.text.len() + 1);
                    }
                    pure = false;
                    w.text.push('=');
                    self.pos += 1;
                }
                '*' | '?' | '[' => {
                    w.glob = true;
                    w.text.push(c);
                    self.pos += 1;
                }
                '{' => {
                    open_brace = true;
                    w.text.push(c);
                    self.pos += 1;
                }
                '}' => {
                    if open_brace {
                        w.brace = true;
                    }
                    w.text.push(c);
                    self.pos += 1;
                }
                _ => {
                    w.text.push(c);
                    self.pos += 1;
                }
            }
        }
        Ok(w)
    }

    /// `NAME=(a b c)`: elements are joined by newlines so each is its own command when re-parsed.
    fn read_array(&mut self, w: &mut Word) -> PResult<()> {
        self.enter()?;
        let mut first = true;
        let result = loop {
            while matches!(self.peek(), Some(' ' | '\t' | '\r' | '\n')) {
                self.pos += 1;
            }
            match self.peek() {
                None => break Err(ParseError),
                Some(')') => {
                    self.pos += 1;
                    break Ok(());
                }
                _ => {}
            }
            let before = self.pos;
            let el = match self.read_word() {
                Ok(el) => el,
                Err(e) => break Err(e),
            };
            if self.pos == before {
                break Err(ParseError);
            }
            if !first {
                w.text.push('\n');
            }
            first = false;
            w.text.push_str(&el.text);
            w.subs.extend(el.subs);
            w.dynamic |= el.dynamic;
            w.quoted |= el.quoted;
        };
        self.leave();
        result
    }

    fn read_single(&mut self, w: &mut Word) -> PResult<()> {
        loop {
            let Some(c) = self.peek() else {
                return Err(ParseError);
            };
            self.pos += 1;
            if c == '\'' {
                return Ok(());
            }
            w.text.push(c);
        }
    }

    /// Double-quoted text up to `term`, or to end of input when `term` is `None` (heredoc bodies).
    fn read_dquote(&mut self, w: &mut Word, term: Option<char>) -> PResult<()> {
        loop {
            let Some(c) = self.peek() else {
                return if term.is_some() {
                    Err(ParseError)
                } else {
                    Ok(())
                };
            };
            if Some(c) == term {
                self.pos += 1;
                return Ok(());
            }
            match c {
                '\\' => match self.peek_at(1) {
                    Some('\n') => self.pos += 2,
                    Some(n) if matches!(n, '$' | '`' | '\\') || (n == '"' && term.is_some()) => {
                        w.text.push(n);
                        self.pos += 2;
                    }
                    _ => {
                        w.text.push('\\');
                        self.pos += 1;
                    }
                },
                '$' => self.read_dollar(w, true)?,
                '`' => self.read_backtick(w)?,
                _ => {
                    w.text.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn read_dollar(&mut self, w: &mut Word, in_dquote: bool) -> PResult<()> {
        match self.peek_at(1) {
            Some('(') => {
                self.pos += 2;
                self.read_cmd_sub(w, "$(")
            }
            Some('{') => {
                self.pos += 2;
                self.read_braced_param(w, in_dquote)
            }
            Some('\'') if !in_dquote => {
                self.pos += 2;
                w.quoted = true;
                self.read_ansi_c(w)
            }
            Some('"') if !in_dquote => {
                self.pos += 2;
                w.quoted = true;
                self.read_dquote(w, Some('"'))
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                self.pos += 1;
                w.text.push('$');
                while let Some(c) = self.peek() {
                    if !(c.is_ascii_alphanumeric() || c == '_') {
                        break;
                    }
                    w.text.push(c);
                    self.pos += 1;
                }
                w.dynamic = true;
                Ok(())
            }
            Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(c) => {
                w.text.push('$');
                w.text.push(c);
                self.pos += 2;
                w.dynamic = true;
                Ok(())
            }
            _ => {
                w.text.push('$');
                self.pos += 1;
                Ok(())
            }
        }
    }

    /// `$(...)`, `<(...)` or `>(...)`; `self.pos` is just past the opening paren.
    fn read_cmd_sub(&mut self, w: &mut Word, opener: &str) -> PResult<()> {
        self.enter()?;
        let start = self.pos;
        let result = self.parse_list(Stop::Paren);
        self.leave();
        result?;
        let inner = self.slice(start, self.pos - 1);
        w.text.push_str(opener);
        w.text.push_str(&inner);
        w.text.push(')');
        w.subs.push(inner);
        w.dynamic = true;
        Ok(())
    }

    /// `${...}`; `self.pos` is just past the `{`.
    fn read_braced_param(&mut self, w: &mut Word, in_dquote: bool) -> PResult<()> {
        self.enter()?;
        w.text.push_str("${");
        w.dynamic = true;
        let mut depth = 1;
        let result = loop {
            let Some(c) = self.peek() else {
                break Err(ParseError);
            };
            let step = match c {
                '}' => {
                    depth -= 1;
                    w.text.push('}');
                    self.pos += 1;
                    if depth == 0 {
                        break Ok(());
                    }
                    Ok(())
                }
                '{' => {
                    depth += 1;
                    w.text.push('{');
                    self.pos += 1;
                    Ok(())
                }
                '\\' => {
                    w.text.push('\\');
                    self.pos += 1;
                    if let Some(n) = self.peek() {
                        w.text.push(n);
                        self.pos += 1;
                    }
                    Ok(())
                }
                '\'' if !in_dquote => {
                    self.pos += 1;
                    self.read_single(w)
                }
                '"' => {
                    self.pos += 1;
                    self.read_dquote(w, Some('"'))
                }
                '$' => self.read_dollar(w, in_dquote),
                '`' => self.read_backtick(w),
                _ => {
                    w.text.push(c);
                    self.pos += 1;
                    Ok(())
                }
            };
            if step.is_err() {
                break step;
            }
        };
        self.leave();
        result
    }

    fn read_backtick(&mut self, w: &mut Word) -> PResult<()> {
        self.pos += 1;
        let mut inner = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(ParseError);
            };
            self.pos += 1;
            match c {
                '`' => break,
                '\\' => match self.peek() {
                    Some(n @ ('`' | '\\' | '$' | '"')) => {
                        inner.push(n);
                        self.pos += 1;
                    }
                    _ => inner.push('\\'),
                },
                _ => inner.push(c),
            }
        }
        self.script(&inner);
        w.text.push('`');
        w.text.push_str(&inner);
        w.text.push('`');
        w.subs.push(inner);
        w.dynamic = true;
        Ok(())
    }

    /// `$'...'`; `self.pos` is just past the opening quote.
    fn read_ansi_c(&mut self, w: &mut Word) -> PResult<()> {
        loop {
            let Some(c) = self.peek() else {
                return Err(ParseError);
            };
            self.pos += 1;
            match c {
                '\'' => return Ok(()),
                '\\' => {
                    let Some(e) = self.peek() else {
                        return Err(ParseError);
                    };
                    self.pos += 1;
                    let decoded = match e {
                        'a' => Some('\x07'),
                        'b' => Some('\x08'),
                        'e' | 'E' => Some('\x1b'),
                        'f' => Some('\x0c'),
                        'n' => Some('\n'),
                        'r' => Some('\r'),
                        't' => Some('\t'),
                        'v' => Some('\x0b'),
                        '\\' | '\'' | '"' | '?' => Some(e),
                        'x' => self.read_radix(2, 16),
                        'u' => self.read_radix(4, 16),
                        'U' => self.read_radix(8, 16),
                        '0'..='7' => {
                            self.pos -= 1;
                            self.read_radix(3, 8)
                        }
                        'c' => {
                            let ctl = self.peek().map(|c| char::from((c as u8) & 0x1f));
                            if ctl.is_some() {
                                self.pos += 1;
                            }
                            ctl
                        }
                        _ => None,
                    };
                    match decoded {
                        Some(d) => w.text.push(d),
                        None => {
                            w.text.push('\\');
                            w.text.push(e);
                        }
                    }
                }
                _ => w.text.push(c),
            }
        }
    }

    fn read_radix(&mut self, max_digits: usize, radix: u32) -> Option<char> {
        let mut value: u32 = 0;
        let mut n = 0;
        while n < max_digits {
            let Some(d) = self.peek().and_then(|c| c.to_digit(radix)) else {
                break;
            };
            value = value * radix + d;
            self.pos += 1;
            n += 1;
        }
        if n == 0 {
            return None;
        }
        char::from_u32(value)
    }
}

/// `NAME`, `NAME+` or `NAME[sub]` before an `=`.
fn is_assign_name(s: &str) -> bool {
    let s = s.strip_suffix('+').unwrap_or(s);
    let s = match s.find('[') {
        Some(i) if s.ends_with(']') => &s[..i],
        Some(_) => return false,
        None => s,
    };
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A word that is a file-descriptor prefix of a following redirection (`2>`, `{fd}>`).
fn is_fd_prefix(w: &Word) -> bool {
    if w.quoted || w.dynamic || w.text.is_empty() {
        return false;
    }
    w.text.chars().all(|c| c.is_ascii_digit())
        || (w.text.starts_with('{') && w.text.ends_with('}') && w.text.len() > 2)
}
