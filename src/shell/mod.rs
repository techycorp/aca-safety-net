//! Shell command parsing.

pub mod exec_sites;
mod splitter;
mod tokenizer;
mod wrappers;

pub use splitter::{CommandSegment, Operator, split_commands};
pub use tokenizer::{Token, tokenize};
pub use wrappers::{extract_options, strip_wrappers};
