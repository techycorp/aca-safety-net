//! Tool analysis entry points.

mod bash;
mod edit;
mod path_tool;
mod read;
mod write;

pub use bash::analyze_bash;
pub use edit::analyze_edit;
pub use path_tool::analyze_path_tool;
pub use read::analyze_read;
pub use write::analyze_write;
