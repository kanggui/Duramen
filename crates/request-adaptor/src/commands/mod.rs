pub mod default;
pub mod git;
pub mod rm;

use duramen_engine::entities::AuthzResource;

/// Result of parsing a shell command: the Cedar action name and the target resource.
#[derive(Clone)]
pub struct CommandParseResult {
    pub action: String,
    pub resource: AuthzResource,
}

/// Trait for command-specific parsing logic.
/// Each handler knows how to parse one binary's arguments into a Cedar action + resource.
pub trait CommandHandler {
    /// The binary name this handler matches (e.g., "git", "docker").
    fn binary_name(&self) -> &str;

    /// Parse the command arguments into a Cedar action and resource.
    /// `args` is everything after the binary name (already prefix-stripped).
    /// `cwd` is the working directory if available.
    fn parse(&self, args: &[&str], cwd: Option<&str>) -> CommandParseResult;
}

/// Look up a command handler by binary name.
/// Returns None if no special handler exists (caller should use DefaultCommandHandler).
pub fn get_command_handler(binary: &str) -> Option<Box<dyn CommandHandler>> {
    match binary {
        "git" => Some(Box::new(git::GitCommandHandler)),
        "rm" | "del" | "Remove-Item" => Some(Box::new(rm::RmCommandHandler)),
        _ => None,
    }
}
