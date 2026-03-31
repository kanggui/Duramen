pub mod copilot_cli;
pub mod generic;
pub mod traits;

use traits::ResponseFormatter;

pub fn get_formatter(agent: &str) -> Result<Box<dyn ResponseFormatter>, String> {
    match agent {
        "copilot-cli" => Ok(Box::new(copilot_cli::CopilotCliFormatter)),
        "generic" | "" => Ok(Box::new(generic::GenericFormatter)),
        unknown => Err(format!("unknown agent: {unknown}")),
    }
}
