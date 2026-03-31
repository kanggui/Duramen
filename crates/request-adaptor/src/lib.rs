pub mod classifiers;
pub mod commands;
pub mod copilot_cli;
pub mod enrichers;
pub mod generic;
pub mod pipeline;
pub mod traits;

use traits::{AgentNormalizer, NormalizerError};

pub fn get_normalizer(agent: &str) -> Result<Box<dyn AgentNormalizer>, NormalizerError> {
    match agent {
        "copilot-cli" => Ok(Box::new(copilot_cli::CopilotCliNormalizer)),
        "generic" | "" => Ok(Box::new(generic::GenericNormalizer)),
        unknown => Err(NormalizerError::InvalidPayload(format!(
            "unknown agent: {unknown}"
        ))),
    }
}
