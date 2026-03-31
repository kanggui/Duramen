use crate::decision::AuthzDecision;
use crate::entities::AuthzRequest;

pub trait PolicyEngine {
    fn evaluate(&self, request: &AuthzRequest) -> Result<AuthzDecision, EngineError>;
    fn validate_policies(&self) -> Result<(), EngineError>;
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("policy parse error: {0}")]
    PolicyParse(String),
    #[error("evaluation error: {0}")]
    Evaluation(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
