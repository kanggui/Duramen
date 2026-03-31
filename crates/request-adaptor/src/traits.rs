use duramen_engine::entities::{AuthzRequest, RawHookPayload};

#[derive(Debug, thiserror::Error)]
pub enum NormalizerError {
    #[error("missing required field: {0}")]
    MissingField(String),
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub trait AgentNormalizer {
    fn normalize(&self, raw_input: &RawHookPayload) -> Result<Vec<AuthzRequest>, NormalizerError>;
    fn agent_type(&self) -> &str;
}
