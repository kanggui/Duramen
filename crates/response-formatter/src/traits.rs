use duramen_engine::decision::AuthzDecision;
use duramen_engine::entities::AuthzRequest;

pub struct FormattedResponse {
    pub stdout: String,
    pub exit_code: i32,
}

pub trait ResponseFormatter {
    fn format(&self, decision: &AuthzDecision, request: &AuthzRequest) -> FormattedResponse;
    fn agent_type(&self) -> &str;
}
