use crate::traits::{FormattedResponse, ResponseFormatter};
use duramen_engine::decision::AuthzDecision;
use duramen_engine::entities::AuthzRequest;

pub struct GenericFormatter;

impl ResponseFormatter for GenericFormatter {
    fn format(&self, decision: &AuthzDecision, _request: &AuthzRequest) -> FormattedResponse {
        let stdout = serde_json::to_string_pretty(decision)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));
        FormattedResponse {
            stdout,
            exit_code: decision.exit_code(),
        }
    }

    fn agent_type(&self) -> &str {
        "generic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duramen_engine::decision::DecisionTier;
    use duramen_engine::entities::{AgentPrincipal, AuthzAction, AuthzContext, AuthzResource};

    fn sample_request() -> AuthzRequest {
        AuthzRequest {
            principal: AgentPrincipal::new("test"),
            action: AuthzAction::new("file:read"),
            resource: AuthzResource::file("/test.txt"),
            context: AuthzContext {
                tool_name: "view".to_string(),
                working_directory: None,
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            },
        }
    }

    #[test]
    fn formats_allow_as_json() {
        let decision = AuthzDecision::new(DecisionTier::Allow, "policy allows".to_string());
        let formatter = GenericFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 0);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["decision"], "allow");
        assert_eq!(parsed["reason"], "policy allows");
    }

    #[test]
    fn formats_deny_with_exit_code_1() {
        let decision = AuthzDecision::new(DecisionTier::Deny, "denied by policy".to_string());
        let formatter = GenericFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 1);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["decision"], "deny");
    }

    #[test]
    fn formats_require_approval_with_exit_code_2() {
        let decision =
            AuthzDecision::new(DecisionTier::RequireApproval, "needs approval".to_string());
        let formatter = GenericFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 2);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["decision"], "require-approval");
    }

    #[test]
    fn formats_audit_with_exit_code_0() {
        let decision = AuthzDecision::new(DecisionTier::Audit, "audit logged".to_string());
        let formatter = GenericFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 0);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["decision"], "audit");
    }

    #[test]
    fn generic_includes_policy_metadata_when_present() {
        let mut decision = AuthzDecision::new(DecisionTier::Deny, "denied".to_string());
        decision.policy_name = Some("Test policy".into());
        let formatter = GenericFormatter;
        let resp = formatter.format(&decision, &sample_request());
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["policy_name"], "Test policy");
    }
}
