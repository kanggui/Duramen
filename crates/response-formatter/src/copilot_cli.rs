use crate::traits::{FormattedResponse, ResponseFormatter};
use duramen_engine::decision::{AuthzDecision, DecisionTier};
use duramen_engine::entities::AuthzRequest;
use serde::Serialize;

#[derive(Serialize)]
struct CopilotResponse {
    allowed: bool,
    message: String,
    should_prompt_user: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_description: Option<String>,
}

pub struct CopilotCliFormatter;

impl ResponseFormatter for CopilotCliFormatter {
    fn format(&self, decision: &AuthzDecision, _request: &AuthzRequest) -> FormattedResponse {
        let response = CopilotResponse {
            allowed: decision.is_allowed(),
            message: decision.reason.clone(),
            should_prompt_user: decision.decision == DecisionTier::RequireApproval,
            policy_id: decision.policy_id.clone(),
            policy_name: decision.policy_name.clone(),
            policy_description: decision.policy_description.clone(),
        };

        let stdout = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"));

        FormattedResponse {
            stdout,
            exit_code: decision.exit_code(),
        }
    }

    fn agent_type(&self) -> &str {
        "copilot-cli"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn copilot_allow_response() {
        let decision = AuthzDecision::new(DecisionTier::Allow, "allowed".to_string());
        let formatter = CopilotCliFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 0);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["allowed"], true);
        assert_eq!(parsed["should_prompt_user"], false);
        assert_eq!(parsed["message"], "allowed");
    }

    #[test]
    fn copilot_deny_response() {
        let mut decision = AuthzDecision::new(DecisionTier::Deny, "blocked by policy".to_string());
        decision.policy_id = Some("policy-shell-deny".to_string());
        let formatter = CopilotCliFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 1);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["allowed"], false);
        assert_eq!(parsed["should_prompt_user"], false);
        assert_eq!(parsed["policy_id"], "policy-shell-deny");
    }

    #[test]
    fn copilot_require_approval_prompts_user() {
        let decision =
            AuthzDecision::new(DecisionTier::RequireApproval, "needs user ok".to_string());
        let formatter = CopilotCliFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 2);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["allowed"], false);
        assert_eq!(parsed["should_prompt_user"], true);
    }

    #[test]
    fn copilot_audit_response() {
        let decision = AuthzDecision::new(DecisionTier::Audit, "audited".to_string());
        let formatter = CopilotCliFormatter;
        let resp = formatter.format(&decision, &sample_request());

        assert_eq!(resp.exit_code, 0);
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();
        assert_eq!(parsed["allowed"], true);
        assert_eq!(parsed["should_prompt_user"], false);
    }

    #[test]
    fn copilot_response_includes_policy_metadata() {
        let mut decision = AuthzDecision::new(DecisionTier::Deny, "denied".to_string());
        decision.policy_id = Some("deny-force-push".into());
        decision.policy_name = Some("Deny force push".into());
        decision.policy_description = Some("Blocks force-push ops".into());

        let formatter = CopilotCliFormatter;
        let resp = formatter.format(&decision, &sample_request());
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();

        assert_eq!(parsed["policy_id"], "deny-force-push");
        assert_eq!(parsed["policy_name"], "Deny force push");
        assert_eq!(parsed["policy_description"], "Blocks force-push ops");
    }

    #[test]
    fn copilot_response_omits_none_metadata() {
        let decision = AuthzDecision::new(DecisionTier::Allow, "ok".to_string());
        let formatter = CopilotCliFormatter;
        let resp = formatter.format(&decision, &sample_request());
        let parsed: serde_json::Value = serde_json::from_str(&resp.stdout).unwrap();

        assert!(parsed.get("policy_id").is_none());
        assert!(parsed.get("policy_name").is_none());
        assert!(parsed.get("policy_description").is_none());
    }
}
