use crate::traits::{AgentNormalizer, NormalizerError};
use duramen_engine::entities::{AuthzRequest, RawHookPayload};

pub struct GenericNormalizer;

impl AgentNormalizer for GenericNormalizer {
    fn normalize(&self, raw_input: &RawHookPayload) -> Result<Vec<AuthzRequest>, NormalizerError> {
        let request: AuthzRequest =
            serde_json::from_value(raw_input.args.clone()).map_err(NormalizerError::Json)?;
        Ok(vec![request])
    }

    fn agent_type(&self) -> &str {
        "generic"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn generic_normalizer_parses_full_request() {
        let payload = RawHookPayload {
            tool: "anything".to_string(),
            args: json!({
                "principal": { "agent_type": "test-agent" },
                "action": { "name": "file:read" },
                "resource": { "resource_type": "file", "id": "/tmp/test.txt" },
                "context": { "tool_name": "view" }
            }),
            cwd: None,
            timestamp: None,
        };

        let normalizer = GenericNormalizer;
        let results = normalizer.normalize(&payload).unwrap();
        let result = &results[0];
        assert_eq!(result.action.name, "file:read");
        assert_eq!(result.resource.id, "/tmp/test.txt");
        assert_eq!(result.principal.agent_type, "test-agent");
        assert_eq!(result.context.tool_name, "view");
    }

    #[test]
    fn generic_normalizer_rejects_invalid_payload() {
        let payload = RawHookPayload {
            tool: "anything".to_string(),
            args: json!({ "not_a_valid": "request" }),
            cwd: None,
            timestamp: None,
        };

        let normalizer = GenericNormalizer;
        let result = normalizer.normalize(&payload);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NormalizerError::Json(_)));
    }
}
