use crate::adapter::{EngineError, PolicyEngine};
use crate::decision::{AuthzDecision, DecisionTier};
use crate::entities::AuthzRequest;
use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityUid, PolicySet, Request, RestrictedExpression,
    Schema, ValidationMode, Validator,
};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

pub struct CedarEngine {
    policy_set: PolicySet,
    schema: Option<Schema>,
}

impl CedarEngine {
    pub fn from_policy_str(policy_src: &str) -> Result<Self, EngineError> {
        let policy_set: PolicySet = if policy_src.trim().is_empty() {
            PolicySet::new()
        } else {
            policy_src
                .parse()
                .map_err(|e| EngineError::PolicyParse(format!("{e}")))?
        };
        Ok(Self {
            policy_set,
            schema: None,
        })
    }

    pub fn from_policy_set(policy_set: PolicySet) -> Self {
        Self {
            policy_set,
            schema: None,
        }
    }

    /// Create an engine from policy source strings and a Cedar schema string.
    /// Used by the `validate` command to perform schema-aware validation.
    pub fn from_policy_sources_with_schema(
        policy_sources: &[String],
        schema_src: &str,
    ) -> Result<Self, EngineError> {
        let combined = policy_sources.join("\n");
        let policy_set: PolicySet = if combined.trim().is_empty() {
            PolicySet::new()
        } else {
            combined
                .parse()
                .map_err(|e| EngineError::PolicyParse(format!("{e}")))?
        };
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_src)
            .map_err(|e| EngineError::Other(format!("schema parse error: {e}")))?;
        Ok(Self {
            policy_set,
            schema: Some(schema),
        })
    }

    fn build_cedar_entities(
        &self,
        request: &AuthzRequest,
    ) -> Result<(Request, Entities), EngineError> {
        // Build UIDs
        let principal_uid: EntityUid = format!(r#"Agent::"{}""#, request.principal.agent_type)
            .parse()
            .map_err(|e| EngineError::Evaluation(format!("bad principal: {e}")))?;
        let action_uid: EntityUid = format!(r#"Action::"{}""#, request.action.name)
            .parse()
            .map_err(|e| EngineError::Evaluation(format!("bad action: {e}")))?;
        let resource_type = match request.resource.resource_type {
            crate::entities::ResourceType::File => "File",
            crate::entities::ResourceType::Command => "Command",
            crate::entities::ResourceType::Url => "Url",
            crate::entities::ResourceType::GitRef => "GitRef",
        };
        // Escape backslashes and strip embedded quotes for Cedar UID parsing
        let sanitized_resource_id = request.resource.id.replace('\\', "\\\\").replace('"', "");
        let resource_uid: EntityUid = format!(r#"{}::"{}""#, resource_type, sanitized_resource_id)
            .parse()
            .map_err(|e| EngineError::Evaluation(format!("bad resource: {e}")))?;

        // Build resource entity with attributes
        let resource_attrs = Self::json_to_cedar_attrs(&request.resource.attributes);
        let resource_entity = Entity::new(resource_uid.clone(), resource_attrs, HashSet::new())
            .map_err(|e| EngineError::Evaluation(format!("resource entity error: {e}")))?;

        // Build principal entity with attributes from AgentPrincipal
        let mut principal_attrs: HashMap<String, RestrictedExpression> = HashMap::new();
        if let Some(ref trust) = request.principal.trust_level {
            principal_attrs.insert(
                "trust_level".into(),
                RestrictedExpression::new_string(trust.clone()),
            );
        }
        if let Some(ref session) = request.principal.session_id {
            principal_attrs.insert(
                "session_id".into(),
                RestrictedExpression::new_string(session.clone()),
            );
        }
        if let Some(ref user) = request.principal.user {
            principal_attrs.insert(
                "user".into(),
                RestrictedExpression::new_string(user.clone()),
            );
        }
        let principal_entity = Entity::new(principal_uid.clone(), principal_attrs, HashSet::new())
            .map_err(|e| EngineError::Evaluation(format!("principal entity error: {e}")))?;

        // Build entities store
        let entities = Entities::from_entities([principal_entity, resource_entity], None)
            .map_err(|e| EngineError::Evaluation(format!("entities error: {e}")))?;

        // Build Cedar context from AuthzContext fields
        let mut context_map = serde_json::Map::new();
        context_map.insert(
            "tool_name".into(),
            serde_json::Value::String(request.context.tool_name.clone()),
        );
        if let Some(ref wd) = request.context.working_directory {
            context_map.insert(
                "working_directory".into(),
                serde_json::Value::String(wd.clone()),
            );
        }
        if !request.context.file_patterns_affected.is_empty() {
            context_map.insert(
                "file_patterns_affected".into(),
                serde_json::Value::String(request.context.file_patterns_affected.join(",")),
            );
        }
        let context = Context::from_json_value(serde_json::Value::Object(context_map), None)
            .unwrap_or_else(|_| Context::empty());
        let cedar_request = Request::new(principal_uid, action_uid, resource_uid, context, None)
            .map_err(|e| EngineError::Evaluation(format!("request build error: {e}")))?;

        Ok((cedar_request, entities))
    }

    fn json_to_cedar_attrs(attrs: &serde_json::Value) -> HashMap<String, RestrictedExpression> {
        let mut cedar_attrs = HashMap::new();
        if let Some(obj) = attrs.as_object() {
            for (key, value) in obj {
                let expr = match value {
                    serde_json::Value::Bool(b) => RestrictedExpression::new_bool(*b),
                    serde_json::Value::String(s) => RestrictedExpression::new_string(s.clone()),
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            RestrictedExpression::new_long(i)
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };
                cedar_attrs.insert(key.clone(), expr);
            }
        }
        cedar_attrs
    }

    fn check_advice(&self, response: &cedar_policy::Response) -> Option<DecisionTier> {
        for reason_id in response.diagnostics().reason() {
            if let Some(policy) = self.policy_set.policy(reason_id) {
                if let Some(annotation) = policy.annotation("advice") {
                    return match annotation {
                        "audit" => Some(DecisionTier::Audit),
                        "require-approval" => Some(DecisionTier::RequireApproval),
                        _ => None,
                    };
                }
            }
        }
        None
    }

    /// Extract @name and @description annotations from the determining policy.
    /// Prefers the policy with @advice annotation (since that determines the decision tier).
    /// Falls back to any policy with @name/@description.
    fn extract_policy_metadata(
        &self,
        response: &cedar_policy::Response,
    ) -> (Option<String>, Option<String>, Option<String>) {
        // First pass: prefer the policy with @advice (it determined the tier)
        for reason_id in response.diagnostics().reason() {
            if let Some(policy) = self.policy_set.policy(reason_id) {
                if policy.annotation("advice").is_some() {
                    let id = reason_id.to_string();
                    let name = policy.annotation("name").map(String::from);
                    let description = policy.annotation("description").map(String::from);
                    return (Some(id), name, description);
                }
            }
        }
        // Second pass: any policy with metadata
        for reason_id in response.diagnostics().reason() {
            if let Some(policy) = self.policy_set.policy(reason_id) {
                let name = policy.annotation("name").map(String::from);
                let description = policy.annotation("description").map(String::from);
                if name.is_some() || description.is_some() {
                    let id = reason_id.to_string();
                    return (Some(id), name, description);
                }
            }
        }
        (
            response
                .diagnostics()
                .reason()
                .next()
                .map(|id| id.to_string()),
            None,
            None,
        )
    }
}

impl PolicyEngine for CedarEngine {
    fn evaluate(&self, request: &AuthzRequest) -> Result<AuthzDecision, EngineError> {
        let start = Instant::now();
        let (cedar_request, entities) = self.build_cedar_entities(request)?;
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&cedar_request, &self.policy_set, &entities);
        let elapsed = start.elapsed().as_millis() as u64;

        let base_decision = match response.decision() {
            cedar_policy::Decision::Allow => DecisionTier::Allow,
            cedar_policy::Decision::Deny => DecisionTier::Deny,
        };

        let final_decision = if base_decision == DecisionTier::Allow {
            self.check_advice(&response).unwrap_or(DecisionTier::Allow)
        } else {
            base_decision
        };

        let (policy_id, policy_name, policy_description) = self.extract_policy_metadata(&response);

        let reason = match final_decision {
            DecisionTier::Allow => "request allowed by policy".to_string(),
            DecisionTier::Audit => "request allowed (audit logged)".to_string(),
            DecisionTier::RequireApproval => {
                if let Some(ref name) = policy_name {
                    format!("request requires human approval — {name}")
                } else {
                    "request requires human approval".to_string()
                }
            }
            DecisionTier::Deny => {
                let errors: Vec<String> = response
                    .diagnostics()
                    .errors()
                    .map(|e| e.to_string())
                    .collect();
                if errors.is_empty() {
                    "request denied by policy".to_string()
                } else {
                    format!("request denied: {}", errors.join("; "))
                }
            }
        };

        Ok(AuthzDecision {
            decision: final_decision,
            reason,
            policy_id,
            policy_name,
            policy_description,
            evaluation_time_ms: elapsed,
        })
    }

    fn validate_policies(&self) -> Result<(), EngineError> {
        let schema = match &self.schema {
            Some(s) => s,
            None => return Ok(()),
        };
        let validator = Validator::new(schema.clone());
        let result = validator.validate(&self.policy_set, ValidationMode::default());
        if result.validation_passed() {
            Ok(())
        } else {
            let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
            Err(EngineError::Validation(errors.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::{AgentPrincipal, AuthzAction, AuthzContext, AuthzResource};

    fn make_request() -> AuthzRequest {
        AuthzRequest {
            principal: AgentPrincipal::new("copilot"),
            action: AuthzAction::new("file:read"),
            resource: AuthzResource::file("/src/main.rs"),
            context: AuthzContext {
                tool_name: "view".into(),
                working_directory: Some("/project".into()),
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            },
        }
    }

    #[test]
    fn permits_when_policy_allows() {
        let engine =
            CedarEngine::from_policy_str(r#"permit(principal, action, resource);"#).unwrap();
        let decision = engine.evaluate(&make_request()).unwrap();
        assert!(decision.is_allowed());
        assert_eq!(decision.decision, DecisionTier::Allow);
    }

    #[test]
    fn denies_when_policy_forbids() {
        let engine = CedarEngine::from_policy_str(
            r#"
            permit(principal, action, resource);
            forbid(principal, action, resource);
            "#,
        )
        .unwrap();
        let decision = engine.evaluate(&make_request()).unwrap();
        assert!(!decision.is_allowed());
        assert_eq!(decision.decision, DecisionTier::Deny);
    }

    #[test]
    fn denies_when_no_policies_match() {
        let engine = CedarEngine::from_policy_str("").unwrap();
        let decision = engine.evaluate(&make_request()).unwrap();
        assert!(!decision.is_allowed());
        assert_eq!(decision.decision, DecisionTier::Deny);
    }

    #[test]
    fn extracts_policy_name_and_description_from_advice() {
        let engine = CedarEngine::from_policy_str(
            r#"
            @name("Audit file writes")
            @description("Permits file edits with audit logging")
            @advice("audit")
            permit(principal, action, resource);
            "#,
        )
        .unwrap();
        let decision = engine.evaluate(&make_request()).unwrap();
        assert_eq!(decision.decision, DecisionTier::Audit);
        assert_eq!(decision.policy_name.as_deref(), Some("Audit file writes"));
        assert_eq!(
            decision.policy_description.as_deref(),
            Some("Permits file edits with audit logging")
        );
    }

    #[test]
    fn policy_name_is_none_without_annotation() {
        let engine =
            CedarEngine::from_policy_str(r#"permit(principal, action, resource);"#).unwrap();
        let decision = engine.evaluate(&make_request()).unwrap();
        assert_eq!(decision.decision, DecisionTier::Allow);
        assert!(decision.policy_name.is_none());
        assert!(decision.policy_description.is_none());
    }

    #[test]
    fn extracts_require_approval_annotations() {
        let engine = CedarEngine::from_policy_str(
            r#"
            @name("Require approval for sensitive ops")
            @description("Human must approve before proceeding")
            @advice("require-approval")
            permit(principal, action, resource);
            "#,
        )
        .unwrap();
        let decision = engine.evaluate(&make_request()).unwrap();
        assert_eq!(decision.decision, DecisionTier::RequireApproval);
        assert_eq!(
            decision.policy_name.as_deref(),
            Some("Require approval for sensitive ops")
        );
        assert!(decision
            .reason
            .contains("Require approval for sensitive ops"));
    }

    #[test]
    fn respects_resource_attributes_in_policy() {
        // Policy that only forbids when is_destructive is true
        let policy = r#"
            permit(principal, action, resource);
            forbid(principal, action, resource) when { resource.is_destructive == true };
        "#;
        let engine = CedarEngine::from_policy_str(policy).unwrap();

        // Request WITH is_destructive = true on resource attributes
        let mut destructive_request = AuthzRequest {
            principal: AgentPrincipal::new("CopilotCLI"),
            action: AuthzAction::new("shell:rm"),
            resource: AuthzResource::file("/"),
            context: AuthzContext {
                tool_name: "powershell".into(),
                working_directory: None,
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            },
        };
        destructive_request.resource.attributes = serde_json::json!({"is_destructive": true});

        let decision = engine.evaluate(&destructive_request).unwrap();
        assert_eq!(
            decision.decision,
            DecisionTier::Deny,
            "destructive command should be denied"
        );

        // Request WITH is_destructive = false
        let mut safe_request = AuthzRequest {
            principal: AgentPrincipal::new("CopilotCLI"),
            action: AuthzAction::new("shell:cargo"),
            resource: AuthzResource::file("/project/build"),
            context: AuthzContext {
                tool_name: "powershell".into(),
                working_directory: None,
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            },
        };
        safe_request.resource.attributes = serde_json::json!({"is_destructive": false});

        let decision = engine.evaluate(&safe_request).unwrap();
        assert!(decision.is_allowed(), "safe command should be allowed");
    }

    #[test]
    fn rejects_malformed_policy_string() {
        let result = CedarEngine::from_policy_str("not valid cedar!!!");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("policy parse error"));
    }

    #[test]
    fn rejects_invalid_schema_string() {
        let policies = vec!["permit(principal, action, resource);".to_string()];
        let result = CedarEngine::from_policy_sources_with_schema(&policies, "not a schema!!!");
        assert!(result.is_err());
    }

    #[test]
    fn handles_non_boolean_resource_attributes() {
        // Attributes with unsupported types (null, arrays) are skipped gracefully
        let engine =
            CedarEngine::from_policy_str(r#"permit(principal, action, resource);"#).unwrap();

        let mut request = make_request();
        request.resource.attributes = serde_json::json!({
            "some_array": [1, 2, 3],
            "some_null": null,
            "valid_string": "hello"
        });
        let decision = engine.evaluate(&request).unwrap();
        assert!(decision.is_allowed());
    }
}
