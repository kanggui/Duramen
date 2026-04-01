use duramen_audit::logger::{AuditEntry, AuditLogger};
use duramen_engine::adapter::PolicyEngine;
use duramen_engine::decision::{AuthzDecision, DecisionTier};
use duramen_engine::entities::*;
use duramen_engine::evaluator::CedarEngine;
use duramen_engine::policy::PolicyLoader;
use duramen_request_adaptor::get_normalizer;
use duramen_response_formatter::get_formatter;
use std::path::PathBuf;

/// Decision tier priority for aggregation (higher = stricter).
fn decision_priority(tier: DecisionTier) -> u8 {
    match tier {
        DecisionTier::Allow => 0,
        DecisionTier::Audit => 1,
        DecisionTier::RequireApproval => 2,
        DecisionTier::Deny => 3,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    agent: Option<String>,
    principal: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    resource_type: String,
    context: Option<String>,
    policy_dir: Option<String>,
    audit_log: Option<String>,
) -> i32 {
    // Build the AuthzRequest(s)
    let (requests, agent_name, raw_payload) = if let Some(ref agent_name) = agent {
        if principal.is_some() || action.is_some() || resource.is_some() {
            // When --agent is provided, use normalizer path; ignore explicit args
        }
        // Read raw payload from stdin
        let raw_input = match std::io::read_to_string(std::io::stdin()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(r#"{{"error":"failed to read stdin: {}"}}"#, e);
                return 3;
            }
        };
        let payload: RawHookPayload = match serde_json::from_str(&raw_input) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(r#"{{"error":"invalid JSON input: {}"}}"#, e);
                return 3;
            }
        };
        let normalizer = match get_normalizer(agent_name) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(r#"{{"error":"normalizer error: {}"}}"#, e);
                return 3;
            }
        };
        let raw_json: serde_json::Value = serde_json::from_str(&raw_input).unwrap_or_default();
        let reqs = match normalizer.normalize(&payload) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(r#"{{"error":"normalization error: {}"}}"#, e);
                return 3;
            }
        };
        (reqs, agent_name.clone(), raw_json)
    } else {
        // Explicit args mode — always a single request
        let principal_str = match principal {
            Some(p) => p,
            None => {
                eprintln!(r#"{{"error":"--principal is required when --agent is not set"}}"#);
                return 3;
            }
        };
        let action_str = match action {
            Some(a) => a,
            None => {
                eprintln!(r#"{{"error":"--action is required when --agent is not set"}}"#);
                return 3;
            }
        };
        let resource_str = match resource {
            Some(r) => r,
            None => {
                eprintln!(r#"{{"error":"--resource is required when --agent is not set"}}"#);
                return 3;
            }
        };

        let res = match resource_type.as_str() {
            "file" => AuthzResource::file(&resource_str),
            "command" => AuthzResource::command(&resource_str),
            "url" => AuthzResource::url(&resource_str),
            "gitref" => AuthzResource::git_ref(&resource_str),
            other => {
                eprintln!(r#"{{"error":"unknown resource type: {}"}}"#, other);
                return 3;
            }
        };

        let ctx = if let Some(ref ctx_json) = context {
            match serde_json::from_str::<serde_json::Value>(ctx_json) {
                Ok(extra) => AuthzContext {
                    tool_name: action_str.clone(),
                    working_directory: None,
                    file_patterns_affected: Vec::new(),
                    extra,
                },
                Err(e) => {
                    eprintln!(r#"{{"error":"invalid context JSON: {}"}}"#, e);
                    return 3;
                }
            }
        } else {
            AuthzContext {
                tool_name: action_str.clone(),
                working_directory: None,
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            }
        };

        let req = AuthzRequest {
            principal: AgentPrincipal::new(&principal_str),
            action: AuthzAction::new(&action_str),
            resource: res,
            context: ctx,
        };
        (vec![req], "generic".to_string(), serde_json::Value::Null)
    };

    // Resolve policy directory
    let repo_policy_dir = policy_dir
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".authz"));
    let user_policy_dir = dirs_next::config_dir().map(|d| d.join("duramen").join("policies"));

    let repo_dir_opt = if repo_policy_dir.exists() {
        Some(repo_policy_dir.as_path())
    } else {
        None
    };
    let user_dir_opt = user_policy_dir
        .as_ref()
        .filter(|d| d.exists())
        .map(|d| d.as_path());

    let defaults = duramen_policy_defaults::all_default_policies();
    let default_refs: Vec<&str> = defaults.to_vec();

    let loader = PolicyLoader::new();
    let policy_set = match loader.load_merged(repo_dir_opt, user_dir_opt, &default_refs) {
        Ok(ps) => ps,
        Err(e) => {
            eprintln!(r#"{{"error":"failed to load policies: {}"}}"#, e);
            return 3;
        }
    };

    let engine = CedarEngine::from_policy_set(policy_set);

    // Evaluate each sub-request, track worst decision, log all non-Allow
    let log_path = audit_log.as_deref().map(PathBuf::from).unwrap_or_else(|| {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".duramen")
            .join("audit.log")
    });

    let mut worst_decision: Option<AuthzDecision> = None;
    let mut worst_request: Option<&AuthzRequest> = None;

    for request in &requests {
        let decision = match engine.evaluate(request) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(r#"{{"error":"evaluation error: {}"}}"#, e);
                return 3;
            }
        };

        // Log every non-Allow decision
        if !matches!(decision.decision, DecisionTier::Allow) {
            if let Some(parent) = log_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let entry = AuditEntry::new(
                request,
                decision.decision,
                decision.reason.clone(),
                decision.policy_id.clone(),
                decision.policy_name.clone(),
                decision.policy_description.clone(),
                decision.evaluation_time_ms,
                raw_payload.clone(),
            );
            if let Ok(logger) = AuditLogger::new(&log_path) {
                let _ = logger.log(&entry);
            }
        }

        // Track the strictest decision
        let dominated = match &worst_decision {
            None => true,
            Some(current) => {
                decision_priority(decision.decision) > decision_priority(current.decision)
            }
        };
        if dominated {
            worst_decision = Some(decision.clone());
            worst_request = Some(request);
        }

        // Short-circuit on Deny — nothing is worse
        if decision.decision == DecisionTier::Deny {
            break;
        }
    }

    let decision = worst_decision.unwrap_or_else(|| {
        AuthzDecision::new(DecisionTier::Allow, "no requests to evaluate".into())
    });
    let response_request = worst_request.unwrap_or(&requests[0]);

    // Format and output
    let formatter = match get_formatter(&agent_name) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(r#"{{"error":"formatter error: {e}"}}"#);
            return 3;
        }
    };
    let response = formatter.format(&decision, response_request);
    print!("{}", response.stdout);
    response.exit_code
}
