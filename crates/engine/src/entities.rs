use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub agent_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl AgentPrincipal {
    pub fn new(agent_type: &str) -> Self {
        Self {
            agent_type: agent_type.to_string(),
            trust_level: None,
            session_id: None,
            user: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzAction {
    pub name: String,
}

impl AuthzAction {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    File,
    Command,
    Url,
    GitRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzResource {
    pub resource_type: ResourceType,
    pub id: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub attributes: serde_json::Value,
}

impl AuthzResource {
    pub fn file(path: &str) -> Self {
        Self {
            resource_type: ResourceType::File,
            id: path.to_string(),
            attributes: serde_json::Value::Null,
        }
    }

    pub fn command(cmd: &str) -> Self {
        Self {
            resource_type: ResourceType::Command,
            id: cmd.to_string(),
            attributes: serde_json::Value::Null,
        }
    }

    pub fn url(url: &str) -> Self {
        Self {
            resource_type: ResourceType::Url,
            id: url.to_string(),
            attributes: serde_json::Value::Null,
        }
    }

    pub fn git_ref(ref_name: &str) -> Self {
        Self {
            resource_type: ResourceType::GitRef,
            id: ref_name.to_string(),
            attributes: serde_json::Value::Null,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzContext {
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_patterns_affected: Vec<String>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzRequest {
    pub principal: AgentPrincipal,
    pub action: AuthzAction,
    pub resource: AuthzResource,
    pub context: AuthzContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawHookPayload {
    #[serde(alias = "toolName")]
    pub tool: String,
    #[serde(default, alias = "toolArgs")]
    pub args: serde_json::Value,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub timestamp: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_principal_creation() {
        let p = AgentPrincipal::new("copilot");
        assert_eq!(p.agent_type, "copilot");
        assert!(p.session_id.is_none());
        assert!(p.user.is_none());
    }

    #[test]
    fn authz_resource_file() {
        let r = AuthzResource::file("/src/main.rs");
        assert_eq!(r.resource_type, ResourceType::File);
        assert_eq!(r.id, "/src/main.rs");
    }

    #[test]
    fn authz_resource_command() {
        let r = AuthzResource::command("rm -rf /");
        assert_eq!(r.resource_type, ResourceType::Command);
        assert_eq!(r.id, "rm -rf /");
    }

    #[test]
    fn authz_request_round_trip_json() {
        let req = AuthzRequest {
            principal: AgentPrincipal::new("copilot"),
            action: AuthzAction::new("file_write"),
            resource: AuthzResource::file("/etc/passwd"),
            context: AuthzContext {
                tool_name: "edit".into(),
                working_directory: Some("/home".into()),
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: AuthzRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.principal.agent_type, "copilot");
        assert_eq!(back.action.name, "file_write");
        assert_eq!(back.resource.id, "/etc/passwd");
        assert_eq!(back.context.tool_name, "edit");
    }

    #[test]
    fn raw_hook_payload_from_json() {
        let json = r#"{"tool":"bash","args":{"command":"ls"}}"#;
        let p: RawHookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.tool, "bash");
        assert_eq!(p.args["command"], "ls");
    }

    #[test]
    fn authz_resource_url() {
        let r = AuthzResource::url("https://example.com");
        assert_eq!(r.resource_type, ResourceType::Url);
        assert_eq!(r.id, "https://example.com");
    }

    #[test]
    fn authz_resource_git_ref() {
        let r = AuthzResource::git_ref("main");
        assert_eq!(r.resource_type, ResourceType::GitRef);
        assert_eq!(r.id, "main");
    }

    #[test]
    fn raw_hook_payload_aliases() {
        let json = r#"{"toolName":"edit","toolArgs":"{\"path\":\"/test.rs\"}"}"#;
        let p: RawHookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.tool, "edit");
        assert!(p.args.is_string());
    }

    #[test]
    fn raw_hook_payload_missing_optional_fields() {
        let json = r#"{"tool":"bash","args":{}}"#;
        let p: RawHookPayload = serde_json::from_str(json).unwrap();
        assert_eq!(p.tool, "bash");
        assert!(p.cwd.is_none());
        assert!(p.timestamp.is_none());
    }
}