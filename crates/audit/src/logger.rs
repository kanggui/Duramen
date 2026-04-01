use chrono::Utc;
use duramen_engine::decision::DecisionTier;
use duramen_engine::entities::AuthzRequest;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub request_id: String,
    pub principal: AuditPrincipal,
    pub action: String,
    pub resource: AuditResource,
    pub context: serde_json::Value,
    pub raw_command: serde_json::Value,
    pub decision: DecisionTier,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_description: Option<String>,
    pub evaluation_time_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditPrincipal {
    #[serde(rename = "type")]
    pub principal_type: String,
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditResource {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub path: String,
}

impl AuditEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &AuthzRequest,
        decision: DecisionTier,
        reason: String,
        policy_id: Option<String>,
        policy_name: Option<String>,
        policy_description: Option<String>,
        evaluation_time_ms: u64,
        raw_command: serde_json::Value,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            request_id: Uuid::new_v4().to_string(),
            principal: AuditPrincipal {
                principal_type: "Agent".into(),
                id: request.principal.agent_type.clone(),
            },
            action: request.action.name.clone(),
            resource: AuditResource {
                resource_type: format!("{:?}", request.resource.resource_type),
                path: request.resource.id.clone(),
            },
            context: serde_json::json!({
                "tool": request.context.tool_name,
                "working_dir": request.context.working_directory,
                "file_patterns_affected": request.context.file_patterns_affected,
            }),
            raw_command,
            decision,
            reason,
            policy_id,
            policy_name,
            policy_description,
            evaluation_time_ms,
        }
    }
}

pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    pub fn new(log_path: &Path) -> Result<Self, std::io::Error> {
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            log_path: log_path.to_path_buf(),
        })
    }

    pub fn log(&self, entry: &AuditEntry) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        writeln!(file, "{json}")?;
        Ok(())
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duramen_engine::entities::{
        AgentPrincipal, AuthzAction, AuthzContext, AuthzResource, ResourceType,
    };
    use std::io::BufRead;
    use tempfile::TempDir;

    fn sample_request() -> AuthzRequest {
        AuthzRequest {
            principal: AgentPrincipal {
                agent_type: "copilot".into(),
                trust_level: None,
                session_id: None,
                user: None,
            },
            action: AuthzAction {
                name: "file:read".into(),
            },
            resource: AuthzResource {
                resource_type: ResourceType::File,
                id: "/home/user/test.txt".into(),
                attributes: serde_json::Value::Null,
            },
            context: AuthzContext {
                tool_name: "cat".into(),
                working_directory: Some("/home/user".into()),
                file_patterns_affected: Vec::new(),
                extra: serde_json::Value::Null,
            },
        }
    }

    #[test]
    fn writes_json_line_to_file() {
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&log_file).unwrap();

        let entry = AuditEntry::new(
            &sample_request(),
            DecisionTier::Allow,
            "matched read-only policy".into(),
            Some("policy-read-only".into()),
            Some("Allow read-only".into()),
            Some("Permits file reads".into()),
            5,
            serde_json::json!({"cmd": "cat test.txt"}),
        );
        logger.log(&entry).unwrap();

        let content = std::fs::read_to_string(&log_file).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["decision"], "allow");
        assert_eq!(parsed["principal"]["id"], "copilot");
        assert_eq!(parsed["raw_command"]["cmd"], "cat test.txt");
    }

    #[test]
    fn appends_multiple_entries() {
        let dir = TempDir::new().unwrap();
        let log_file = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&log_file).unwrap();

        for _ in 0..2 {
            let entry = AuditEntry::new(
                &sample_request(),
                DecisionTier::Deny,
                "denied".into(),
                None,
                None,
                None,
                1,
                serde_json::json!(null),
            );
            logger.log(&entry).unwrap();
        }

        let file = std::fs::File::open(&log_file).unwrap();
        let lines: Vec<String> = std::io::BufReader::new(file)
            .lines()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(lines.len(), 2);
    }
}
