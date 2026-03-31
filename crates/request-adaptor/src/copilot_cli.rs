use crate::commands::{self, default::DefaultCommandHandler, CommandHandler};
use crate::classifiers::{destructive::DestructiveClassifier, package_install::PackageInstallClassifier};
use crate::enrichers::{
    elevation::ElevationEnricher, file_metadata::FileMetadataEnricher,
    network_domain::NetworkDomainEnricher, path_sensitivity::PathSensitivityEnricher,
};
use crate::pipeline::{EnrichmentPipeline, PipelineContext};
use crate::traits::{AgentNormalizer, NormalizerError};
use duramen_engine::entities::{
    AgentPrincipal, AuthzAction, AuthzContext, AuthzRequest, AuthzResource, RawHookPayload,
};

pub struct CopilotCliNormalizer;

fn default_pipeline() -> EnrichmentPipeline {
    let mut p = EnrichmentPipeline::new();
    p.add_enricher(Box::new(PathSensitivityEnricher::new()));
    p.add_enricher(Box::new(FileMetadataEnricher::new()));
    p.add_enricher(Box::new(NetworkDomainEnricher::new()));
    p.add_enricher(Box::new(ElevationEnricher::new()));
    p.add_classifier(Box::new(DestructiveClassifier::new()));
    p.add_classifier(Box::new(PackageInstallClassifier::new()));
    p
}

/// If args is a JSON string (Copilot CLI sends toolArgs as a string), parse it.
/// If args is already an object, use it directly.
fn resolve_args(args: &serde_json::Value) -> serde_json::Value {
    match args {
        serde_json::Value::String(s) => {
            serde_json::from_str(s).unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
        }
        other => other.clone(),
    }
}

const DESTRUCTIVE_PATTERNS: &[&str] = &[
    "rm -rf",
    "rm -r",
    "sudo ",
    "git push --force",
    "git push -f",
    "mkfs",
    "dd if=",
    "format ",
    "> /dev/",
    "chmod 777",
    ":(){ :|:& };:",
];

fn is_destructive(command: &str) -> bool {
    let lower = command.to_lowercase();
    DESTRUCTIVE_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Prefixes that modify execution context but aren't the actual command.
const COMMAND_PREFIXES: &[&str] = &["sudo", "env", "nohup", "nice", "time"];

/// Parse a shell command string into (action, resource, is_elevated).
/// Strips prefixes like `sudo`, `env`. Delegates to command-specific
/// handlers via the registry, falling back to DefaultCommandHandler.
fn parse_shell_command(command: &str, cwd: Option<&str>) -> (String, AuthzResource, bool) {
    parse_single_command(command, cwd)
}

fn parse_single_command(command: &str, cwd: Option<&str>) -> (String, AuthzResource, bool) {
    let parts: Vec<&str> = command.split_whitespace().collect();

    // Strip command prefixes (sudo, env, nohup, etc.)
    let mut is_elevated = false;
    let mut cmd_parts = &parts[..];
    while let Some(&first) = cmd_parts.first() {
        if COMMAND_PREFIXES.contains(&first.to_lowercase().as_str()) {
            if first.eq_ignore_ascii_case("sudo") {
                is_elevated = true;
            }
            cmd_parts = &cmd_parts[1..];
        } else if first.contains('=') && !first.starts_with('-') {
            // Skip environment variable assignments (KEY=VALUE)
            cmd_parts = &cmd_parts[1..];
            continue;
        } else {
            break;
        }
    }

    let binary = cmd_parts.first().copied().unwrap_or("unknown");
    let args = if cmd_parts.len() > 1 { &cmd_parts[1..] } else { &[] };

    // Look up special handler, fall back to default
    let result = if let Some(handler) = commands::get_command_handler(binary) {
        handler.parse(args, cwd)
    } else {
        let mut result = DefaultCommandHandler.parse(args, cwd);
        result.action = format!("shell:{}", binary);
        result
    };

    (result.action, result.resource, is_elevated)
}

fn map_tool(tool: &str) -> (&str, &str) {
    match tool {
        "view" => ("file:read", "file"),
        "edit" => ("file:edit", "file"),
        "create" => ("file:create", "file"),
        "grep" => ("file:read", "file"),
        "glob" => ("directory:list", "file"),
        "web_fetch" => ("network:fetch", "url"),
        _ => ("tool:unknown", "unknown"),
    }
}

fn extract_resource(args: &serde_json::Value, resource_kind: &str) -> AuthzResource {
    match resource_kind {
        "file" => {
            let path = args
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            AuthzResource::file(path)
        }
        "url" => {
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            AuthzResource::url(url)
        }
        _ => AuthzResource::command("unknown"),
    }
}

/// Split a command string on shell operators (`&&`, `||`, `;`).
fn split_chained_commands(command: &str) -> Vec<&str> {
    let mut commands = Vec::new();
    let mut start = 0;
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'&' {
            commands.push(command[start..i].trim());
            i += 2;
            start = i;
        } else if bytes[i] == b'|' && i + 1 < bytes.len() && bytes[i + 1] == b'|' {
            commands.push(command[start..i].trim());
            i += 2;
            start = i;
        } else if bytes[i] == b';' {
            commands.push(command[start..i].trim());
            i += 1;
            start = i;
        } else {
            i += 1;
        }
    }
    let last = command[start..].trim();
    if !last.is_empty() {
        commands.push(last);
    }
    commands.into_iter().filter(|s| !s.is_empty()).collect()
}

impl AgentNormalizer for CopilotCliNormalizer {
    fn normalize(&self, raw_input: &RawHookPayload) -> Result<Vec<AuthzRequest>, NormalizerError> {
        let args = resolve_args(&raw_input.args);
        let cwd = raw_input.cwd.as_deref();

        let working_directory = raw_input
            .cwd
            .clone()
            .or_else(|| {
                args.get("working_directory")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        if raw_input.tool == "powershell" || raw_input.tool == "bash" {
            let command = args
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let sub_commands = split_chained_commands(command);
            let mut requests = Vec::with_capacity(sub_commands.len());

            for sub_cmd in &sub_commands {
                let request = self.normalize_shell_command(
                    sub_cmd,
                    command,
                    cwd,
                    &raw_input.tool,
                    &working_directory,
                );
                requests.push(request);
            }

            Ok(requests)
        } else {
            let (action_name, resource_kind) = map_tool(&raw_input.tool);
            let mut res = extract_resource(&args, resource_kind);
            if resource_kind == "file" {
                res.attributes = serde_json::json!({"is_protected": false});
            }

            let file_patterns_affected =
                if res.resource_type == duramen_engine::entities::ResourceType::File {
                    vec![res.id.clone()]
                } else {
                    Vec::new()
                };

            Ok(vec![AuthzRequest {
                principal: AgentPrincipal::new("CopilotCLI"),
                action: AuthzAction::new(action_name),
                resource: res,
                context: AuthzContext {
                    tool_name: raw_input.tool.clone(),
                    working_directory,
                    file_patterns_affected,
                    extra: serde_json::Value::Null,
                },
            }])
        }
    }

    fn agent_type(&self) -> &str {
        "copilot-cli"
    }
}

impl CopilotCliNormalizer {
    fn normalize_shell_command(
        &self,
        sub_cmd: &str,
        full_command: &str,
        cwd: Option<&str>,
        tool: &str,
        working_directory: &Option<String>,
    ) -> AuthzRequest {
        let (action, mut res, is_elevated) = parse_shell_command(sub_cmd, cwd);

        // Ensure resource attributes are an object for enrichers
        if res.attributes.is_null() {
            res.attributes = serde_json::json!({});
        }

        // Extract binary and args for pipeline context
        let parts: Vec<&str> = sub_cmd.split_whitespace().collect();
        let mut cmd_parts = &parts[..];
        while let Some(&first) = cmd_parts.first() {
            if COMMAND_PREFIXES.contains(&first.to_lowercase().as_str())
                || (first.contains('=') && !first.starts_with('-'))
            {
                cmd_parts = &cmd_parts[1..];
            } else {
                break;
            }
        }
        let binary = cmd_parts.first().copied().unwrap_or("unknown");
        let args: Vec<&str> = if cmd_parts.len() > 1 {
            cmd_parts[1..].to_vec()
        } else {
            Vec::new()
        };

        // Run enrichment pipeline
        let pipeline = default_pipeline();
        let ctx = PipelineContext {
            sub_command: sub_cmd,
            full_command,
            binary,
            args: &args,
            cwd,
            tool_name: tool,
            is_elevated,
        };
        let final_action = pipeline.process(&action, &mut res, &ctx);

        // For non-handler actions (generic shell commands), set is_destructive if not already set
        if !final_action.starts_with("git::") && final_action != "file:delete" {
            if res.attributes.get("is_destructive").is_none() {
                if let Some(attrs) = res.attributes.as_object_mut() {
                    attrs.insert(
                        "is_destructive".into(),
                        serde_json::Value::Bool(
                            is_destructive(full_command) || is_destructive(sub_cmd),
                        ),
                    );
                }
            }
        }

        let file_patterns_affected =
            if res.resource_type == duramen_engine::entities::ResourceType::File {
                vec![res.id.clone()]
            } else {
                Vec::new()
            };

        AuthzRequest {
            principal: AgentPrincipal::new("CopilotCLI"),
            action: AuthzAction::new(&final_action),
            resource: res,
            context: AuthzContext {
                tool_name: tool.to_string(),
                working_directory: working_directory.clone(),
                file_patterns_affected,
                extra: serde_json::Value::Null,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duramen_engine::entities::ResourceType;
    use serde_json::json;

    #[test]
    fn normalizes_file_edit() {
        let payload = RawHookPayload {
            tool: "edit".to_string(),
            args: json!({ "path": "/home/user/project/main.rs" }),
            cwd: None,
            timestamp: None,
        };

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "file:edit");
        assert_eq!(req.resource.id, "/home/user/project/main.rs");
        assert_eq!(req.principal.agent_type, "CopilotCLI");
        assert_eq!(req.context.tool_name, "edit");
        assert_eq!(req.resource.attributes.get("is_protected").unwrap(), &json!(false));
    }

    #[test]
    fn normalizes_shell_command() {
        let payload = RawHookPayload {
            tool: "powershell".to_string(),
            args: json!({ "command": "cargo build" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "shell:cargo");
        assert_eq!(req.resource.resource_type, ResourceType::File);
        assert_eq!(req.resource.id, "/project/build");
        assert_eq!(
            req.resource.attributes.get("is_destructive").unwrap(),
            &json!(false)
        );
        assert_eq!(
            req.resource.attributes.get("is_elevated").unwrap(),
            &json!(false)
        );
    }

    #[test]
    fn detects_destructive_command() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "sudo rm -rf /" }),
            cwd: None,
            timestamp: None,
        };

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "file:delete");
        assert_eq!(req.resource.resource_type, ResourceType::File);
        assert_eq!(req.resource.id, "/");
        assert_eq!(
            req.resource.attributes.get("is_destructive").unwrap(),
            &json!(true)
        );
    }

    #[test]
    fn parses_rm_command_with_target() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "rm -rf dist" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "file:delete");
        assert_eq!(req.resource.resource_type, ResourceType::File);
        assert_eq!(req.resource.id, "/project/dist");
        assert_eq!(
            req.resource.attributes.get("is_destructive").unwrap(),
            &json!(true)
        );
    }

    #[test]
    fn parses_git_status_as_read() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git status" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::read");
        assert_eq!(req.resource.resource_type, ResourceType::GitRef);
        assert_eq!(req.resource.id, "HEAD");
    }

    #[test]
    fn parses_git_log_as_read() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git log --oneline -10" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::read");
        assert_eq!(req.resource.resource_type, ResourceType::GitRef);
    }

    #[test]
    fn parses_git_commit_as_write() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git commit -m \"fix bug\"" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::write");
        assert_eq!(req.resource.resource_type, ResourceType::GitRef);
    }

    #[test]
    fn parses_git_push_as_network() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git push origin main" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::network");
        assert_eq!(req.resource.resource_type, ResourceType::GitRef);
        assert_eq!(req.resource.id, "main");
        assert_eq!(req.resource.attributes.get("remote").unwrap(), &json!("origin"));
        assert_eq!(req.resource.attributes.get("is_destructive").unwrap(), &json!(false));
    }

    #[test]
    fn parses_git_force_push_as_destructive() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git push --force origin main" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::destructive");
        assert_eq!(req.resource.id, "main");
        assert_eq!(req.resource.attributes.get("is_destructive").unwrap(), &json!(true));
        assert_eq!(req.resource.attributes.get("remote").unwrap(), &json!("origin"));
    }

    #[test]
    fn parses_git_reset_hard_as_destructive() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git reset --hard HEAD~3" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::destructive");
        assert_eq!(req.resource.id, "HEAD~3");
        assert_eq!(req.resource.attributes.get("is_destructive").unwrap(), &json!(true));
    }

    #[test]
    fn parses_git_branch_delete_as_destructive() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git branch -D old-feature" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::destructive");
        assert_eq!(req.resource.id, "old-feature");
    }

    #[test]
    fn parses_sudo_git_push_as_elevated() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "sudo git push origin main" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::network");
        assert_eq!(req.resource.attributes.get("is_elevated").unwrap(), &json!(true));
    }

    #[test]
    fn parses_git_checkout_branch() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git checkout feature-branch" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::write");
        assert_eq!(req.resource.id, "feature-branch");
    }

    #[test]
    fn parses_git_fetch_as_network() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git fetch origin" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::network");
        assert_eq!(req.resource.attributes.get("remote").unwrap(), &json!("origin"));
    }

    #[test]
    fn parses_git_branch_list_as_read() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git branch" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::read");
    }

    #[test]
    fn parses_curl_as_url_resource() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "curl https://example.com" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "shell:curl");
        assert_eq!(req.resource.resource_type, ResourceType::Url);
        assert_eq!(req.resource.id, "https://example.com");
        assert_eq!(
            req.resource.attributes.get("is_destructive").unwrap(),
            &json!(false)
        );
    }

    #[test]
    fn normalizes_web_fetch() {
        let payload = RawHookPayload {
            tool: "web_fetch".to_string(),
            args: json!({ "url": "https://example.com/api" }),
            cwd: None,
            timestamp: None,
        };

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "network:fetch");
        assert_eq!(req.resource.id, "https://example.com/api");
        assert_eq!(req.context.tool_name, "web_fetch");
    }

    #[test]
    fn normalizes_real_copilot_cli_format() {
        // This is the ACTUAL format Copilot CLI sends
        let json_str = r#"{"timestamp":1704614600000,"cwd":"/path/to/project","toolName":"bash","toolArgs":"{\"command\":\"cargo test\",\"description\":\"Run tests\"}"}"#;
        let payload: RawHookPayload = serde_json::from_str(json_str).unwrap();

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "shell:cargo");
        assert_eq!(req.resource.resource_type, ResourceType::File);
        assert_eq!(req.context.working_directory, Some("/path/to/project".to_string()));
    }

    #[test]
    fn normalizes_real_copilot_cli_destructive() {
        let json_str = r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"bash","toolArgs":"{\"command\":\"sudo rm -rf /\"}"}"#;
        let payload: RawHookPayload = serde_json::from_str(json_str).unwrap();

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "file:delete");
        assert_eq!(req.resource.resource_type, ResourceType::File);
        assert_eq!(req.resource.id, "/");
        assert_eq!(req.resource.attributes.get("is_destructive").unwrap(), &json!(true));
        assert_eq!(req.resource.attributes.get("is_elevated").unwrap(), &json!(true));
    }

    #[test]
    fn normalizes_real_copilot_cli_file_edit() {
        let json_str = r#"{"timestamp":1704614600000,"cwd":"/project","toolName":"edit","toolArgs":"{\"path\":\"/src/main.rs\",\"old_str\":\"foo\",\"new_str\":\"bar\"}"}"#;
        let payload: RawHookPayload = serde_json::from_str(json_str).unwrap();

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "file:edit");
        assert_eq!(req.resource.id, "/src/main.rs");
        assert_eq!(req.resource.attributes.get("is_protected").unwrap(), &json!(false));
    }

    #[test]
    fn shell_command_no_args_uses_cwd() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "ls" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };

        let normalizer = CopilotCliNormalizer;
        let reqs = normalizer.normalize(&payload).unwrap();
        let req = &reqs[0];

        assert_eq!(req.action.name, "shell:ls");
        assert_eq!(req.resource.resource_type, ResourceType::File);
        assert_eq!(req.resource.id, "/project");
    }

    #[test]
    fn handles_empty_command_string() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        // Empty command should not panic
        if !reqs.is_empty() {
            let req = &reqs[0];
            assert!(req.action.name.starts_with("shell:"));
        }
    }

    #[test]
    fn strips_env_prefix() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "env cargo test" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "shell:cargo");
    }

    #[test]
    fn strips_nohup_prefix() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "nohup cargo build" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "shell:cargo");
    }

    #[test]
    fn detects_mkfs_as_destructive() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "mkfs.ext4 /dev/sda1" }),
            cwd: None,
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.resource.attributes.get("is_destructive").unwrap(), &json!(true));
    }

    #[test]
    fn detects_dd_as_destructive() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "dd if=/dev/zero of=/dev/sda" }),
            cwd: None,
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.resource.attributes.get("is_destructive").unwrap(), &json!(true));
    }

    #[test]
    fn parses_git_pull_as_network() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git pull origin main" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::network");
        assert_eq!(req.resource.resource_type, ResourceType::GitRef);
    }

    #[test]
    fn parses_git_add_as_write() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git add ." }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::write");
    }

    #[test]
    fn parses_git_merge_as_write() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git merge feature-branch" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::write");
    }

    #[test]
    fn parses_git_rebase_as_write() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git rebase main" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::write");
    }

    #[test]
    fn parses_git_stash_as_write() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git stash" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::write");
    }

    #[test]
    fn parses_git_clone_as_network() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git clone https://github.com/repo.git" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::network");
    }

    #[test]
    fn parses_git_clean_f_as_destructive() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git clean -fd" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::destructive");
    }

    #[test]
    fn parses_git_tag_as_read() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git tag" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "git::read");
    }

    #[test]
    fn unknown_tool_maps_to_tool_unknown() {
        let payload = RawHookPayload {
            tool: "some_new_tool".to_string(),
            args: json!({ "path": "/file.txt" }),
            cwd: None,
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.action.name, "tool:unknown");
    }

    #[test]
    fn file_patterns_affected_populated_for_file_tool() {
        let payload = RawHookPayload {
            tool: "edit".to_string(),
            args: json!({ "path": "/src/main.rs" }),
            cwd: None,
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        let req = &reqs[0];
        assert_eq!(req.context.file_patterns_affected, vec!["/src/main.rs"]);
    }

    #[test]
    fn invalid_tool_args_string_handled() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: serde_json::Value::String("not valid json{{{".to_string()),
            cwd: None,
            timestamp: None,
        };
        // Should not panic; args resolution falls back to empty object
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        if !reqs.is_empty() {
            let req = &reqs[0];
            assert!(req.action.name.starts_with("shell:"));
        }
    }

    // ── Chained command tests ──

    #[test]
    fn chained_command_detects_destructive_in_chain() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git log --oneline -5 && git reset --hard HEAD~2" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].action.name, "git::read");
        assert_eq!(reqs[1].action.name, "git::destructive",
            "chained command with destructive sub-command should be classified as destructive");
    }

    #[test]
    fn chained_command_safe_commands_stay_safe() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git status && git log --oneline -5" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].action.name, "git::read");
        assert_eq!(reqs[1].action.name, "git::read");
    }

    #[test]
    fn chained_command_semicolon_separator() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "echo hello; rm -rf /" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].resource.attributes.get("is_destructive").unwrap(), &json!(true));
    }

    #[test]
    fn chained_command_or_separator() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "cargo build || git push --force origin main" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].action.name, "git::destructive");
    }

    #[test]
    fn chained_command_three_parts_picks_worst() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "echo start && git push --force origin main && echo done" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 3);
        assert_eq!(reqs[1].action.name, "git::destructive");
    }

    #[test]
    fn chained_command_single_command_unchanged() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "cargo test" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].action.name, "shell:cargo");
    }

    #[test]
    fn chained_command_real_copilot_pattern() {
        // Real pattern: Copilot CLI chains log + destructive + log
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "git --no-pager log --oneline -5 && echo \"---\" && git reset --hard HEAD~2 && echo \"---\" && git --no-pager log --oneline -5" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 5);
        assert_eq!(reqs[2].action.name, "git::destructive",
            "real Copilot pattern hiding destructive in chain should be caught");
    }

    #[test]
    fn normalizes_glob_tool() {
        let payload = RawHookPayload {
            tool: "glob".to_string(),
            args: json!({ "path": "/src" }),
            cwd: None,
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs[0].action.name, "directory:list");
    }

    #[test]
    fn strips_time_prefix() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "time cargo build" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs[0].action.name, "shell:cargo");
    }

    #[test]
    fn strips_nice_prefix() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "nice cargo test" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs[0].action.name, "shell:cargo");
    }

    #[test]
    fn chained_command_returns_correct_count() {
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "echo a && echo b && echo c" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 3, "should produce 3 AuthzRequests for 3 sub-commands");
    }

    #[test]
    fn pipe_operator_not_split() {
        // Pipes should NOT be split — they're a single command pipeline
        let payload = RawHookPayload {
            tool: "bash".to_string(),
            args: json!({ "command": "cat file.txt | grep pattern" }),
            cwd: Some("/project".to_string()),
            timestamp: None,
        };
        let reqs = CopilotCliNormalizer.normalize(&payload).unwrap();
        assert_eq!(reqs.len(), 1, "pipe should not split into multiple requests");
    }
}
