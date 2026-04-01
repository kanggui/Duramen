use crate::pipeline::{PipelineContext, ResourceEnricher};
use duramen_engine::entities::{AuthzResource, ResourceType};

const SENSITIVE_PATTERNS: &[&str] = &[
    ".env",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "secrets",
    ".secret",
    "credentials",
];

const LOCK_FILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
    "poetry.lock",
    "go.sum",
];

const CI_PATTERNS: &[&str] = &[
    ".github/workflows/",
    ".github/actions/",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/",
    ".azure-pipelines/",
    "azure-pipelines.yml",
];

#[derive(Default)]
pub struct PathSensitivityEnricher;

impl PathSensitivityEnricher {
    pub fn new() -> Self {
        Self
    }
}

impl ResourceEnricher for PathSensitivityEnricher {
    fn name(&self) -> &str {
        "path-sensitivity"
    }

    fn enrich(&self, resource: &mut AuthzResource, _ctx: &PipelineContext) {
        if resource.resource_type != ResourceType::File {
            return;
        }

        let path = resource.id.to_lowercase();
        let is_sensitive = SENSITIVE_PATTERNS.iter().any(|p| path.contains(p))
            || LOCK_FILES.iter().any(|f| path.ends_with(&f.to_lowercase()))
            || CI_PATTERNS.iter().any(|p| path.contains(&p.to_lowercase()));

        if is_sensitive {
            if let Some(attrs) = resource.attributes.as_object_mut() {
                attrs.insert("is_protected".into(), serde_json::Value::Bool(true));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::PipelineContext;

    fn ctx() -> PipelineContext<'static> {
        PipelineContext {
            sub_command: "", full_command: "", binary: "", args: &[],
            cwd: None, tool_name: "bash", is_elevated: false,
        }
    }

    #[test]
    fn marks_env_file_as_protected() {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::file("/project/.env");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes.get("is_protected").unwrap(), &serde_json::json!(true));
    }

    #[test]
    fn marks_ssh_key_as_protected() {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::file("/home/user/.ssh/id_rsa");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes.get("is_protected").unwrap(), &serde_json::json!(true));
    }

    #[test]
    fn marks_ci_config_as_protected() {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::file("/project/.github/workflows/ci.yml");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes.get("is_protected").unwrap(), &serde_json::json!(true));
    }

    #[test]
    fn marks_lock_file_as_protected() {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::file("/project/Cargo.lock");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes.get("is_protected").unwrap(), &serde_json::json!(true));
    }

    #[test]
    fn skips_normal_files() {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::file("/project/src/main.rs");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert!(resource.attributes.get("is_protected").is_none());
    }

    #[test]
    fn skips_non_file_resources() {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::url("https://example.com/.env");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert!(resource.attributes.get("is_protected").is_none());
    }
}
