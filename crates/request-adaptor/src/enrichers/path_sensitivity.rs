use crate::pipeline::{PipelineContext, ResourceEnricher};
use duramen_engine::entities::{AuthzResource, ResourceType};

/// This file maintains lists of sensitive paths and files to flag as `is_protected` for CEDAR policies.
/// Categories include:
/// - Cloud configuration & credentials (.aws, .kube)
/// - Auth tokens and git credentials (.npmrc, .git-credentials)
/// - Shell histories (.bash_history)
/// - Keys and certificates (.pem, id_rsa)
/// - IDE and Secret Managers (.vscode/settings.json, vault-token)
/// - Infrastructure state files (*.tfstate)
const SENSITIVE_PATTERNS: &[&str] = &[".env", "secrets", ".secret", "credentials"];

const KEY_PATTERNS: &[&str] = &[
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".gnupg/",
];

const CLOUD_CONFIG_PATTERNS: &[&str] = &[".aws/", ".azure/", ".gcloud/", ".kube/"];

const AUTH_TOKEN_PATTERNS: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".docker/config.json",
    ".git-credentials",
    ".gitconfig",
    ".vault-token",
    "vault.hcl",
    ".pgpass",
    ".my.cnf",
];

const HISTORY_PATTERNS: &[&str] = &[".bash_history", ".zsh_history", ".node_repl_history"];

const IDE_PATTERNS: &[&str] = &[".vscode/settings.json", ".idea/"];

const CI_PATTERNS: &[&str] = &[
    ".github/workflows/",
    ".github/actions/",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/",
    ".azure-pipelines/",
    "azure-pipelines.yml",
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

const SENSITIVE_EXTENSIONS: &[&str] = &[
    ".tfstate",
    ".tfvars",
    ".jks",
    ".keystore",
    ".kubeconfig",
    "kubeconfig", // Catches files named exactly 'kubeconfig'
    ".crt",
    ".cert",
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

        let contains_sensitive = SENSITIVE_PATTERNS
            .iter()
            .any(|p| path.contains(&p.to_lowercase()))
            || KEY_PATTERNS
                .iter()
                .any(|p| path.contains(&p.to_lowercase()))
            || CLOUD_CONFIG_PATTERNS
                .iter()
                .any(|p| path.contains(&p.to_lowercase()))
            || AUTH_TOKEN_PATTERNS
                .iter()
                .any(|p| path.contains(&p.to_lowercase()))
            || HISTORY_PATTERNS
                .iter()
                .any(|p| path.contains(&p.to_lowercase()))
            || IDE_PATTERNS
                .iter()
                .any(|p| path.contains(&p.to_lowercase()))
            || CI_PATTERNS.iter().any(|p| path.contains(&p.to_lowercase()));

        let ends_with_sensitive = LOCK_FILES.iter().any(|f| path.ends_with(&f.to_lowercase()))
            || SENSITIVE_EXTENSIONS
                .iter()
                .any(|e| path.ends_with(&e.to_lowercase()));

        if contains_sensitive || ends_with_sensitive {
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
            sub_command: "",
            full_command: "",
            binary: "",
            args: &[],
            cwd: None,
            tool_name: "bash",
            is_elevated: false,
        }
    }

    fn assert_is_protected(path: &str) {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::file(path);
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(
            resource.attributes.get("is_protected").unwrap(),
            &serde_json::json!(true),
            "Failed to protect: {}",
            path
        );
    }

    fn assert_not_protected(path: &str) {
        let enricher = PathSensitivityEnricher::new();
        let mut resource = AuthzResource::file(path);
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert!(
            resource.attributes.get("is_protected").is_none(),
            "Incorrectly protected: {}",
            path
        );
    }

    #[test]
    fn marks_env_file_as_protected() {
        assert_is_protected("/project/.env");
    }

    #[test]
    fn marks_ssh_key_as_protected() {
        assert_is_protected("/home/user/.ssh/id_rsa");
        assert_is_protected("/home/user/.gnupg/pubring.kbx");
    }

    #[test]
    fn marks_cloud_config_as_protected() {
        assert_is_protected("/home/user/.aws/credentials");
        assert_is_protected("/home/user/.azure/accessTokens.json");
        assert_is_protected("/home/user/.kube/config");
    }

    #[test]
    fn marks_auth_tokens_as_protected() {
        assert_is_protected("/app/.npmrc");
        assert_is_protected("/home/user/.docker/config.json");
        assert_is_protected("/var/lib/.git-credentials");
        assert_is_protected("/home/user/.vault-token");
    }

    #[test]
    fn marks_history_files_as_protected() {
        assert_is_protected("/home/user/.bash_history");
        assert_is_protected("/home/user/.zsh_history");
    }

    #[test]
    fn marks_ide_secrets_as_protected() {
        assert_is_protected("/project/.vscode/settings.json");
        assert_is_protected("/project/.idea/workspace.xml");
    }

    #[test]
    fn marks_sensitive_extensions_as_protected() {
        assert_is_protected("/infra/prod.tfstate");
        assert_is_protected("/infra/variables.tfvars");
        assert_is_protected("/etc/ssl/certs/server.crt");
        assert_is_protected("/app/security/keystore.jks");
        assert_is_protected("/home/user/mycluster.kubeconfig");
    }

    #[test]
    fn marks_ci_config_as_protected() {
        assert_is_protected("/project/.github/workflows/ci.yml");
    }

    #[test]
    fn marks_lock_file_as_protected() {
        assert_is_protected("/project/Cargo.lock");
    }

    #[test]
    fn skips_normal_files() {
        assert_not_protected("/project/src/main.rs");
        assert_not_protected("/project/README.md");
        assert_not_protected("/app/public/index.html");
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
