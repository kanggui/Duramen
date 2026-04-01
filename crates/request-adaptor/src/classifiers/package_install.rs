use crate::pipeline::{ActionClassifier, PipelineContext};
use duramen_engine::entities::AuthzResource;

const PACKAGE_MANAGERS: &[(&str, &[&str])] = &[
    ("apt", &["install"]),
    ("apt-get", &["install"]),
    ("pip", &["install"]),
    ("pip3", &["install"]),
    ("npm", &["install"]),
    ("yarn", &["add", "global"]),
    ("pnpm", &["add"]),
    ("cargo", &["install"]),
    ("brew", &["install"]),
    ("gem", &["install"]),
    ("go", &["install"]),
];

#[derive(Default)]
pub struct PackageInstallClassifier;

impl PackageInstallClassifier {
    pub fn new() -> Self {
        Self
    }
}

impl ActionClassifier for PackageInstallClassifier {
    fn name(&self) -> &str {
        "package-install"
    }

    fn classify(
        &self,
        action: &str,
        _resource: &AuthzResource,
        ctx: &PipelineContext,
    ) -> Option<String> {
        // Only reclassify generic shell commands
        if !action.starts_with("shell:") {
            return None;
        }

        for (manager, subcommands) in PACKAGE_MANAGERS {
            if ctx.binary == *manager {
                if let Some(first_arg) = ctx.args.first() {
                    if subcommands.contains(first_arg) {
                        return Some("package:install".to_string());
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::PipelineContext;

    fn ctx_for<'a>(binary: &'a str, args: &'a [&'a str]) -> PipelineContext<'a> {
        PipelineContext {
            sub_command: "",
            full_command: "",
            binary,
            args,
            cwd: None,
            tool_name: "bash",
            is_elevated: false,
        }
    }

    #[test]
    fn detects_pip_install() {
        let classifier = PackageInstallClassifier::new();
        let resource = AuthzResource::command("pip");
        let result = classifier.classify(
            "shell:pip",
            &resource,
            &ctx_for("pip", &["install", "requests"]),
        );
        assert_eq!(result, Some("package:install".to_string()));
    }

    #[test]
    fn detects_npm_install() {
        let classifier = PackageInstallClassifier::new();
        let resource = AuthzResource::command("npm");
        let result = classifier.classify(
            "shell:npm",
            &resource,
            &ctx_for("npm", &["install", "express"]),
        );
        assert_eq!(result, Some("package:install".to_string()));
    }

    #[test]
    fn detects_cargo_install() {
        let classifier = PackageInstallClassifier::new();
        let resource = AuthzResource::command("cargo");
        let result = classifier.classify(
            "shell:cargo",
            &resource,
            &ctx_for("cargo", &["install", "ripgrep"]),
        );
        assert_eq!(result, Some("package:install".to_string()));
    }

    #[test]
    fn ignores_cargo_build() {
        let classifier = PackageInstallClassifier::new();
        let resource = AuthzResource::command("cargo");
        let result = classifier.classify(
            "shell:cargo",
            &resource,
            &ctx_for("cargo", &["build", "--release"]),
        );
        assert!(result.is_none());
    }

    #[test]
    fn ignores_non_shell_actions() {
        let classifier = PackageInstallClassifier::new();
        let resource = AuthzResource::file("/test");
        let result = classifier.classify(
            "file:edit",
            &resource,
            &ctx_for("pip", &["install", "requests"]),
        );
        assert!(result.is_none());
    }
}
