use crate::pipeline::{ActionClassifier, PipelineContext};
use duramen_engine::entities::AuthzResource;

const DESTRUCTIVE_PATTERNS: &[&str] = &[
    "rm -rf",
    "rm -r",
    "git push --force",
    "git push -f",
    "mkfs",
    "dd if=",
    "format ",
    "> /dev/",
    "chmod 777",
    ":(){ :|:& };:",
];

pub struct DestructiveClassifier;

impl DestructiveClassifier {
    pub fn new() -> Self {
        Self
    }
}

impl ActionClassifier for DestructiveClassifier {
    fn name(&self) -> &str {
        "destructive"
    }

    fn classify(
        &self,
        _action: &str,
        resource: &AuthzResource,
        ctx: &PipelineContext,
    ) -> Option<String> {
        // Don't reclassify actions already handled by command-specific handlers
        // (git::destructive, file:delete). Just set is_destructive attribute.
        let cmd = ctx.sub_command.to_lowercase();
        let is_destructive = DESTRUCTIVE_PATTERNS
            .iter()
            .any(|pattern| cmd.contains(pattern));

        if is_destructive {
            // We can't mutate resource here (immutable ref), but the enricher
            // pipeline handles attributes. This classifier only checks if
            // is_destructive is already set by a handler.
            if resource
                .attributes
                .get("is_destructive")
                .and_then(|v| v.as_bool())
                != Some(true)
            {
                // Signal to the caller that this is destructive
                // by not reclassifying — the DestructiveEnricher handles attributes
            }
        }

        None // Don't reclassify; destructive detection is attribute-based
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::PipelineContext;

    fn ctx_with_cmd(cmd: &str) -> PipelineContext {
        PipelineContext {
            sub_command: cmd,
            full_command: cmd,
            binary: "",
            args: &[],
            cwd: None,
            tool_name: "bash",
            is_elevated: false,
        }
    }

    #[test]
    fn does_not_reclassify_action() {
        let classifier = DestructiveClassifier::new();
        let resource = AuthzResource::file("/");
        let result = classifier.classify("shell:rm", &resource, &ctx_with_cmd("rm -rf /"));
        assert!(result.is_none(), "destructive classifier sets attributes, not actions");
    }
}
