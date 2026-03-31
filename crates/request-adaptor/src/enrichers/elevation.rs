use crate::pipeline::{PipelineContext, ResourceEnricher};
use duramen_engine::entities::AuthzResource;

pub struct ElevationEnricher;

impl ElevationEnricher {
    pub fn new() -> Self {
        Self
    }
}

impl ResourceEnricher for ElevationEnricher {
    fn name(&self) -> &str {
        "elevation"
    }

    fn enrich(&self, resource: &mut AuthzResource, ctx: &PipelineContext) {
        if let Some(attrs) = resource.attributes.as_object_mut() {
            attrs.insert(
                "is_elevated".into(),
                serde_json::Value::Bool(ctx.is_elevated),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::PipelineContext;

    #[test]
    fn sets_elevated_when_sudo() {
        let enricher = ElevationEnricher::new();
        let ctx = PipelineContext {
            sub_command: "cargo build", full_command: "sudo cargo build",
            binary: "cargo", args: &["build"],
            cwd: None, tool_name: "bash", is_elevated: true,
        };
        let mut resource = AuthzResource::file("/project");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx);
        assert_eq!(resource.attributes["is_elevated"], true);
    }

    #[test]
    fn sets_false_when_not_elevated() {
        let enricher = ElevationEnricher::new();
        let ctx = PipelineContext {
            sub_command: "cargo build", full_command: "cargo build",
            binary: "cargo", args: &["build"],
            cwd: None, tool_name: "bash", is_elevated: false,
        };
        let mut resource = AuthzResource::file("/project");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx);
        assert_eq!(resource.attributes["is_elevated"], false);
    }
}
