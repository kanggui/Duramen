use crate::pipeline::{PipelineContext, ResourceEnricher};
use duramen_engine::entities::{AuthzResource, ResourceType};

pub struct FileMetadataEnricher;

impl FileMetadataEnricher {
    pub fn new() -> Self {
        Self
    }
}

impl ResourceEnricher for FileMetadataEnricher {
    fn name(&self) -> &str {
        "file-metadata"
    }

    fn enrich(&self, resource: &mut AuthzResource, _ctx: &PipelineContext) {
        if resource.resource_type != ResourceType::File {
            return;
        }

        let path = &resource.id;

        // Extract extension
        if let Some(ext) = path.rsplit('.').next() {
            if ext != path && !ext.contains('/') && !ext.contains('\\') {
                if let Some(attrs) = resource.attributes.as_object_mut() {
                    if !attrs.contains_key("extension") {
                        attrs.insert(
                            "extension".into(),
                            serde_json::Value::String(ext.to_string()),
                        );
                    }
                }
            }
        }

        // Extract directory
        let dir = if let Some(pos) = path.rfind('/') {
            &path[..pos]
        } else if let Some(pos) = path.rfind('\\') {
            &path[..pos]
        } else {
            ""
        };
        if !dir.is_empty() {
            if let Some(attrs) = resource.attributes.as_object_mut() {
                if !attrs.contains_key("directory") {
                    attrs.insert(
                        "directory".into(),
                        serde_json::Value::String(dir.to_string()),
                    );
                }
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
    fn extracts_extension() {
        let enricher = FileMetadataEnricher::new();
        let mut resource = AuthzResource::file("/src/main.rs");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes["extension"], "rs");
    }

    #[test]
    fn extracts_directory() {
        let enricher = FileMetadataEnricher::new();
        let mut resource = AuthzResource::file("/project/src/lib.rs");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes["directory"], "/project/src");
    }

    #[test]
    fn handles_no_extension() {
        let enricher = FileMetadataEnricher::new();
        let mut resource = AuthzResource::file("/project/Makefile");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        // Makefile has no dot-separated extension
        assert!(resource.attributes.get("extension").is_none());
    }

    #[test]
    fn skips_non_file() {
        let enricher = FileMetadataEnricher::new();
        let mut resource = AuthzResource::command("cargo build");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert!(resource.attributes.get("extension").is_none());
    }
}
