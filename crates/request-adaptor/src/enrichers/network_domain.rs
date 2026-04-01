use crate::pipeline::{PipelineContext, ResourceEnricher};
use duramen_engine::entities::{AuthzResource, ResourceType};

#[derive(Default)]
pub struct NetworkDomainEnricher;

impl NetworkDomainEnricher {
    pub fn new() -> Self {
        Self
    }
}

impl ResourceEnricher for NetworkDomainEnricher {
    fn name(&self) -> &str {
        "network-domain"
    }

    fn enrich(&self, resource: &mut AuthzResource, _ctx: &PipelineContext) {
        if resource.resource_type != ResourceType::Url {
            return;
        }

        if let Some(domain) = extract_domain(&resource.id) {
            if let Some(attrs) = resource.attributes.as_object_mut() {
                if !attrs.contains_key("domain") {
                    attrs.insert(
                        "domain".into(),
                        serde_json::Value::String(domain),
                    );
                }
            }
        }
    }
}

fn extract_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = without_scheme.split('/').next()?;
    let domain = host.split(':').next()?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
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
    fn extracts_domain_from_url() {
        let enricher = NetworkDomainEnricher::new();
        let mut resource = AuthzResource::url("https://api.example.com/v1/data");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes["domain"], "api.example.com");
    }

    #[test]
    fn extracts_domain_with_port() {
        let enricher = NetworkDomainEnricher::new();
        let mut resource = AuthzResource::url("http://localhost:8080/api");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert_eq!(resource.attributes["domain"], "localhost");
    }

    #[test]
    fn skips_non_url_resources() {
        let enricher = NetworkDomainEnricher::new();
        let mut resource = AuthzResource::file("/src/main.rs");
        resource.attributes = serde_json::json!({});
        enricher.enrich(&mut resource, &ctx());
        assert!(resource.attributes.get("domain").is_none());
    }
}
