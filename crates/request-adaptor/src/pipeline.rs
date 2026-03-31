use duramen_engine::entities::AuthzResource;

/// Context available to all pipeline stages.
pub struct PipelineContext<'a> {
    pub sub_command: &'a str,
    pub full_command: &'a str,
    pub binary: &'a str,
    pub args: &'a [&'a str],
    pub cwd: Option<&'a str>,
    pub tool_name: &'a str,
    pub is_elevated: bool,
}

/// Stage 2: Enriches resource attributes after command parsing.
pub trait ResourceEnricher: Send + Sync {
    fn name(&self) -> &str;
    fn enrich(&self, resource: &mut AuthzResource, ctx: &PipelineContext);
}

/// Stage 3: May reclassify the action based on deeper analysis.
/// Returns Some(new_action) to reclassify, None to keep current.
pub trait ActionClassifier: Send + Sync {
    fn name(&self) -> &str;
    fn classify(
        &self,
        action: &str,
        resource: &AuthzResource,
        ctx: &PipelineContext,
    ) -> Option<String>;
}

/// Runs enrichers then classifiers in registration order.
pub struct EnrichmentPipeline {
    enrichers: Vec<Box<dyn ResourceEnricher>>,
    classifiers: Vec<Box<dyn ActionClassifier>>,
}

impl EnrichmentPipeline {
    pub fn new() -> Self {
        Self {
            enrichers: Vec::new(),
            classifiers: Vec::new(),
        }
    }

    pub fn add_enricher(&mut self, e: Box<dyn ResourceEnricher>) {
        self.enrichers.push(e);
    }

    pub fn add_classifier(&mut self, c: Box<dyn ActionClassifier>) {
        self.classifiers.push(c);
    }

    /// Run all enrichers on the resource, then all classifiers on the action.
    /// Returns the final action (original or reclassified).
    pub fn process(
        &self,
        action: &str,
        resource: &mut AuthzResource,
        ctx: &PipelineContext,
    ) -> String {
        for enricher in &self.enrichers {
            enricher.enrich(resource, ctx);
        }

        let mut final_action = action.to_string();
        for classifier in &self.classifiers {
            if let Some(new_action) = classifier.classify(&final_action, resource, ctx) {
                final_action = new_action;
            }
        }

        final_action
    }
}

impl Default for EnrichmentPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duramen_engine::entities::AuthzResource;

    struct TestEnricher;
    impl ResourceEnricher for TestEnricher {
        fn name(&self) -> &str { "test" }
        fn enrich(&self, resource: &mut AuthzResource, _ctx: &PipelineContext) {
            if let Some(attrs) = resource.attributes.as_object_mut() {
                attrs.insert("enriched".into(), serde_json::Value::Bool(true));
            }
        }
    }

    struct TestClassifier;
    impl ActionClassifier for TestClassifier {
        fn name(&self) -> &str { "test" }
        fn classify(&self, action: &str, resource: &AuthzResource, _ctx: &PipelineContext) -> Option<String> {
            if resource.attributes.get("enriched") == Some(&serde_json::Value::Bool(true)) {
                Some(format!("{action}:enriched"))
            } else {
                None
            }
        }
    }

    fn test_ctx() -> PipelineContext<'static> {
        PipelineContext {
            sub_command: "test",
            full_command: "test",
            binary: "test",
            args: &[],
            cwd: Some("/project"),
            tool_name: "bash",
            is_elevated: false,
        }
    }

    #[test]
    fn pipeline_runs_enrichers_then_classifiers() {
        let mut pipeline = EnrichmentPipeline::new();
        pipeline.add_enricher(Box::new(TestEnricher));
        pipeline.add_classifier(Box::new(TestClassifier));

        let mut resource = AuthzResource::file("/test");
        resource.attributes = serde_json::json!({});
        let action = pipeline.process("shell:test", &mut resource, &test_ctx());

        assert_eq!(action, "shell:test:enriched");
        assert_eq!(resource.attributes.get("enriched").unwrap(), &serde_json::Value::Bool(true));
    }

    #[test]
    fn empty_pipeline_passes_through() {
        let pipeline = EnrichmentPipeline::new();
        let mut resource = AuthzResource::file("/test");
        let action = pipeline.process("shell:cargo", &mut resource, &test_ctx());
        assert_eq!(action, "shell:cargo");
    }
}
