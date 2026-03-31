use duramen_engine::adapter::PolicyEngine;
use duramen_engine::evaluator::CedarEngine;
use duramen_engine::policy::PolicyLoader;
use std::path::Path;

pub fn run(policy_dir: &str) -> i32 {
    let dir = Path::new(policy_dir);
    if !dir.exists() {
        eprintln!(r#"{{"error":"policy directory not found: {}"}}"#, policy_dir);
        return 3;
    }
    let loader = PolicyLoader::new();
    let policies = match loader.load_from_dir(dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(r#"{{"error":"{}"}}"#, e);
            return 3;
        }
    };

    let schema_path = std::path::Path::new(policy_dir).join("schema.cedarschema");
    let schema_src = if schema_path.exists() {
        std::fs::read_to_string(&schema_path)
            .map_err(|e| {
                eprintln!(r#"{{"error":"failed to read schema: {e}"}}"#);
            })
            .unwrap_or_else(|_| duramen_policy_defaults::SCHEMA.to_string())
    } else {
        duramen_policy_defaults::SCHEMA.to_string()
    };
    let engine = match CedarEngine::from_policy_sources_with_schema(&policies, &schema_src) {
        Ok(e) => e,
        Err(e) => {
            eprintln!(r#"{{"error":"{}"}}"#, e);
            return 3;
        }
    };

    match engine.validate_policies() {
        Ok(()) => {
            println!(
                r#"{{"status":"valid","policy_count":{}}}"#,
                policies.len()
            );
            0
        }
        Err(e) => {
            eprintln!(r#"{{"error":"{}"}}"#, e);
            1
        }
    }
}
