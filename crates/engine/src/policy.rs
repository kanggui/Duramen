use crate::adapter::EngineError;
use std::path::Path;

pub struct PolicyLoader;

impl Default for PolicyLoader {
    fn default() -> Self {
        Self
    }
}

impl PolicyLoader {
    pub fn new() -> Self {
        Self
    }

    /// Load all .cedar files from a directory and return their contents.
    pub fn load_from_dir(&self, dir: &Path) -> Result<Vec<String>, EngineError> {
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut policies = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map_err(EngineError::Io)?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "cedar") {
                let content = std::fs::read_to_string(&path).map_err(EngineError::Io)?;
                content.parse::<cedar_policy::PolicySet>().map_err(|e| {
                    EngineError::PolicyParse(format!("{}: {e}", path.display()))
                })?;
                policies.push(content);
            }
        }
        Ok(policies)
    }

    /// Load policies with resolution order: defaults + user dir + repo dir.
    pub fn load_merged(
        &self,
        repo_dir: Option<&Path>,
        user_dir: Option<&Path>,
        defaults: &[&str],
    ) -> Result<cedar_policy::PolicySet, EngineError> {
        let mut all_sources: Vec<String> = Vec::new();
        for d in defaults {
            all_sources.push((*d).to_string());
        }
        if let Some(dir) = user_dir {
            all_sources.extend(self.load_from_dir(dir)?);
        }
        if let Some(dir) = repo_dir {
            all_sources.extend(self.load_from_dir(dir)?);
        }
        let combined = all_sources.join("\n");
        combined
            .parse::<cedar_policy::PolicySet>()
            .map_err(|e| EngineError::PolicyParse(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn loads_policies_from_directory() {
        let dir = TempDir::new().unwrap();
        let policy = r#"permit(principal, action, resource);"#;
        std::fs::write(dir.path().join("test.cedar"), policy).unwrap();

        let loader = PolicyLoader::new();
        let result = loader.load_from_dir(dir.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("permit"));
    }

    #[test]
    fn ignores_non_cedar_files() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("readme.md"), "# Hello").unwrap();

        let loader = PolicyLoader::new();
        let result = loader.load_from_dir(dir.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn returns_error_on_invalid_policy() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("bad.cedar"), "not valid cedar!!!").unwrap();

        let loader = PolicyLoader::new();
        let result = loader.load_from_dir(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("policy parse error"), "got: {err}");
    }

    #[test]
    fn loads_empty_directory() {
        let dir = TempDir::new().unwrap();
        let loader = PolicyLoader::new();
        let result = loader.load_from_dir(dir.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn nonexistent_directory_returns_empty() {
        let loader = PolicyLoader::new();
        let result = loader.load_from_dir(std::path::Path::new("/nonexistent/path")).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn load_merged_with_defaults_only() {
        let loader = PolicyLoader::new();
        let defaults = vec!["permit(principal, action, resource);"];
        let result = loader.load_merged(None, None, &defaults).unwrap();
        // Should have at least one policy from defaults
        assert!(result.policies().count() > 0);
    }

    #[test]
    fn load_merged_repo_overrides_defaults() {
        let dir = TempDir::new().unwrap();
        let policy = r#"forbid(principal, action, resource);"#;
        std::fs::write(dir.path().join("override.cedar"), policy).unwrap();

        let loader = PolicyLoader::new();
        let defaults = vec!["permit(principal, action, resource);"];
        let result = loader.load_merged(Some(dir.path()), None, &defaults).unwrap();
        // Both default permit and repo forbid should be loaded
        assert!(result.policies().count() >= 2);
    }

    #[test]
    fn load_merged_all_empty_sources() {
        let loader = PolicyLoader::new();
        let defaults: Vec<&str> = vec![];
        let result = loader.load_merged(None, None, &defaults).unwrap();
        assert_eq!(result.policies().count(), 0);
    }
}
