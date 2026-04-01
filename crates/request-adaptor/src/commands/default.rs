use super::{CommandHandler, CommandParseResult};
use duramen_engine::entities::AuthzResource;

pub struct DefaultCommandHandler;

impl CommandHandler for DefaultCommandHandler {
    fn binary_name(&self) -> &str {
        "default"
    }

    fn parse(&self, args: &[&str], cwd: Option<&str>) -> CommandParseResult {
        let action = "shell:unknown".to_string(); // caller overrides action with shell:<binary>

        // Collect non-flag arguments
        let non_flag_args: Vec<&str> = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .copied()
            .collect();

        let target = non_flag_args.last().copied();

        let resource = if let Some(t) = target {
            if t.starts_with("http://") || t.starts_with("https://") {
                AuthzResource::url(t)
            } else {
                let resolved = if t.starts_with('/') || t.starts_with('\\') {
                    t.to_string()
                } else if let Some(cwd) = cwd {
                    format!("{}/{}", cwd.trim_end_matches('/'), t)
                } else {
                    t.to_string()
                };
                AuthzResource::file(&resolved)
            }
        } else {
            let dir = cwd.unwrap_or(".");
            AuthzResource::file(dir)
        };

        CommandParseResult { action, resource }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duramen_engine::entities::ResourceType;

    #[test]
    fn default_handler_extracts_file_target() {
        let result = DefaultCommandHandler.parse(&["-rf", "dist"], Some("/project"));
        assert_eq!(result.resource.resource_type, ResourceType::File);
        assert_eq!(result.resource.id, "/project/dist");
    }

    #[test]
    fn default_handler_detects_url() {
        let result = DefaultCommandHandler.parse(&["https://example.com"], None);
        assert_eq!(result.resource.resource_type, ResourceType::Url);
    }

    #[test]
    fn default_handler_falls_back_to_cwd() {
        let result = DefaultCommandHandler.parse(&["-v"], Some("/project"));
        assert_eq!(result.resource.id, "/project");
    }

    #[test]
    fn default_handler_no_cwd_no_args() {
        let result = DefaultCommandHandler.parse(&[], None);
        assert_eq!(result.resource.id, ".");
    }

    #[test]
    fn default_handler_absolute_path() {
        let result = DefaultCommandHandler.parse(&["/etc/passwd"], Some("/home"));
        assert_eq!(result.resource.id, "/etc/passwd");
    }
}
