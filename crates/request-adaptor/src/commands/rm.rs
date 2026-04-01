use super::{CommandHandler, CommandParseResult};
use duramen_engine::entities::AuthzResource;

pub struct RmCommandHandler;

impl CommandHandler for RmCommandHandler {
    fn binary_name(&self) -> &str {
        "rm"
    }

    fn parse(&self, args: &[&str], cwd: Option<&str>) -> CommandParseResult {
        let non_flag_args: Vec<&str> = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .copied()
            .collect();

        let target = non_flag_args.last().copied();

        let resource = if let Some(t) = target {
            let resolved = if t.starts_with('/') || t.starts_with('\\') {
                t.to_string()
            } else if let Some(cwd) = cwd {
                format!("{}/{}", cwd.trim_end_matches('/'), t)
            } else {
                t.to_string()
            };
            let mut r = AuthzResource::file(&resolved);
            r.attributes = serde_json::json!({
                "is_destructive": true,
                "is_protected": false,
            });
            r
        } else {
            let dir = cwd.unwrap_or(".");
            let mut r = AuthzResource::file(dir);
            r.attributes = serde_json::json!({
                "is_destructive": true,
                "is_protected": false,
            });
            r
        };

        CommandParseResult {
            action: "file:delete".to_string(),
            resource,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duramen_engine::entities::ResourceType;

    #[test]
    fn rm_handler_maps_to_file_delete() {
        let result = RmCommandHandler.parse(&["-rf", "dist"], Some("/project"));
        assert_eq!(result.action, "file:delete");
        assert_eq!(result.resource.resource_type, ResourceType::File);
        assert_eq!(result.resource.id, "/project/dist");
    }

    #[test]
    fn rm_handler_marks_destructive() {
        let result = RmCommandHandler.parse(&["file.txt"], Some("/project"));
        assert_eq!(
            result.resource.attributes.get("is_destructive").unwrap(),
            &serde_json::json!(true)
        );
    }

    #[test]
    fn rm_handler_absolute_path() {
        let result = RmCommandHandler.parse(&["/etc/important"], None);
        assert_eq!(result.action, "file:delete");
        assert_eq!(result.resource.id, "/etc/important");
    }

    #[test]
    fn rm_handler_no_args() {
        let result = RmCommandHandler.parse(&[], Some("/project"));
        assert_eq!(result.action, "file:delete");
        assert_eq!(result.resource.id, "/project");
    }
}
