use super::{CommandHandler, CommandParseResult};
use duramen_engine::entities::AuthzResource;

pub struct GitCommandHandler;

impl CommandHandler for GitCommandHandler {
    fn binary_name(&self) -> &str {
        "git"
    }

    fn parse(&self, parts: &[&str], _cwd: Option<&str>) -> CommandParseResult {
        let subcommand = parts.first().copied().unwrap_or("status");
        let remaining = if parts.len() > 1 { &parts[1..] } else { &[] };

        let has_force = remaining.iter().any(|a| *a == "--force" || *a == "-f");
        let has_hard = remaining.contains(&"--hard");
        let has_delete = remaining
            .iter()
            .any(|a| *a == "-D" || *a == "-d" || *a == "--delete");

        let action = match subcommand {
            "status" | "log" | "diff" | "show" | "remote" => "git::read",
            "branch" if has_delete => "git::destructive",
            "branch" => "git::read",
            "tag" if has_delete => "git::write",
            "tag" => "git::read",
            "add" | "commit" | "checkout" | "switch" | "stash" | "merge" | "rebase" => "git::write",
            "fetch" | "pull" | "clone" => "git::network",
            "push" if has_force => "git::destructive",
            "push" => "git::network",
            "reset" if has_hard => "git::destructive",
            "reset" => "git::write",
            "clean"
                if remaining
                    .iter()
                    .any(|a| *a == "-fd" || *a == "-f" || a.contains('f')) =>
            {
                "git::destructive"
            }
            "clean" => "git::write",
            _ => "git::write",
        };

        let is_destructive = action == "git::destructive";

        // Extract non-flag arguments
        let non_flag_args: Vec<&str> = remaining
            .iter()
            .filter(|a| !a.starts_with('-'))
            .copied()
            .collect();

        // Extract remote and ref for network commands
        let (remote, git_ref) = match subcommand {
            "push" | "pull" | "fetch" => {
                let remote = non_flag_args.first().copied();
                let ref_name = non_flag_args.get(1).copied().unwrap_or("HEAD");
                (remote, ref_name)
            }
            "checkout" | "switch" => {
                let ref_name = non_flag_args.last().copied().unwrap_or("HEAD");
                (None, ref_name)
            }
            "reset" => {
                let ref_name = non_flag_args.last().copied().unwrap_or("HEAD");
                (None, ref_name)
            }
            "branch" if has_delete => {
                let ref_name = non_flag_args.last().copied().unwrap_or("HEAD");
                (None, ref_name)
            }
            _ => (None, "HEAD"),
        };

        let mut resource = AuthzResource::git_ref(git_ref);
        let mut attrs = serde_json::Map::new();
        attrs.insert(
            "is_destructive".to_string(),
            serde_json::Value::Bool(is_destructive),
        );
        if let Some(remote) = remote {
            attrs.insert(
                "remote".to_string(),
                serde_json::Value::String(remote.to_string()),
            );
        }
        resource.attributes = serde_json::Value::Object(attrs);

        CommandParseResult {
            action: action.to_string(),
            resource,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duramen_engine::entities::ResourceType;

    #[test]
    fn git_handler_binary_name() {
        assert_eq!(GitCommandHandler.binary_name(), "git");
    }

    #[test]
    fn git_handler_parses_push_force() {
        let result =
            GitCommandHandler.parse(&["push", "--force", "origin", "main"], Some("/project"));
        assert_eq!(result.action, "git::destructive");
        assert_eq!(result.resource.resource_type, ResourceType::GitRef);
        assert_eq!(result.resource.id, "main");
    }

    #[test]
    fn git_handler_parses_status() {
        let result = GitCommandHandler.parse(&["status"], Some("/project"));
        assert_eq!(result.action, "git::read");
    }

    #[test]
    fn git_handler_parses_commit() {
        let result = GitCommandHandler.parse(&["commit", "-m", "fix bug"], None);
        assert_eq!(result.action, "git::write");
    }

    #[test]
    fn git_handler_parses_pull() {
        let result = GitCommandHandler.parse(&["pull", "origin", "main"], None);
        assert_eq!(result.action, "git::network");
        assert_eq!(result.resource.id, "main");
    }

    #[test]
    fn git_handler_parses_clone() {
        let result = GitCommandHandler.parse(&["clone", "https://github.com/repo.git"], None);
        assert_eq!(result.action, "git::network");
    }

    #[test]
    fn git_handler_parses_add() {
        let result = GitCommandHandler.parse(&["add", "."], None);
        assert_eq!(result.action, "git::write");
    }

    #[test]
    fn git_handler_parses_merge() {
        let result = GitCommandHandler.parse(&["merge", "feature"], None);
        assert_eq!(result.action, "git::write");
    }

    #[test]
    fn git_handler_parses_rebase() {
        let result = GitCommandHandler.parse(&["rebase", "main"], None);
        assert_eq!(result.action, "git::write");
    }

    #[test]
    fn git_handler_parses_reset_soft() {
        let result = GitCommandHandler.parse(&["reset", "HEAD~1"], None);
        assert_eq!(result.action, "git::write");
    }

    #[test]
    fn git_handler_parses_reset_hard() {
        let result = GitCommandHandler.parse(&["reset", "--hard", "HEAD~3"], None);
        assert_eq!(result.action, "git::destructive");
        assert_eq!(result.resource.id, "HEAD~3");
    }

    #[test]
    fn git_handler_parses_clean_fd() {
        let result = GitCommandHandler.parse(&["clean", "-fd"], None);
        assert_eq!(result.action, "git::destructive");
    }

    #[test]
    fn git_handler_parses_branch_delete_lowercase() {
        let result = GitCommandHandler.parse(&["branch", "-d", "old-branch"], None);
        assert_eq!(result.action, "git::destructive");
        assert_eq!(result.resource.id, "old-branch");
    }

    #[test]
    fn git_handler_parses_tag_read() {
        let result = GitCommandHandler.parse(&["tag"], None);
        assert_eq!(result.action, "git::read");
    }

    #[test]
    fn git_handler_parses_tag_delete() {
        let result = GitCommandHandler.parse(&["tag", "-d", "v1.0"], None);
        assert_eq!(result.action, "git::write");
    }

    #[test]
    fn git_handler_parses_push_with_remote_and_ref() {
        let result = GitCommandHandler.parse(&["push", "upstream", "feature-branch"], None);
        assert_eq!(result.action, "git::network");
        assert_eq!(result.resource.id, "feature-branch");
        assert_eq!(
            result.resource.attributes.get("remote").unwrap(),
            &serde_json::json!("upstream")
        );
    }

    #[test]
    fn git_handler_defaults_unknown_subcommand_to_write() {
        let result = GitCommandHandler.parse(&["bisect", "start"], None);
        assert_eq!(result.action, "git::write");
    }

    #[test]
    fn git_handler_no_subcommand_defaults_to_status() {
        let result = GitCommandHandler.parse(&[], None);
        assert_eq!(result.action, "git::read");
    }
}
