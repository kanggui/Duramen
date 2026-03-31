@id("require-approval-protected-git")
@name("Require approval for protected git ops")
@description("Requires human approval before push, commit, or network operations on protected refs")
@advice("require-approval")
permit(
    principal,
    action in [
        Action::"git:push",
        Action::"git:commit",
        Action::"git::network",
        Action::"git::write"
    ],
    resource
) when {
    resource has is_protected && resource.is_protected == true
};

@id("require-approval-file-delete")
@name("Require approval for file deletion")
@description("Requires human approval before deleting non-protected files")
@advice("require-approval")
permit(
    principal,
    action == Action::"file:delete",
    resource
) when {
    !(resource has is_protected && resource.is_protected == true)
};
