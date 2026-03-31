@id("deny-force-push")
@name("Deny force push")
@description("Blocks git force-push operations")
forbid(
    principal,
    action == Action::"git:force-push",
    resource
);

@id("deny-git-destructive")
@name("Deny destructive git")
@description("Blocks destructive git operations like reset --hard and branch -D")
forbid(
    principal,
    action == Action::"git::destructive",
    resource
);

@id("deny-destructive-resource")
@name("Deny destructive resources")
@description("Blocks any action on resources marked as destructive")
forbid(
    principal,
    action,
    resource
) when {
    resource has is_destructive && resource.is_destructive == true
};

@id("deny-protected-delete")
@name("Deny protected file deletion")
@description("Blocks deletion of files marked as protected")
forbid(
    principal,
    action == Action::"file:delete",
    resource
) when {
    resource has is_protected && resource.is_protected == true
};
