// Team workflow policy: a realistic policy for collaborative development.
//
// Rules:
//   - Allow all read operations freely
//   - Allow file edits with audit logging
//   - Require approval before pushing to protected branches
//   - Deny destructive git operations entirely
//   - Deny file deletions on protected resources

// 1. Permit read-only operations without restriction
@id("team-allow-reads")
@name("Allow read operations")
@description("Permits file reads, directory listings, and git read operations for all team members")
permit(
    principal,
    action in [
        Action::"file:read",
        Action::"directory:list",
        Action::"git:status",
        Action::"git:log",
        Action::"git:diff",
        Action::"git::read"
    ],
    resource
);

// 2. Permit file writes with audit trail
@id("team-audit-writes")
@name("Audit file writes")
@description("Permits file create and edit operations with audit logging for traceability")
@advice("audit")
permit(
    principal,
    action in [
        Action::"file:create",
        Action::"file:edit"
    ],
    resource
);

// 3. Require human approval for git push/commit on any resource
@id("team-require-approval-git")
@name("Require approval for git writes")
@description("Requires human approval before push, commit, write, or network git operations")
@advice("require-approval")
permit(
    principal,
    action in [
        Action::"git:push",
        Action::"git:commit",
        Action::"git::write",
        Action::"git::network"
    ],
    resource
);

// 4. Always deny destructive git operations
@id("team-deny-force-push")
@name("Deny force push")
@description("Blocks git force-push to prevent history rewriting")
forbid(
    principal,
    action == Action::"git:force-push",
    resource
);

@id("team-deny-git-destructive")
@name("Deny destructive git")
@description("Blocks destructive git operations like reset --hard and branch -D")
forbid(
    principal,
    action == Action::"git::destructive",
    resource
);

// 5. Deny deletion of protected files
@id("team-deny-protected-delete")
@name("Deny protected file deletion")
@description("Blocks deletion of files marked as protected")
forbid(
    principal,
    action == Action::"file:delete",
    resource
) when {
    resource has is_protected && resource.is_protected == true
};
