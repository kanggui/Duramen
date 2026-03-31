@id("audit-file-writes")
@name("Audit file writes")
@description("Permits file create and edit on non-protected files with audit logging")
@advice("audit")
permit(
    principal,
    action in [
        Action::"file:create",
        Action::"file:edit"
    ],
    resource
) when {
    !(resource has is_protected && resource.is_protected == true)
};
