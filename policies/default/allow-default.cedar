@id("allow-all-by-default")
@name("Allow all operations by default")
@description("Permits any action not explicitly forbidden by other policies. Specific forbid, audit, and approval rules take precedence.")
permit(
    principal,
    action,
    resource
);
