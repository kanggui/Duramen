// Allow-all policy: permits every action unconditionally.
// Use this for development/testing or as a starting point for customization.
// WARNING: This bypasses all authorization checks.

@id("allow-all")
@name("Allow all operations")
@description("Permits every action unconditionally — for development and testing only")
permit(principal, action, resource);
