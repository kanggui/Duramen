pub const SCHEMA: &str = include_str!("../../../policies/default/schema.cedarschema");
pub const ALLOW_DEFAULT: &str = include_str!("../../../policies/default/allow-default.cedar");
pub const AUDIT_FILE_WRITES: &str =
    include_str!("../../../policies/default/audit-file-writes.cedar");
pub const DENY_DESTRUCTIVE: &str =
    include_str!("../../../policies/default/deny-destructive.cedar");
pub const REQUIRE_APPROVAL_SENSITIVE: &str =
    include_str!("../../../policies/default/require-approval-sensitive.cedar");

/// Deprecated: use `ALLOW_DEFAULT` instead.
#[deprecated(note = "renamed to ALLOW_DEFAULT")]
pub const ALLOW_READ_ONLY: &str = ALLOW_DEFAULT;

pub fn all_default_policies() -> Vec<&'static str> {
    vec![
        ALLOW_DEFAULT,
        AUDIT_FILE_WRITES,
        DENY_DESTRUCTIVE,
        REQUIRE_APPROVAL_SENSITIVE,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policies_are_non_empty() {
        for policy in all_default_policies() {
            assert!(!policy.trim().is_empty());
        }
    }

    #[test]
    fn schema_is_non_empty() {
        assert!(!SCHEMA.trim().is_empty());
    }
}
