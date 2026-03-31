use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionTier {
    Allow,
    Audit,
    RequireApproval,
    Deny,
}

impl DecisionTier {
    pub fn exit_code(&self) -> i32 {
        match self {
            DecisionTier::Allow => 0,
            DecisionTier::Audit => 0,
            DecisionTier::RequireApproval => 2,
            DecisionTier::Deny => 1,
        }
    }
}

impl FromStr for DecisionTier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(DecisionTier::Allow),
            "audit" => Ok(DecisionTier::Audit),
            "require-approval" => Ok(DecisionTier::RequireApproval),
            "deny" => Ok(DecisionTier::Deny),
            other => Err(format!("unknown decision tier: {other}")),
        }
    }
}

impl std::fmt::Display for DecisionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecisionTier::Allow => write!(f, "allow"),
            DecisionTier::Audit => write!(f, "audit"),
            DecisionTier::RequireApproval => write!(f, "require-approval"),
            DecisionTier::Deny => write!(f, "deny"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzDecision {
    pub decision: DecisionTier,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_description: Option<String>,
    pub evaluation_time_ms: u64,
}

impl AuthzDecision {
    pub fn new(decision: DecisionTier, reason: String) -> Self {
        Self {
            decision,
            reason,
            policy_id: None,
            policy_name: None,
            policy_description: None,
            evaluation_time_ms: 0,
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, DecisionTier::Allow | DecisionTier::Audit)
    }

    pub fn exit_code(&self) -> i32 {
        self.decision.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn decision_tier_exit_codes() {
        assert_eq!(DecisionTier::Allow.exit_code(), 0);
        assert_eq!(DecisionTier::Audit.exit_code(), 0);
        assert_eq!(DecisionTier::RequireApproval.exit_code(), 2);
        assert_eq!(DecisionTier::Deny.exit_code(), 1);
    }

    #[test]
    fn decision_tier_from_str() {
        assert_eq!(DecisionTier::from_str("allow").unwrap(), DecisionTier::Allow);
        assert_eq!(DecisionTier::from_str("audit").unwrap(), DecisionTier::Audit);
        assert_eq!(
            DecisionTier::from_str("require-approval").unwrap(),
            DecisionTier::RequireApproval
        );
        assert_eq!(DecisionTier::from_str("deny").unwrap(), DecisionTier::Deny);
        assert!(DecisionTier::from_str("bogus").is_err());
    }

    #[test]
    fn decision_tier_serializes_lowercase() {
        let json = serde_json::to_string(&DecisionTier::RequireApproval).unwrap();
        assert_eq!(json, "\"require-approval\"");
    }

    #[test]
    fn authz_decision_is_allowed() {
        let allow = AuthzDecision::new(DecisionTier::Allow, "ok".into());
        let audit = AuthzDecision::new(DecisionTier::Audit, "logged".into());
        let deny = AuthzDecision::new(DecisionTier::Deny, "blocked".into());
        assert!(allow.is_allowed());
        assert!(audit.is_allowed());
        assert!(!deny.is_allowed());
    }

    #[test]
    fn decision_tier_from_str_rejects_variations() {
        assert!(DecisionTier::from_str("Allow").is_err());
        assert!(DecisionTier::from_str("DENY").is_err());
        assert!(DecisionTier::from_str("").is_err());
        assert!(DecisionTier::from_str(" allow ").is_err());
    }

    #[test]
    fn authz_decision_json_round_trip() {
        let mut decision = AuthzDecision::new(DecisionTier::Audit, "logged".into());
        decision.policy_id = Some("policy-1".into());
        decision.policy_name = Some("Audit writes".into());
        decision.policy_description = Some("Logs file writes".into());
        decision.evaluation_time_ms = 5;

        let json = serde_json::to_string(&decision).unwrap();
        let back: AuthzDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decision, DecisionTier::Audit);
        assert_eq!(back.policy_name.as_deref(), Some("Audit writes"));
        assert_eq!(back.policy_description.as_deref(), Some("Logs file writes"));
    }

    #[test]
    fn authz_decision_omits_none_fields_in_json() {
        let decision = AuthzDecision::new(DecisionTier::Allow, "ok".into());
        let json = serde_json::to_string(&decision).unwrap();
        assert!(!json.contains("policy_id"));
        assert!(!json.contains("policy_name"));
        assert!(!json.contains("policy_description"));
    }
}