mod constraints;
mod markers;

pub use constraints::{FleetConstraints, NodeConstraint, ResourceClass};
pub use markers::{END_MARKER, START_MARKER, TransportError, extract_snapshot};

use rsi_probe::{ProbeError, Runner, SshAlias};
use rsi_schema::{Constraints, Finding, Snapshot};
use rsi_verify::VerificationPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NodeResult {
    Value {
        alias: String,
        snapshot: Box<Snapshot>,
        findings: Vec<Finding>,
    },
    Unreachable {
        alias: String,
    },
    Constrained {
        alias: String,
        reason_codes: Vec<String>,
    },
    Stale {
        alias: String,
        as_of: chrono::DateTime<chrono::Utc>,
    },
    VerificationFailed {
        alias: String,
        reason_codes: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetBundle {
    pub schema_version: String,
    pub nodes: Vec<NodeResult>,
}

pub fn scan(constraints: &FleetConstraints) -> FleetBundle {
    if constraints.validate().is_err() {
        let mut nodes = constraints
            .nodes
            .iter()
            .map(|constraint| NodeResult::Constrained {
                alias: public_alias(&constraint.alias),
                reason_codes: vec!["constraints_invalid".into()],
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| node_alias(left).cmp(node_alias(right)));
        return FleetBundle {
            schema_version: "rsi.fleet.v1".into(),
            nodes,
        };
    }

    let mut nodes = constraints
        .nodes
        .iter()
        .map(|constraint| {
            let output_alias = public_alias(&constraint.alias);
            let blocked_collectors = active_collectors()
                .into_iter()
                .filter(|collector| constraint.forbidden_collectors.contains(*collector))
                .map(str::to_string)
                .collect::<Vec<_>>();
            let mut reason_codes = blocked_collectors
                .iter()
                .map(|collector| format!("collector_forbidden:{collector}"))
                .collect::<Vec<_>>();
            if constraint.max_resource_class < ResourceClass::Standard {
                reason_codes.push("resource_class_exceeded:standard".into());
            }
            if !reason_codes.is_empty() {
                reason_codes.sort();
                return NodeResult::Constrained {
                    alias: output_alias,
                    reason_codes,
                };
            }
            let Ok(alias) = SshAlias::parse(constraint.alias.clone()) else {
                return NodeResult::Unreachable {
                    alias: output_alias,
                };
            };
            match Runner.run_ssh_scan(&alias, constraint.max_probe_duration_ms) {
                Ok(output) => match extract_snapshot(output.framed_stdout(), 1_048_576) {
                    Ok(snapshot) => evaluate_snapshot(snapshot, constraint),
                    Err(_) => NodeResult::Unreachable {
                        alias: output_alias,
                    },
                },
                Err(
                    ProbeError::Unavailable
                    | ProbeError::Execution
                    | ProbeError::Timeout { .. }
                    | ProbeError::OutputLimit { .. }
                    | ProbeError::AliasDenied,
                ) => NodeResult::Unreachable {
                    alias: output_alias,
                },
                Err(ProbeError::CapabilityDenied(_)) => NodeResult::Unreachable {
                    alias: output_alias,
                },
            }
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| node_alias(left).cmp(node_alias(right)));
    FleetBundle {
        schema_version: "rsi.fleet.v1".into(),
        nodes,
    }
}

pub fn evaluate_snapshot(snapshot: Snapshot, constraint: &NodeConstraint) -> NodeResult {
    let age = chrono::Utc::now().signed_duration_since(snapshot.captured_at);
    if age.num_seconds()
        > constraint
            .freshness_limit_secs
            .try_into()
            .unwrap_or(i64::MAX)
    {
        return NodeResult::Stale {
            alias: public_alias(&constraint.alias),
            as_of: snapshot.captured_at,
        };
    }
    let rules_constraints = Constraints {
        forbidden_collectors: constraint.forbidden_collectors.clone(),
        forbidden_rules: constraint.forbidden_rules.clone(),
        max_probe_duration_ms: Some(constraint.max_probe_duration_ms),
    };
    let verified = match rsi_verify::verify(snapshot, &VerificationPolicy::default()) {
        Ok(verified) => verified,
        Err(report) => {
            return NodeResult::VerificationFailed {
                alias: public_alias(&constraint.alias),
                reason_codes: report.issues.into_iter().map(|issue| issue.code).collect(),
            };
        }
    };
    let findings = rsi_optimize::analyze(&verified, &rules_constraints);
    NodeResult::Value {
        alias: public_alias(&constraint.alias),
        snapshot: Box::new(verified.into_snapshot()),
        findings,
    }
}

fn active_collectors() -> [&'static str; 5] {
    ["portable", "cli", "mcp", "gpu", "applications"]
}

fn node_alias(node: &NodeResult) -> &str {
    match node {
        NodeResult::Value { alias, .. }
        | NodeResult::Unreachable { alias }
        | NodeResult::Constrained { alias, .. }
        | NodeResult::Stale { alias, .. }
        | NodeResult::VerificationFailed { alias, .. } => alias,
    }
}

fn public_alias(alias: &str) -> String {
    let digest: String = Sha256::digest(alias.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("node-{}", &digest[..12])
}
