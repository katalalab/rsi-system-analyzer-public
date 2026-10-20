use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use rsi_fleet::{
    END_MARKER, FleetConstraints, NodeConstraint, NodeResult, ResourceClass, START_MARKER,
    TransportError, evaluate_snapshot, extract_snapshot, scan,
};

#[test]
fn parser_ignores_noise_outside_exact_markers() {
    let snapshot =
        rsi_schema::Snapshot::minimal_for_test(Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap());
    let payload = serde_json::to_string(&snapshot).unwrap();
    let noisy = format!("warning\n{START_MARKER}\n{payload}\n{END_MARKER}\nmotd");
    assert_eq!(extract_snapshot(&noisy, 1_048_576).unwrap(), snapshot);
}

fn constraint() -> NodeConstraint {
    NodeConstraint {
        alias: "fixture-node".into(),
        max_probe_duration_ms: 5_000,
        forbidden_collectors: BTreeSet::new(),
        forbidden_rules: BTreeSet::new(),
        max_resource_class: ResourceClass::Standard,
        freshness_limit_secs: 300,
    }
}

#[test]
fn collector_and_resource_constraints_stop_before_ssh() {
    let mut collector_blocked = constraint();
    collector_blocked.forbidden_collectors.insert("gpu".into());
    let mut resource_blocked = constraint();
    resource_blocked.max_resource_class = ResourceClass::Minimal;
    let bundle = scan(&FleetConstraints {
        nodes: vec![collector_blocked, resource_blocked],
    });
    assert!(matches!(
        &bundle.nodes[0],
        NodeResult::Constrained { reason_codes, .. }
            if reason_codes == &["collector_forbidden:gpu"]
    ));
    assert!(matches!(
        &bundle.nodes[1],
        NodeResult::Constrained { reason_codes, .. }
            if reason_codes == &["resource_class_exceeded:standard"]
    ));
}

#[test]
fn fleet_output_uses_stable_public_labels_not_ssh_aliases() {
    let mut blocked = constraint();
    blocked.forbidden_collectors.insert("gpu".into());
    let bundle = scan(&FleetConstraints {
        nodes: vec![blocked],
    });
    let json = serde_json::to_string(&bundle).unwrap();
    assert!(!json.contains("fixture-node"));
    assert!(json.contains("node-748dd8681526"));
}

#[test]
fn applications_collector_constraint_stops_before_ssh() {
    let mut application_blocked = constraint();
    application_blocked
        .forbidden_collectors
        .insert("applications".into());
    let bundle = scan(&FleetConstraints {
        nodes: vec![application_blocked],
    });
    assert!(matches!(
        &bundle.nodes[0],
        NodeResult::Constrained { reason_codes, .. }
            if reason_codes == &["collector_forbidden:applications"]
    ));
}

#[test]
fn invalid_constraints_stop_before_ssh() {
    let mut invalid = constraint();
    invalid.max_probe_duration_ms = 99;
    let bundle = scan(&FleetConstraints {
        nodes: vec![invalid],
    });
    assert!(matches!(
        &bundle.nodes[0],
        NodeResult::Constrained { reason_codes, .. }
            if reason_codes == &["constraints_invalid"]
    ));
}

#[test]
fn forbidden_rules_are_removed_before_fleet_ai_boundary() {
    let mut constraint = constraint();
    constraint
        .forbidden_rules
        .insert("resource.gpu-contention".into());
    let at = Utc::now();
    let mut snapshot = rsi_schema::Snapshot::minimal_for_test(at);
    snapshot
        .completeness
        .collectors_completed
        .extend(["portable".into(), "cli".into()]);
    snapshot.machine.gpus = rsi_schema::Observation::stable(
        vec![rsi_schema::GpuFact {
            vendor: "NVIDIA".into(),
            model: "fixture".into(),
            memory_bytes: None,
            utilization_percent: rsi_schema::Observation::Value {
                value: 100,
                captured_at: at,
                source: rsi_schema::Source::TypedProbe,
                confidence: rsi_schema::Confidence::High,
                stability: rsi_schema::Stability::Ephemeral,
            },
        }],
        at,
        rsi_schema::Source::TypedProbe,
    );
    match evaluate_snapshot(snapshot, &constraint) {
        NodeResult::Value { findings, .. } => assert!(findings.is_empty()),
        other => panic!("unexpected node result: {other:?}"),
    }
}

#[test]
fn invalid_snapshot_stops_before_optimization() {
    let mut snapshot = rsi_schema::Snapshot::minimal_for_test(Utc::now());
    snapshot.schema_version = "unknown".into();
    match evaluate_snapshot(snapshot, &constraint()) {
        NodeResult::VerificationFailed { reason_codes, .. } => {
            assert!(reason_codes.contains(&"schema.unsupported".into()));
        }
        other => panic!("unexpected node result: {other:?}"),
    }
}

#[test]
fn stale_snapshot_is_marked_without_findings() {
    let snapshot =
        rsi_schema::Snapshot::minimal_for_test(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
    assert!(matches!(
        evaluate_snapshot(snapshot, &constraint()),
        NodeResult::Stale { .. }
    ));
}

#[test]
fn parser_rejects_missing_markers_and_oversized_payloads() {
    assert_eq!(extract_snapshot("{}", 1_024), Err(TransportError::Framing));
    let snapshot =
        rsi_schema::Snapshot::minimal_for_test(Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap());
    let payload = serde_json::to_string(&snapshot).unwrap();
    let framed = format!("{START_MARKER}\n{payload}\n{END_MARKER}");
    assert_eq!(
        extract_snapshot(&framed, 16),
        Err(TransportError::Oversized)
    );
}

#[test]
fn parser_rejects_duplicate_or_shadowed_transport_frames() {
    let snapshot =
        rsi_schema::Snapshot::minimal_for_test(Utc.with_ymd_and_hms(2026, 7, 27, 0, 0, 0).unwrap());
    let payload = serde_json::to_string(&snapshot).unwrap();
    let frame = format!("{START_MARKER}\n{payload}\n{END_MARKER}");
    assert_eq!(
        extract_snapshot(&format!("{frame}\n{frame}"), 1_048_576),
        Err(TransportError::Framing)
    );
}

#[test]
fn constraints_reject_addresses_and_user_targets() {
    for alias in ["100.64.1.2", "user@node", "node:22", "-N", "-oProxyCommand"] {
        let constraints = FleetConstraints {
            nodes: vec![NodeConstraint {
                alias: alias.into(),
                max_probe_duration_ms: 5_000,
                forbidden_collectors: BTreeSet::new(),
                forbidden_rules: BTreeSet::new(),
                max_resource_class: ResourceClass::Minimal,
                freshness_limit_secs: 300,
            }],
        };
        assert!(constraints.validate().is_err());
    }
}

#[test]
fn constraints_reject_unknown_collector_and_rule_ids() {
    let mut unknown_collector = constraint();
    unknown_collector
        .forbidden_collectors
        .insert("gpu-typo".into());
    assert!(
        FleetConstraints {
            nodes: vec![unknown_collector]
        }
        .validate()
        .is_err()
    );

    let mut unknown_rule = constraint();
    unknown_rule.forbidden_rules.insert("resource.typo".into());
    assert!(
        FleetConstraints {
            nodes: vec![unknown_rule]
        }
        .validate()
        .is_err()
    );
}
