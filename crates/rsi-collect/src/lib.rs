mod inventory;
mod portable;
mod tools;

use std::time::Instant;

use chrono::Utc;
use rsi_probe::PROBE_MANIFEST_VERSION;
use rsi_schema::redaction::sanitize_snapshot;
use rsi_schema::{Completeness, MachineFacts, Observation, Snapshot};
use uuid::Uuid;

pub use portable::collect_portable;
pub use tools::collect_cli;

#[derive(Debug, Clone, Copy, Default)]
pub struct CollectOptions {
    pub fast: bool,
}

pub fn collect_snapshot(options: CollectOptions) -> Snapshot {
    let started = Instant::now();
    let captured_at = Utc::now();
    let (mut machine, processes) = collect_portable(captured_at);
    let cli = collect_cli();
    let mcp = inventory::collect_mcp_metadata();
    let applications = if options.fast {
        Vec::new()
    } else {
        inventory::collect_application_names()
    };
    machine.gpus = inventory::collect_gpu(captured_at);
    let mut completeness = Completeness::default();
    record_portable_completeness(&machine, &mut completeness);
    completeness.collectors_completed.insert("cli".into());
    if options.fast {
        completeness
            .collectors_partial
            .insert("applications".into(), "disabled in fast mode".into());
    }

    let mut snapshot = Snapshot {
        schema_version: rsi_schema::SCHEMA_VERSION.into(),
        analyzer_version: env!("CARGO_PKG_VERSION").into(),
        probe_manifest_version: PROBE_MANIFEST_VERSION.into(),
        snapshot_id: Uuid::new_v4(),
        captured_at,
        elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        machine,
        processes,
        cli,
        mcp,
        applications,
        completeness,
    };
    sanitize_snapshot(&mut snapshot);
    snapshot
}

fn record_portable_completeness(machine: &MachineFacts, completeness: &mut Completeness) {
    if matches!(machine.os_family, Observation::Value { .. })
        && matches!(machine.os_version, Observation::Value { .. })
        && matches!(machine.kernel_version, Observation::Value { .. })
        && matches!(machine.cpu, Observation::Value { .. })
        && matches!(machine.memory_bytes, Observation::Value { .. })
        && matches!(machine.available_memory_bytes, Observation::Value { .. })
    {
        completeness.collectors_completed.insert("portable".into());
    } else {
        completeness
            .collectors_partial
            .insert("portable".into(), "native platform facts incomplete".into());
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use rsi_schema::{Completeness, CpuFacts, MachineFacts, Observation, Source};

    use super::record_portable_completeness;

    #[test]
    fn portable_missing_facts_are_partial_not_completed() {
        let at = Utc.with_ymd_and_hms(2026, 11, 3, 0, 0, 0).unwrap();
        let complete = MachineFacts {
            os_family: Observation::stable("FixtureOS".into(), at, Source::Native),
            os_version: Observation::stable("1".into(), at, Source::Native),
            kernel_version: Observation::stable("1".into(), at, Source::Native),
            cpu: Observation::stable(
                CpuFacts {
                    logical_cores: 4,
                    ..CpuFacts::default()
                },
                at,
                Source::Native,
            ),
            memory_bytes: Observation::stable(128, at, Source::Native),
            available_memory_bytes: Observation::stable(64, at, Source::Native),
            ..MachineFacts::default()
        };
        let mut completeness = Completeness::default();
        record_portable_completeness(&complete, &mut completeness);
        assert!(completeness.collectors_completed.contains("portable"));
        assert!(!completeness.collectors_partial.contains_key("portable"));

        for field in 0..6 {
            let mut missing = complete.clone();
            match field {
                0 => missing.os_family = Observation::default(),
                1 => missing.os_version = Observation::default(),
                2 => missing.kernel_version = Observation::default(),
                3 => missing.cpu = Observation::default(),
                4 => missing.memory_bytes = Observation::default(),
                _ => missing.available_memory_bytes = Observation::default(),
            }
            let mut completeness = Completeness::default();
            record_portable_completeness(&missing, &mut completeness);
            assert!(!completeness.collectors_completed.contains("portable"));
            assert_eq!(
                completeness
                    .collectors_partial
                    .get("portable")
                    .map(String::as_str),
                Some("native platform facts incomplete")
            );
        }
    }
}
