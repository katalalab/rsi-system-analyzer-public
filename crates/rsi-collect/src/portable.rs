use std::ffi::OsStr;
use std::thread;

use chrono::{DateTime, Utc};
use rsi_schema::redaction::sanitize_metadata_text;
use rsi_schema::{
    Capability, CpuFacts, ErrorCode, MachineFacts, Observation, ProcessSummary, Source,
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

pub fn collect_portable(captured_at: DateTime<Utc>) -> (MachineFacts, Vec<ProcessSummary>) {
    let machine = MachineFacts {
        os_family: result_observation(System::name(), captured_at),
        os_version: result_observation(System::os_version(), captured_at),
        kernel_version: result_observation(System::kernel_version(), captured_at),
        gpus: Observation::Unsupported {
            reason: "vendor probe not completed".into(),
        },
        ..MachineFacts::default()
    };
    collect_from_system(System::new_all(), machine, captured_at)
}

fn collect_from_system(
    system: Result<System, sysinfo::Error>,
    mut machine: MachineFacts,
    captured_at: DateTime<Utc>,
) -> (MachineFacts, Vec<ProcessSummary>) {
    let mut system = match system {
        Ok(system) => system,
        Err(error) => {
            machine.cpu = missing_observation(&error);
            machine.memory_bytes = missing_observation(&error);
            machine.available_memory_bytes = missing_observation(&error);
            return (machine, Vec::new());
        }
    };
    let refresh = ProcessRefreshKind::nothing().with_cpu().with_memory();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);
    thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, refresh);

    let logical_cores = system.cpus().len().max(1);
    let cpu = CpuFacts {
        architecture: std::env::consts::ARCH.into(),
        logical_cores,
        vendor: system.cpus().first().map(|cpu| cpu.vendor_id().to_owned()),
        brand: system.cpus().first().map(|cpu| cpu.brand().to_owned()),
    };
    machine.cpu = Observation::stable(cpu, captured_at, Source::Native);
    machine.memory_bytes = Observation::stable(system.total_memory(), captured_at, Source::Native);
    machine.available_memory_bytes = ephemeral(system.available_memory(), captured_at);

    let processes = summarize_processes(
        system
            .processes()
            .values()
            .map(|process| (process.name(), process.cpu_usage(), process.memory())),
        logical_cores,
        captured_at,
    );
    (machine, processes)
}

fn summarize_processes<'a>(
    samples: impl Iterator<Item = (&'a OsStr, f32, u64)>,
    logical_cores: usize,
    captured_at: DateTime<Utc>,
) -> Vec<ProcessSummary> {
    let mut processes = samples
        .map(|(name, cpu_usage, memory)| ProcessSummary {
            executable_basename: safe_basename(name),
            category: categorize(name),
            cpu_percent: ephemeral(cpu_usage / logical_cores as f32, captured_at),
            memory_bytes: ephemeral(memory, captured_at),
        })
        .collect::<Vec<_>>();
    processes.sort_by(|left, right| {
        observation_f32(&right.cpu_percent)
            .total_cmp(&observation_f32(&left.cpu_percent))
            .then_with(|| {
                observation_u64(&right.memory_bytes).cmp(&observation_u64(&left.memory_bytes))
            })
            .then_with(|| left.executable_basename.cmp(&right.executable_basename))
    });
    processes.truncate(20);

    processes
}

fn ephemeral<T>(value: T, captured_at: DateTime<Utc>) -> Observation<T> {
    Observation::Value {
        value,
        captured_at,
        source: Source::Native,
        confidence: rsi_schema::Confidence::High,
        stability: rsi_schema::Stability::Ephemeral,
    }
}

fn observation_f32(observation: &Observation<f32>) -> f32 {
    match observation {
        Observation::Value { value, .. } => *value,
        _ => 0.0,
    }
}

fn observation_u64(observation: &Observation<u64>) -> u64 {
    match observation {
        Observation::Value { value, .. } => *value,
        _ => 0,
    }
}

fn result_observation(
    value: Result<String, sysinfo::Error>,
    captured_at: DateTime<Utc>,
) -> Observation<String> {
    match value {
        Ok(value) => {
            Observation::stable(sanitize_metadata_text(&value), captured_at, Source::Native)
        }
        Err(error) => missing_observation(&error),
    }
}

fn missing_observation<T>(error: &sysinfo::Error) -> Observation<T> {
    match error {
        sysinfo::Error::Unsupported => Observation::Unsupported {
            reason: "platform did not expose value".into(),
        },
        sysinfo::Error::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Observation::Denied {
                capability: Capability::FileRead,
            }
        }
        sysinfo::Error::Io(_) => Observation::Error {
            code: ErrorCode::Io,
        },
        sysinfo::Error::Other(_) => Observation::Error {
            code: ErrorCode::InvalidOutput,
        },
    }
}

fn safe_basename(name: &OsStr) -> String {
    let sanitized = sanitize_metadata_text(&name.to_string_lossy());
    let basename = sanitized
        .rsplit(['/', '\\'])
        .find(|component| !component.is_empty())
        .unwrap_or("unknown");
    basename.replace(':', "_")
}

fn categorize(name: &OsStr) -> String {
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if ["python", "ollama", "cuda", "nvidia", "torch"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        "ai_compute"
    } else if ["codex", "claude", "gemini", "node", "cargo", "rustc"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        "development"
    } else if ["chrome", "firefox", "edge", "safari"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        "browser"
    } else {
        "other"
    }
    .into()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io;

    use chrono::{TimeZone, Utc};
    use rsi_schema::{
        Capability, Completeness, ErrorCode, MachineFacts, Observation, Source, Stability,
    };

    use super::{collect_from_system, result_observation, safe_basename, summarize_processes};

    #[test]
    fn metadata_results_preserve_values_and_explicit_missing_states() {
        let at = Utc.with_ymd_and_hms(2026, 11, 3, 0, 0, 0).unwrap();
        assert_eq!(
            result_observation(Ok("FixtureOS".into()), at),
            Observation::stable("FixtureOS".into(), at, Source::Native)
        );
        for (error, expected) in [
            (
                sysinfo::Error::Unsupported,
                Observation::Unsupported {
                    reason: "platform did not expose value".into(),
                },
            ),
            (
                sysinfo::Error::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic private context",
                )),
                Observation::Denied {
                    capability: Capability::FileRead,
                },
            ),
            (
                sysinfo::Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "synthetic private context",
                )),
                Observation::Error {
                    code: ErrorCode::Io,
                },
            ),
            (
                sysinfo::Error::from("synthetic private context"),
                Observation::Error {
                    code: ErrorCode::InvalidOutput,
                },
            ),
        ] {
            let observation = result_observation(Err(error), at);
            assert_eq!(observation, expected);
            assert!(
                !serde_json::to_string(&observation)
                    .unwrap()
                    .contains("private context")
            );
        }
    }

    #[test]
    fn metadata_values_are_redacted_at_the_collector_boundary() {
        let at = Utc.with_ymd_and_hms(2026, 11, 3, 0, 0, 0).unwrap();
        assert_eq!(
            result_observation(Ok("token=synthetic-value".into()), at),
            Observation::stable("[redacted-credential]".into(), at, Source::Native)
        );
    }

    #[test]
    fn failed_initialization_has_no_fabricated_cpu_memory_or_processes() {
        let at = Utc.with_ymd_and_hms(2026, 11, 3, 0, 0, 0).unwrap();
        for error in [
            sysinfo::Error::Unsupported,
            sysinfo::Error::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic private context",
            )),
            sysinfo::Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "synthetic private context",
            )),
            sysinfo::Error::from("synthetic private context"),
        ] {
            let metadata = MachineFacts {
                os_family: Observation::stable("FixtureOS".into(), at, Source::Native),
                ..MachineFacts::default()
            };
            let expected_cpu = super::missing_observation(&error);
            let expected_memory = super::missing_observation(&error);
            let (machine, processes) = collect_from_system(Err(error), metadata, at);
            assert_eq!(machine.cpu, expected_cpu);
            assert_eq!(machine.memory_bytes, expected_memory);
            assert_eq!(machine.available_memory_bytes, expected_memory);
            assert_eq!(
                machine.os_family,
                Observation::stable("FixtureOS".into(), at, Source::Native)
            );
            assert!(processes.is_empty());
            let mut completeness = Completeness::default();
            crate::record_portable_completeness(&machine, &mut completeness);
            assert!(!completeness.collectors_completed.contains("portable"));
            assert!(completeness.collectors_partial.contains_key("portable"));
            assert!(
                !serde_json::to_string(&machine)
                    .unwrap()
                    .contains("private context")
            );
        }
    }

    #[test]
    fn synthetic_processes_keep_normalization_order_cap_and_safe_shape() {
        let at = Utc.with_ymd_and_hms(2026, 11, 3, 0, 0, 0).unwrap();
        let names = (0..25)
            .map(|index| format!("worker-{index:02}"))
            .collect::<Vec<_>>();
        let processes = summarize_processes(
            names.iter().map(|name| (OsStr::new(name), 200.0, 64)),
            4,
            at,
        );
        assert_eq!(processes.len(), 20);
        assert_eq!(processes[0].executable_basename, "worker-00");
        assert_eq!(processes[19].executable_basename, "worker-19");
        assert!(processes.iter().all(|process| matches!(
            process.cpu_percent,
            Observation::Value {
                value: 50.0,
                stability: Stability::Ephemeral,
                ..
            }
        )));
        assert!(processes.iter().all(|process| matches!(
            process.memory_bytes,
            Observation::Value {
                value: 64,
                stability: Stability::Ephemeral,
                ..
            }
        )));
        let ranked = summarize_processes(
            [
                (OsStr::new("worker-low"), 4.0, 100),
                (OsStr::new("cargo"), 8.0, 10),
                (OsStr::new("token=synthetic-value"), 8.0, 20),
            ]
            .into_iter(),
            4,
            at,
        );
        assert_eq!(ranked[0].executable_basename, "[redacted-credential]");
        assert_eq!(ranked[1].executable_basename, "cargo");
        assert_eq!(ranked[1].category, "development");
        assert_eq!(ranked[2].executable_basename, "worker-low");
        let json = serde_json::to_string(&ranked).unwrap();
        for forbidden in [
            "pid",
            "command",
            "args",
            "environment",
            "exe_path",
            "synthetic-value",
        ] {
            assert!(!json.contains(forbidden));
        }
    }

    #[test]
    fn process_basenames_exclude_path_separators_on_every_platform() {
        for name in [
            "kworker/u8:0",
            "worker:pool",
            "folder\\worker",
            "plain-worker",
        ] {
            let sanitized = safe_basename(OsStr::new(name));
            assert!(!sanitized.contains(['/', '\\', ':']));
        }
        assert_eq!(safe_basename(OsStr::new("plain-worker")), "plain-worker");
    }

    #[test]
    fn process_basename_preserves_redaction_context_and_empty_fallback() {
        assert_eq!(
            safe_basename(OsStr::new("token=a\\sensitive-fixture")),
            "[redacted-credential]"
        );
        for name in ["", "/", "\\"] {
            assert_eq!(safe_basename(OsStr::new(name)), "unknown");
        }
        assert_eq!(safe_basename(OsStr::new("folder/worker/")), "worker");
    }

    #[test]
    fn process_basename_is_redacted_and_control_free() {
        let sanitized = safe_basename(OsStr::new("token=ghp_FAKEFAKEFAKE\u{1b}[31m"));
        assert!(!sanitized.contains("ghp_"));
        assert!(!sanitized.contains('\u{1b}'));
        assert!(!sanitized.contains("[31m"));
    }
}
