use std::ffi::OsStr;
use std::thread;

use chrono::{DateTime, Utc};
use rsi_schema::redaction::sanitize_metadata_text;
use rsi_schema::{CpuFacts, MachineFacts, Observation, ProcessSummary, Source};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

pub fn collect_portable(captured_at: DateTime<Utc>) -> (MachineFacts, Vec<ProcessSummary>) {
    let mut system = System::new_all();
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
    let machine = MachineFacts {
        os_family: Observation::stable(
            System::name().unwrap_or_else(|| std::env::consts::OS.into()),
            captured_at,
            Source::Native,
        ),
        os_version: optional_observation(System::os_version(), captured_at),
        kernel_version: optional_observation(System::kernel_version(), captured_at),
        cpu: Observation::stable(cpu, captured_at, Source::Native),
        memory_bytes: Observation::stable(system.total_memory(), captured_at, Source::Native),
        available_memory_bytes: Observation::Value {
            value: system.available_memory(),
            captured_at,
            source: Source::Native,
            confidence: rsi_schema::Confidence::High,
            stability: rsi_schema::Stability::Ephemeral,
        },
        gpus: Observation::Unsupported {
            reason: "vendor probe not completed".into(),
        },
    };

    let mut processes = system
        .processes()
        .values()
        .map(|process| ProcessSummary {
            executable_basename: safe_basename(process.name()),
            category: categorize(process.name()),
            cpu_percent: ephemeral(process.cpu_usage() / logical_cores as f32, captured_at),
            memory_bytes: ephemeral(process.memory(), captured_at),
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

    (machine, processes)
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

fn optional_observation(value: Option<String>, captured_at: DateTime<Utc>) -> Observation<String> {
    value.map_or_else(
        || Observation::Unsupported {
            reason: "platform did not expose value".into(),
        },
        |value| Observation::stable(value, captured_at, Source::Native),
    )
}

fn safe_basename(name: &OsStr) -> String {
    let name = name.to_string_lossy();
    let basename = name.rsplit(['/', '\\']).next().unwrap_or("unknown");
    sanitize_metadata_text(basename).replace(':', "_")
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

    use super::safe_basename;

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
    fn process_basename_is_redacted_and_control_free() {
        let sanitized = safe_basename(OsStr::new("token=ghp_FAKEFAKEFAKE\u{1b}[31m"));
        assert!(!sanitized.contains("ghp_"));
        assert!(!sanitized.contains('\u{1b}'));
        assert!(!sanitized.contains("[31m"));
    }
}
