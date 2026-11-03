use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use command_group::CommandGroup;
use rsi_schema::Capability;
use rsi_schema::redaction::sanitize_untrusted_text;
use thiserror::Error;

use crate::{CapabilityPolicy, ProbeId, ProbeSpec, SshAlias};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProbeError {
    #[error("probe capability denied")]
    CapabilityDenied(Capability),
    #[error("probe executable unavailable")]
    Unavailable,
    #[error("probe timed out after {limit_ms} ms")]
    Timeout { limit_ms: u64 },
    #[error("probe output exceeded {limit_bytes} bytes")]
    OutputLimit { limit_bytes: usize },
    #[error("probe execution failed")]
    Execution,
    #[error("SSH alias denied")]
    AliasDenied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshScanOutput(String);

impl SshScanOutput {
    pub fn framed_stdout(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Default)]
pub struct Runner;

impl Runner {
    pub fn run(&self, id: ProbeId) -> Result<ProbeOutput, ProbeError> {
        self.run_spec(ProbeSpec::from_id(id))
    }

    pub fn run_ssh_scan(
        &self,
        alias: &SshAlias,
        timeout_ms: u64,
    ) -> Result<SshScanOutput, ProbeError> {
        let output = self.run_program(
            "ssh",
            &[
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                alias.as_str(),
                "rsi-scan scan --fast --transport-markers",
            ],
            timeout_ms.clamp(100, 30_000),
            1_048_576,
            false,
        )?;
        if !output.success {
            return Err(ProbeError::Execution);
        }
        Ok(SshScanOutput(output.stdout))
    }

    fn run_spec(&self, spec: ProbeSpec) -> Result<ProbeOutput, ProbeError> {
        if let CapabilityPolicy::Denied(capability) = spec.capability {
            return Err(ProbeError::CapabilityDenied(capability));
        }
        self.run_program(
            spec.executable.program(),
            spec.args,
            spec.timeout_ms,
            spec.max_output_bytes,
            true,
        )
    }

    fn run_program(
        &self,
        program: &str,
        args: &[&str],
        timeout_ms: u64,
        max_output_bytes: usize,
        sanitize_stdout: bool,
    ) -> Result<ProbeOutput, ProbeError> {
        let started = Instant::now();
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, _) in std::env::vars_os() {
            if sensitive_environment_key(&key.to_string_lossy()) {
                command.env_remove(key);
            }
        }
        let mut child = command.group_spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProbeError::Unavailable
            } else {
                ProbeError::Execution
            }
        })?;

        let stdout = child.inner().stdout.take().ok_or(ProbeError::Execution)?;
        let stderr = child.inner().stderr.take().ok_or(ProbeError::Execution)?;
        let cap = max_output_bytes + 1;
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(1);
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let _ = stdout_sender.send(read_bounded(stdout, cap));
        });
        thread::spawn(move || {
            let _ = stderr_sender.send(read_bounded(stderr, cap));
        });
        let deadline = started + Duration::from_millis(timeout_ms);

        let status = loop {
            match child.try_wait().map_err(|_| ProbeError::Execution)? {
                Some(status) => break status,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProbeError::Timeout {
                        limit_ms: timeout_ms,
                    });
                }
                None => thread::sleep(Duration::from_millis(10)),
            }
        };

        let stdout = match receive_output(&stdout_receiver, deadline, timeout_ms) {
            Ok(stdout) => stdout,
            Err(error @ ProbeError::Timeout { .. }) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let stderr = match receive_output(&stderr_receiver, deadline, timeout_ms) {
            Ok(stderr) => stderr,
            Err(error @ ProbeError::Timeout { .. }) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if stdout.len() > max_output_bytes || stderr.len() > max_output_bytes {
            return Err(ProbeError::OutputLimit {
                limit_bytes: max_output_bytes,
            });
        }

        let stdout = String::from_utf8_lossy(&stdout);
        Ok(ProbeOutput {
            stdout: if sanitize_stdout {
                sanitize_untrusted_text(&stdout)
            } else {
                stdout.into_owned()
            },
            stderr: sanitize_untrusted_text(&String::from_utf8_lossy(&stderr)),
            success: status.success(),
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        })
    }
}

fn receive_output(
    receiver: &Receiver<Result<Vec<u8>, ProbeError>>,
    deadline: Instant,
    timeout_ms: u64,
) -> Result<Vec<u8>, ProbeError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(output) => output,
        Err(RecvTimeoutError::Timeout) => Err(ProbeError::Timeout {
            limit_ms: timeout_ms,
        }),
        Err(RecvTimeoutError::Disconnected) => Err(ProbeError::Execution),
    }
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, ProbeError> {
    let mut output = Vec::new();
    reader
        .take(limit.try_into().unwrap_or(u64::MAX))
        .read_to_end(&mut output)
        .map_err(|_| ProbeError::Execution)?;
    Ok(output)
}

fn sensitive_environment_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "COOKIE",
        "AUTHORIZATION",
        "API_KEY",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "SESSION_KEY",
        "CREDENTIAL",
        "BEARER",
        "APIKEY",
        "NUGET_APIKEY",
    ]
    .iter()
    .any(|marker| upper.contains(marker))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use sysinfo::{Pid, ProcessesToUpdate, System};

    use super::Runner;
    use super::{ProbeError, receive_output, sensitive_environment_key};

    #[test]
    fn output_receive_never_waits_past_deadline() {
        let (_sender, receiver) = mpsc::sync_channel(1);
        assert_eq!(
            receive_output(&receiver, Instant::now() + Duration::from_millis(1), 1),
            Err(ProbeError::Timeout { limit_ms: 1 })
        );
    }

    #[test]
    fn secret_environment_names_are_removed_without_breaking_ssh_agent() {
        assert!(sensitive_environment_key("GITHUB_TOKEN"));
        assert!(sensitive_environment_key("AWS_SECRET_ACCESS_KEY"));
        assert!(!sensitive_environment_key("PATH"));
        assert!(!sensitive_environment_key("SSH_AUTH_SOCK"));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_descendant_process_tree() -> Result<(), &'static str> {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("descendant.pid");
        let pid_path = pid_file.to_str().unwrap();
        let started = Instant::now();
        let result = Runner.run_program(
            "sh",
            &["-c", "sleep 30 & echo $! > \"$1\"; wait", "sh", pid_path],
            250,
            1_024,
            true,
        );
        assert_eq!(result, Err(ProbeError::Timeout { limit_ms: 250 }));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_process_terminated(&pid_file)
    }

    #[cfg(unix)]
    #[test]
    fn parent_exit_pipe_holder_is_killed() -> Result<(), &'static str> {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("pipe-holder.pid");
        let pid_path = pid_file.to_str().unwrap();
        let result = Runner.run_program(
            "sh",
            &["-c", "sleep 30 & echo $! > \"$1\"", "sh", pid_path],
            250,
            1_024,
            true,
        );
        assert_eq!(result, Err(ProbeError::Timeout { limit_ms: 250 }));
        assert_process_terminated(&pid_file)
    }

    // PowerShell has to cold-start, launch a second PowerShell and write the child's id
    // before the runner's clock runs out; two seconds covered that on a developer machine
    // and not on a loaded CI runner, where both Windows tests raced the setup and panicked
    // reading a pid file that was never written. The budget is generous because what is
    // under test is that the timeout fires and the descendant dies, not how fast the shell
    // starts. The unix pair stays at 250ms -- sh has nothing to load.
    #[cfg(windows)]
    const WINDOWS_SETUP_BUDGET_MS: u64 = 15_000;

    #[cfg(windows)]
    #[test]
    fn timeout_terminates_descendant_process_tree() -> Result<(), &'static str> {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("descendant.pid");
        let pid_path = pid_file.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$child = Start-Process -FilePath 'powershell.exe' \
             -ArgumentList '-NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 30\"' \
             -NoNewWindow -PassThru; \
             Set-Content -NoNewline -LiteralPath '{pid_path}' -Value $child.Id; \
             Wait-Process -Id $child.Id"
        );
        let started = Instant::now();
        let result = Runner.run_program(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            WINDOWS_SETUP_BUDGET_MS,
            1_024,
            true,
        );
        assert_eq!(
            result,
            Err(ProbeError::Timeout {
                limit_ms: WINDOWS_SETUP_BUDGET_MS
            })
        );
        // Still a promptness check: the kill must follow the deadline, not trail it.
        assert!(started.elapsed() < Duration::from_millis(WINDOWS_SETUP_BUDGET_MS + 5_000));
        assert_process_terminated(&pid_file)
    }

    #[cfg(windows)]
    #[test]
    fn parent_exit_pipe_holder_is_killed() -> Result<(), &'static str> {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("pipe-holder.pid");
        let pid_path = pid_file.to_string_lossy().replace('\'', "''");
        let script = format!(
            "$child = Start-Process -FilePath 'powershell.exe' \
             -ArgumentList '-NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 30\"' \
             -NoNewWindow -PassThru; \
             Set-Content -NoNewline -LiteralPath '{pid_path}' -Value $child.Id"
        );
        let result = Runner.run_program(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            WINDOWS_SETUP_BUDGET_MS,
            1_024,
            true,
        );
        assert_eq!(
            result,
            Err(ProbeError::Timeout {
                limit_ms: WINDOWS_SETUP_BUDGET_MS
            })
        );
        assert_process_terminated(&pid_file)
    }

    fn assert_process_terminated(pid_file: &std::path::Path) -> Result<(), &'static str> {
        // A missing file means the script never reached the line that writes it, so the
        // run proved nothing about termination. Say that, rather than panicking on unwrap.
        let pid = fs::read_to_string(pid_file)
            .expect("child pid was never recorded; the setup did not finish before the timeout")
            .trim()
            .parse::<u32>()
            .unwrap();
        thread::sleep(Duration::from_millis(200));
        let mut system = System::new().map_err(
            |_| "sysinfo initialization failed; descendant termination could not be verified",
        )?;
        let pid = Pid::from_u32(pid);
        system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        assert!(
            system.process(pid).is_none(),
            "descendant process {pid} survived group termination"
        );
        Ok(())
    }
}
