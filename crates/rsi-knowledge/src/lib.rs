use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const KNOWLEDGE_SCHEMA_VERSION: &str = "rsi.knowledge.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProductFamily {
    Rust,
    Windows,
    Wsl,
    Apple,
    Nvidia,
    Amd,
    Intel,
    OpenAiCodex,
    AnthropicClaude,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OfficialSource {
    pub id: &'static str,
    pub title: &'static str,
    pub product: ProductFamily,
    pub url: &'static str,
    pub refresh_days: u32,
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeEntry {
    pub source_id: String,
    pub title: String,
    pub product: ProductFamily,
    pub official_url: String,
    pub retrieved_at: DateTime<Utc>,
    pub refresh_after: DateTime<Utc>,
    pub sha256: String,
    pub byte_count: usize,
    pub cache_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeCatalog {
    pub schema_version: String,
    pub entries: Vec<KnowledgeEntry>,
    pub failures: Vec<KnowledgeFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeFailure {
    pub source_id: String,
    pub reason_code: String,
}

#[derive(Debug, Error)]
pub enum KnowledgeError {
    #[error("unknown knowledge source id")]
    UnknownSource,
    #[error("knowledge cache path could not be created")]
    CacheCreate,
    #[error("official document request failed")]
    Request,
    #[error("official document exceeded its byte limit")]
    BodyLimit,
    #[error("official document cache write failed")]
    CacheWrite,
    #[error("content-addressed cache entry did not match its filename")]
    CacheMismatch,
    #[error("knowledge cache path was not a regular local file")]
    CacheUnsafe,
    #[error("knowledge client setup failed")]
    Client,
}

pub fn official_sources() -> &'static [OfficialSource] {
    &[
        OfficialSource {
            id: "rust-platform-support",
            title: "Rust platform support",
            product: ProductFamily::Rust,
            url: "https://doc.rust-lang.org/rustc/platform-support.html",
            refresh_days: 14,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "windows-system-information",
            title: "Windows system information",
            product: ProductFamily::Windows,
            url: "https://learn.microsoft.com/en-us/windows/win32/sysinfo/system-information",
            refresh_days: 30,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "windows-wsl",
            title: "Windows Subsystem for Linux",
            product: ProductFamily::Wsl,
            url: "https://learn.microsoft.com/en-us/windows/wsl/",
            refresh_days: 14,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "apple-metal",
            title: "Apple Metal",
            product: ProductFamily::Apple,
            url: "https://developer.apple.com/metal/",
            refresh_days: 30,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "nvidia-cuda",
            title: "NVIDIA CUDA documentation",
            product: ProductFamily::Nvidia,
            url: "https://docs.nvidia.com/cuda/",
            refresh_days: 14,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "amd-rocm",
            title: "AMD ROCm documentation",
            product: ProductFamily::Amd,
            url: "https://rocm.docs.amd.com/en/latest/",
            refresh_days: 14,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "intel-oneapi",
            title: "Intel oneAPI documentation",
            product: ProductFamily::Intel,
            url: "https://www.intel.com/content/www/us/en/developer/tools/oneapi/documentation.html",
            refresh_days: 30,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "openai-codex",
            title: "OpenAI Codex documentation",
            product: ProductFamily::OpenAiCodex,
            url: "https://learn.chatgpt.com/docs",
            refresh_days: 7,
            max_bytes: 2_000_000,
        },
        OfficialSource {
            id: "anthropic-claude-code",
            title: "Anthropic Claude Code documentation",
            product: ProductFamily::AnthropicClaude,
            url: "https://code.claude.com/docs/en/overview",
            refresh_days: 7,
            max_bytes: 2_000_000,
        },
    ]
}

pub fn sync(
    cache_dir: &Path,
    selected_ids: &BTreeSet<String>,
) -> Result<KnowledgeCatalog, KnowledgeError> {
    sync_at(cache_dir, selected_ids, Utc::now())
}

fn sync_at(
    cache_dir: &Path,
    selected_ids: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> Result<KnowledgeCatalog, KnowledgeError> {
    fs::create_dir_all(cache_dir).map_err(|_| KnowledgeError::CacheCreate)?;
    let cache_metadata =
        fs::symlink_metadata(cache_dir).map_err(|_| KnowledgeError::CacheCreate)?;
    if cache_metadata.file_type().is_symlink() || !cache_metadata.is_dir() {
        return Err(KnowledgeError::CacheUnsafe);
    }
    let sources = select_sources(selected_ids)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .redirect(Policy::none())
        .referer(false)
        .no_proxy()
        .user_agent(concat!("rsi-system-analyzer/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| KnowledgeError::Client)?;
    let mut entries = Vec::new();
    let mut failures = Vec::new();
    for source in sources {
        match fetch_source(&client, cache_dir, source, now) {
            Ok(entry) => entries.push(entry),
            Err(error) => failures.push(KnowledgeFailure {
                source_id: source.id.into(),
                reason_code: error.reason_code().into(),
            }),
        }
    }
    entries.sort_by(|left, right| left.source_id.cmp(&right.source_id));
    failures.sort_by(|left, right| left.source_id.cmp(&right.source_id));
    Ok(KnowledgeCatalog {
        schema_version: KNOWLEDGE_SCHEMA_VERSION.into(),
        entries,
        failures,
    })
}

impl KnowledgeError {
    fn reason_code(&self) -> &'static str {
        match self {
            Self::UnknownSource => "source_unknown",
            Self::CacheCreate => "cache_create_failed",
            Self::Request => "source_unavailable",
            Self::BodyLimit => "body_limit_exceeded",
            Self::CacheWrite => "cache_write_failed",
            Self::CacheMismatch | Self::CacheUnsafe => "cache_integrity_failed",
            Self::Client => "client_setup_failed",
        }
    }
}

fn select_sources(
    selected_ids: &BTreeSet<String>,
) -> Result<Vec<&'static OfficialSource>, KnowledgeError> {
    if selected_ids.is_empty() {
        return Ok(official_sources().iter().collect());
    }
    let known = official_sources()
        .iter()
        .map(|source| source.id)
        .collect::<BTreeSet<_>>();
    if selected_ids.iter().any(|id| !known.contains(id.as_str())) {
        return Err(KnowledgeError::UnknownSource);
    }
    Ok(official_sources()
        .iter()
        .filter(|source| selected_ids.contains(source.id))
        .collect())
}

fn fetch_source(
    client: &Client,
    cache_dir: &Path,
    source: &OfficialSource,
    now: DateTime<Utc>,
) -> Result<KnowledgeEntry, KnowledgeError> {
    let response = client
        .get(source.url)
        .send()
        .map_err(|_| KnowledgeError::Request)?;
    if !response.status().is_success() {
        return Err(KnowledgeError::Request);
    }
    if response
        .content_length()
        .is_some_and(|length| length > source.max_bytes as u64)
    {
        return Err(KnowledgeError::BodyLimit);
    }
    let mut body = Vec::new();
    response
        .take((source.max_bytes + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|_| KnowledgeError::Request)?;
    if body.len() > source.max_bytes {
        return Err(KnowledgeError::BodyLimit);
    }
    let sha256 = document_hash(&body);
    let file_name = format!("{sha256}.document");
    let cache_file = cache_dir.join(&file_name);
    write_content_addressed(&cache_file, &body)?;
    Ok(KnowledgeEntry {
        source_id: source.id.into(),
        title: source.title.into(),
        product: source.product,
        official_url: source.url.into(),
        retrieved_at: now,
        refresh_after: now + chrono::Duration::days(source.refresh_days.into()),
        sha256,
        byte_count: body.len(),
        cache_file: file_name,
    })
}

fn document_hash(body: &[u8]) -> String {
    Sha256::digest(body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn write_content_addressed(path: &PathBuf, body: &[u8]) -> Result<(), KnowledgeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(KnowledgeError::CacheUnsafe);
            }
            let existing = fs::read(path).map_err(|_| KnowledgeError::CacheMismatch)?;
            return if existing == body {
                Ok(())
            } else {
                Err(KnowledgeError::CacheMismatch)
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(KnowledgeError::CacheMismatch),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| KnowledgeError::CacheWrite)?;
    file.write_all(body).map_err(|_| KnowledgeError::CacheWrite)
}

#[cfg(test)]
mod tests {
    use super::{KnowledgeError, official_sources, select_sources, write_content_addressed};
    use std::collections::BTreeSet;

    #[test]
    fn document_hash_preserves_lowercase_zero_padded_sha256() {
        assert_eq!(
            super::document_hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            super::document_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn registry_is_https_unique_and_bounded() {
        let mut ids = BTreeSet::new();
        for source in official_sources() {
            assert!(source.url.starts_with("https://"));
            assert!(source.max_bytes <= 2_000_000);
            assert!(ids.insert(source.id));
        }
    }

    #[test]
    fn arbitrary_url_or_source_id_is_rejected_before_network_access() {
        let ids = ["https://example.invalid/secret".to_string()]
            .into_iter()
            .collect();
        assert!(matches!(
            select_sources(&ids),
            Err(KnowledgeError::UnknownSource)
        ));
    }

    #[test]
    fn cache_rejects_non_file_existing_entry() {
        let directory = tempfile::tempdir().unwrap();
        let entry = directory.path().join("entry.document");
        std::fs::create_dir(&entry).unwrap();
        assert!(matches!(
            write_content_addressed(&entry, b"content"),
            Err(KnowledgeError::CacheUnsafe)
        ));
    }
}
