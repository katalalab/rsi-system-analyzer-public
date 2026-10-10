# RSI System Analyzer

Fast, privacy-preserving system analysis for Windows, macOS, and Linux. The
Rust workspace separates collection, verification, deterministic optimization,
official-document synchronization, and sanitized audit classification.

## Current V1 capabilities

- OS, kernel, CPU architecture/model, logical cores, and memory
- top 20 processes as basename/category/CPU/memory summaries
- fixed CLI catalog presence and sanitized version output
- NVIDIA GPU model, VRAM, and utilization through a bounded typed probe
- MCP server names and enabled state for Codex, Claude, and Gemini
- application names from standard OS application directories
- explicit unsupported, timeout, denied, unreachable, stale, and error states
- deterministic findings and semantic JSON diff
- opaque verified snapshots required by optimization and AI layers
- explicit, allowlisted official-document synchronization
- sanitized configuration inventory journal output
- provider-neutral AI packets containing findings and architecture only
- bounded SSH fleet scans using validated local SSH config aliases
- OS-native probe containment using Unix process groups and Windows Job Objects

The analyzer does not collect raw command lines, environment values, PIDs, full
paths, configuration bodies, auth databases, SSH material, or raw logs. Every
string output is bounded and control-stripped; recognized credential, token,
user-path, IP-address, MAC-address, and hostname patterns are redacted before
the verified snapshot can be emitted. Fleet aliases are emitted only as stable
pseudonymous labels.

## Build and run

```text
cargo build --release -p rsi-cli
cargo run -p rsi-cli -- scan --fast --format json
cargo run -p rsi-cli -- scan --format markdown
cargo run -p rsi-cli -- verify snapshot.json
cargo run -p rsi-cli -- analyze snapshot.json
cargo run -p rsi-cli -- diff before.json after.json
cargo run -p rsi-cli -- ai-packet snapshot.json
cargo run -p rsi-cli -- journal snapshot.json
cargo run -p rsi-cli -- knowledge-sources
cargo run -p rsi-cli -- knowledge-sync --cache .rsi/knowledge --source rust-platform-support
cargo run -p rsi-cli -- fleet-scan fleet-constraints.json
```

`--fast` skips application enumeration. Normal analysis writes JSON only to
stdout. `knowledge-sync` is the sole networked command and writes only new,
content-addressed documents to the operator-selected cache. V1 has no apply,
elevate, install, remove, cleanup, service, or permission mutation command.

Snapshots currently use `rsi.snapshot.v2`. Fleet constraints remain local and
uncommitted; targets are SSH config aliases, never addresses or `user@host`
strings. A remote node must already have `rsi-scan` on its executable path.

## Development verification

After the locked dependencies are available, run the offline library checks:

```text
cargo fmt --all --check
cargo test --offline --locked --workspace --lib
```

These checks include synthetic process-name fixtures. The collector removes
path separators and normalizes colons before a process name reaches the
snapshot. The verifier still rejects path-like names.

Run the full verification in a disposable development or CI environment:

```text
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all
pwsh -NoProfile -File scripts/check-read-only-boundary.ps1
```

The full suite collects local machine facts, probes installed tools, and reads
local MCP metadata. Keep generated snapshots out of commits. On Unix, the
boundary check is `bash scripts/check-read-only-boundary.sh`. CI runs full
verification on Windows, macOS, and Ubuntu.

## Architecture

- `rsi-collect`: sanitized facts only
- `rsi-verify`: schema, freshness, completeness, privacy, and size gates
- `rsi-optimize`: deterministic findings from `VerifiedSnapshot` only
- `rsi-knowledge`: explicit synchronization from embedded official HTTPS URLs
- `rsi-journal`: categorized metadata without raw configuration bodies

See
[`docs/superpowers/specs/2026-07-27-layered-public-architecture.md`](docs/superpowers/specs/2026-07-27-layered-public-architecture.md)
for the dependency and public-release gates.

## Security and contributing

Read [`SECURITY.md`](SECURITY.md) before reporting a vulnerability or sharing
diagnostic artifacts. Contribution requirements are in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Recursive self-improvement boundary

V1 improves its proposal rules through reviewed source changes and fixtures.
It does not rewrite its running binary or execute AI-generated commands.
Deterministic findings, regression tests, a different-engine review, and
operator approval are required before a proposed rule is promoted.

- [Documentation](docs/)

- [License](LICENSE)

- [Repository hygiene](.gitignore)
