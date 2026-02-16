# Trunks — Agent Guidelines

## Project

Trunks is an HTTP load testing tool written in Rust — the son of [vegeta](https://github.com/tsenart/vegeta). ~5800 lines across two workspace crates.

## Workspace Layout

```
trunks/
├── Cargo.toml          # Workspace root (edition 2021, MSRV 1.70)
├── lib/                # trunks library crate (published to crates.io)
│   └── src/
│       ├── lib.rs      # Public API re-exports
│       ├── attack.rs   # Attack engine: builder, workers, hit loop, body streaming
│       ├── hit.rs      # Hit struct, codecs (JSON/CSV/MsgPack), serialization
│       ├── target.rs   # Target parsing (http/json formats), TargetRead trait
│       ├── metrics.rs  # Metrics aggregation, percentiles via t-digest
│       ├── pacer.rs    # Rate control: ConstantPacer, LinearPacer, SinePacer
│       ├── resolver.rs # Custom async DNS resolver with caching
│       ├── proxy.rs    # HTTP/HTTPS proxy with CONNECT tunneling
│       ├── reporters.rs# Text/JSON/histogram/HDR report generators
│       ├── prometheus.rs# Prometheus exposition format
│       ├── plot.rs     # HTML latency plots with LTTB downsampling
│       ├── lttb.rs     # Largest-Triangle-Three-Buckets algorithm
│       └── unix.rs     # Unix domain socket connector
├── cli/                # trunks-cli binary crate
│   └── src/
│       ├── main.rs     # Clap subcommands: attack, report, plot, encode
│       ├── attack.rs   # CLI attack command, TLS/proxy/connector setup
│       ├── report.rs   # CLI report command
│       ├── plot.rs     # CLI plot command
│       └── encode.rs   # CLI encode/transcode command
└── REVIEW.md           # Code review tracker (17 issues, 14 fixed, 3 deferred)
```

## Architecture

```
CLI (clap)
  └─ Attack::builder(name, client, pacer, targets).build()
       ├─ Pacer (clock-based, avoids coordinated omission)
       ├─ Targets (Static round-robin or Lazy via Box<dyn TargetRead>)
       ├─ Workers (dynamic scaling via bounded channel backpressure)
       └─ Hit (result struct) → Stream<Item = Result<Hit>>
              └─ Codecs: JsonCodec / CsvCodec / MsgpackCodec
                    └─ Report / Plot / Encode (downstream consumers)
```

## Key Design Decisions

- **Attack fields are private.** Construct via `Attack::builder(name, client, pacer, targets)` with fluent setters. Defaults: workers=num_cpus, timeout=30s, max_body=-1, redirects=10.
- **Targets is not generic over R.** `Targets::Lazy` stores `Box<dyn TargetRead + Send>`. This erases the reader type from `Attack<C, P>`.
- **Codecs are NOT traits.** `JsonCodec`, `CsvCodec`, `MsgpackCodec` have inherent `async fn encode/decode` methods. No `dyn Codec`, no `async_trait` boxing.
- **TargetRead IS a trait** (with `#[async_trait]`) because it's used as `dyn TargetRead` in `Targets::Lazy`.
- **DNS resolution is fully async** — `tokio::net::UdpSocket`, no `spawn_blocking`.
- **Body streaming** — response bodies are read chunk-by-chunk up to `max_body` bytes, not fully materialized.
- **Body file caching** — `@body_path` files are read once and cached in a `HashMap<String, Bytes>`.
- **Status codes are `BTreeMap<u16, u64>`** with a custom serializer for JSON string keys.
- **Metrics.close() is idempotent** — guarded by a `closed: bool` field.

## Conventions

- **No `unsafe` code** — `#![deny(unsafe_code)]` in lib.
- **Error handling** — `eyre::Result` throughout. No panics in library code except explicit `unwrap_or` saturation paths.
- **Serialization** — `serde` with custom modules for durations (`duration_as_nanos`), bytes (`bytes_as_base64`), and status codes.
- **Tests** — 90 tests in `lib/`, 0 in `cli/`. Run with `cargo test`. All tests use `#[tokio::test]` for async tests.
- **Formatting** — `cargo fmt`. No clippy overrides except `#[allow(clippy::too_many_arguments)]` on the internal `attack()` function.
- **MSRV** — `rust-version = "1.70"` in workspace. Don't use features requiring newer Rust without bumping this.

## Build & Test

```sh
cargo build              # Debug build
cargo build --release    # Release (LTO=fat, codegen-units=1)
cargo test --all         # Run all 90 tests
cargo fmt --check        # Verify formatting
cargo clippy -- -D warnings  # Lint (CI runs this, must pass)
```

## CI & Release

CI runs on every push/PR via `.github/workflows/ci.yml`. Three jobs:

1. **QA** — `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`. Runs on all pushes and PRs.
2. **Build** — cross-compiles 7 targets (only on `v*.*.*` tags). Uploads `.tar.gz`/`.zip` artifacts.
3. **Release** — creates a **draft** GitHub Release with auto-generated notes, checksums, and all build artifacts.
4. **Publish** — publishes `trunks` (lib) then `trunks-cli` to crates.io via OIDC token.

### Build targets

| Target | OS | Cross |
|--------|----|-------|
| `x86_64-unknown-linux-gnu` | ubuntu | no |
| `x86_64-unknown-linux-musl` | ubuntu | yes |
| `aarch64-unknown-linux-gnu` | ubuntu | yes |
| `aarch64-unknown-linux-musl` | ubuntu | yes |
| `x86_64-apple-darwin` | macos | no |
| `aarch64-apple-darwin` | macos | no |
| `x86_64-pc-windows-msvc` | windows | no |

### Release process

```sh
# 1. Bump version in lib/Cargo.toml, cli/Cargo.toml, cli's trunks dep
# 2. Update README.md crate version if needed
# 3. Commit, push to main
# 4. Tag and push:
git tag v0.X.Y && git push origin v0.X.Y
# 5. CI builds all targets, creates draft release, publishes to crates.io
# 6. Go to GitHub Releases and un-draft the release
```

**Versioning:** use semver. Bump minor for breaking API changes (pub types, builder API, trait changes). The lib crate is published to crates.io — breaking changes matter.

## Common Pitfalls

- **Don't add `async_trait` to new traits** unless they need dynamic dispatch (`dyn Trait`). Use inherent async methods or (if MSRV is bumped to 1.75+) RPITIT.
- **Don't use `as u32` or `as u64` for narrowing casts.** Use `u64::try_from().unwrap_or()` for saturation or `div_f64` for safe division.
- **Don't use `std::net::UdpSocket` or other blocking I/O** in async code. Use `tokio::net` equivalents.
- **Don't allocate before validating untrusted lengths** (e.g., msgpack frame length). Check against a cap first.
- **Don't construct `Attack` with struct literals** — fields are private. Use the builder.
- **`Targets` is not `Debug`-derivable** (contains `dyn TargetRead`). It has a manual `Debug` impl.
