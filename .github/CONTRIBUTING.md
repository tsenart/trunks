# Contributing to Trunks

PRs welcome! Here's how to get started.

## Build

```sh
cargo build --release
```

## Test

Tests use an echo server (`echosrv`) that reflects requests back to the caller.
The test harness starts it automatically — just run:

```sh
cargo test --all
```

## Run

Trunks reads targets from stdin, one per line:

```sh
echo "GET http://localhost:8080/" | trunks attack --duration 10s --rate 50 | trunks report
```

## Code style

Before submitting a PR, please run:

```sh
cargo fmt --all
cargo clippy --all -- -D warnings
```
