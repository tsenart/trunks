# Trunks

[![CI](https://github.com/tsenart/trunks/workflows/CI/badge.svg)](https://github.com/tsenart/trunks/actions)
[![crates.io](https://img.shields.io/crates/v/trunks.svg)](https://crates.io/crates/trunks)

Trunks is a versatile HTTP load testing tool written in Rust. It's the son of
[Vegeta](https://github.com/tsenart/vegeta), rewritten from scratch in Rust for
maximum performance. It's over 90,000!

![Trunks](assets/hero.png)

## Features

- Usable as both a **command line tool** and a **Rust library**
- CLI designed with **UNIX composability** in mind — pipe attack results into reports, plots, and transcoders
- **Avoids Coordinated Omission** — pacing is clock-based, not response-driven
- Extensive reporting: **text, JSON, histogram, HDR**
- **HTML latency plots** with LTTB downsampling
- **Dynamic worker scaling** — automatically spawns workers when the attack falls behind
- **HTTP/2**, **h2c** (HTTP/2 cleartext), **TLS** (rustls), **mTLS**
- **Unix domain socket** support
- **Custom DNS resolution** with configurable caching TTL
- **HTTP/HTTPS proxy** support with CONNECT tunneling
- **Prometheus metrics** exporter
- Multiple pacer types: **constant**, **linear**, **sine**
- **Graceful two-phase shutdown** (Ctrl+C drains in-flight, second Ctrl+C force exits)
- Three output encodings: **JSON**, **CSV**, **MessagePack**
- Redirect following with cross-origin credential stripping

## Install

### Pre-compiled binaries

Download pre-compiled binaries from the
[GitHub Releases](https://github.com/tsenart/trunks/releases) page.

### Homebrew (macOS)

```sh
brew install tsenart/tap/trunks
```

### Cargo

```sh
cargo install trunks-cli
```

### Source

```sh
git clone https://github.com/tsenart/trunks.git
cd trunks
cargo build --release
# Binary at ./target/release/trunks
```

## Usage

```
Usage: trunks <COMMAND>

Commands:
  attack  Execute an HTTP load test
  report  Generate reports from attack results
  plot    Generate HTML plot from attack results
  encode  Transcode attack results between encodings
```

### `trunks attack`

Execute an HTTP load test against one or more targets.

```
trunks attack [OPTIONS] --name <NAME>
```

#### Targeting

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | *required* | Attack name — used in reports and the `x-trunks-attack` request header |
| `--targets` | `stdin` | Targets file path. Use `stdin` to read from a pipe |
| `--format` | `http` | Target format: `http` or `json` |
| `--lazy` | `false` | Read targets lazily instead of pre-loading into memory |
| `--body` | | Request body file path (used as default body for all targets) |

#### Pacing

| Flag | Default | Description |
|------|---------|-------------|
| `--duration` | `0s` | Duration of the test. `0` = run forever (until Ctrl+C) |
| `--rate` | `0/1s` | Request rate as `freq[/duration]`. `0` or `infinity` = max rate. Examples: `50/1s`, `100`, `10/500ms` |
| `--pace` | `constant` | Pacer type: `constant`, `linear`, `sine` |
| `--slope` | `0.0` | Linear pacer slope in hits/s² increase per second |
| `--sine-period` | | Sine pacer period (e.g. `10s`, `1m`). Required for sine pacer |
| `--sine-amp` | | Sine pacer amplitude as rate (e.g. `50/1s`). Required for sine pacer |
| `--sine-offset` | `mean-up` | Sine pacer starting offset: `mean-up`, `peak`, `mean-down`, `trough` |

#### Workers

| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `num_cpus` | Initial number of workers |
| `--max-workers` | `0` | Maximum number of workers. `0` = no dynamic scaling. When set, workers are spawned automatically when the attack falls behind |

#### HTTP

| Flag | Default | Description |
|------|---------|-------------|
| `-H`, `--header` | | Default request headers (repeatable). Format: `"Key: Value"` |
| `--timeout` | `30s` | Timeout per request |
| `--keepalive` | `true` | Use persistent connections |
| `--connections` | `10000` | Max idle connections per target host |
| `--max-connections` | `0` | Maximum idle connections per host. `0` = unlimited |
| `--redirects` | `10` | Max redirects to follow. `-1` = don't follow but mark success |
| `--max-body` | `-1` | Max response body bytes to capture. `-1` = unlimited |
| `--http2` | `true` | Enable HTTP/2 |
| `--h2c` | `false` | Enable HTTP/2 cleartext (without TLS) |
| `--chunked` | `false` | Use chunked transfer encoding for request body |
| `--laddr` | | Local IP address to bind to |
| `--unix-socket` | | Connect via Unix domain socket |
| `--proxy-header` | | Custom proxy CONNECT headers (repeatable). Format: `"Key: Value"` |
| `--connect-to` | | Remap host connections (repeatable). Format: `"from=to1,to2,..."` |

#### TLS

| Flag | Default | Description |
|------|---------|-------------|
| `-k`, `--insecure` | `false` | Skip TLS certificate verification |
| `--root-certs` | | Custom root CA certificates, PEM file paths (repeatable) |
| `--cert` | | Client TLS certificate (PEM file path) |
| `--key` | | Client TLS private key (PEM file path) |
| `--session-tickets` | `true` | Enable TLS session resumption |

#### DNS

| Flag | Default | Description |
|------|---------|-------------|
| `--dns-ttl` | | DNS cache TTL. `0s` = cache forever, omit = no cache |
| `--resolvers` | | Custom DNS resolver addresses (repeatable). Format: `"ip[:port]"` |

#### Output

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `stdout` | Output file path |
| `--encode` | `json` | Output encoding: `json`, `csv`, `msgpack` |

#### Prometheus

| Flag | Default | Description |
|------|---------|-------------|
| `--prometheus-addr` | | Start a Prometheus metrics endpoint at this address (e.g. `0.0.0.0:8880`) |

### `trunks report`

Generate aggregate reports from attack results. Reads results from stdin or files.

```
trunks report [OPTIONS] [FILES]...
```

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | `text` | Report type: `text`, `json`, `hist`, `hdrplot` |
| `--output` | `stdout` | Output file path |
| `--buckets` | | Histogram bucket boundaries for `hist` report. Format: `"[0,1ms,10ms,100ms]"` |
| `--every` | | Streaming report interval (e.g. `1s`, `5s`). Outputs periodic reports while reading |

The input encoding (JSON, CSV, or MessagePack) is auto-detected.

#### Report types

##### `text`
Human-readable summary with latency percentiles, throughput, status codes, and errors:
```
Requests      [total, rate, throughput]  250, 50.20, 49.89
Duration      [total, attack, wait]     5.012s, 4.98s, 32ms
Latencies     [min, mean, 50, 90, 95, 99, max]  25ms, 32ms, 30ms, 42ms, 48ms, 55ms, 89ms
Bytes In      [total, mean]             62500, 250.00
Bytes Out     [total, mean]             0, 0.00
Success       [ratio]                   100.00%
Status Codes  [code:count]              200:250
Error Set:
```

##### `json`
Machine-readable JSON with the same fields as `text`. Latencies are in nanoseconds.

##### `hist`
Bucketed latency histogram. Requires `--buckets`:
```
Bucket           #     %       Histogram
[0,      1ms]    0     0.00%
[1ms,    10ms]   5     2.00%   ##
[10ms,   100ms]  240   96.00%  ########################################################################
[100ms,  +Inf]   5     2.00%   ##
```

##### `hdrplot`
Logarithmic percentile distribution compatible with
[HDR Histogram Plotter](https://hdrhistogram.github.io/HdrHistogram/plotFiles.html).

### `trunks plot`

Generate an interactive HTML latency plot from attack results.

```
trunks plot [OPTIONS] [FILES]...
```

| Flag | Default | Description |
|------|---------|-------------|
| `--title` | `Vegeta Plot` | Plot title |
| `--output` | `stdout` | Output file path |
| `--threshold` | `4000` | Maximum points per series (LTTB downsampling threshold) |

The plot features:
- Dark theme with scatter plot visualization
- Per-attack series with separate OK/ERROR coloring
- Log/linear scale toggle
- LTTB downsampling for large datasets

### `trunks encode`

Transcode attack results between encoding formats. Input encoding is auto-detected.

```
trunks encode [OPTIONS] [FILES]...
```

| Flag | Default | Description |
|------|---------|-------------|
| `--to` | `json` | Output encoding: `json`, `csv`, `msgpack` |
| `--output` | `stdout` | Output file path |

## Target formats

### `http` format

A simple line-based format compatible with vegeta. Each target is a method and URL,
optionally followed by headers and a body reference:

```
GET http://localhost:8080/
POST http://localhost:8080/api
Content-Type: application/json
@body.json
```

Lines starting with `#` are treated as comments. Blank lines separate targets.

### `json` format

One JSON object per line:

```json
{"method": "GET", "url": "http://localhost:8080/", "headers": {}, "body": ""}
{"method": "POST", "url": "http://localhost:8080/api", "headers": {"Content-Type": ["application/json"]}, "body": "eyJrZXkiOiJ2YWx1ZSJ9"}
```

The `body` field is base64-encoded.

## Examples

### Basic load test

```sh
echo "GET http://localhost:8080/" | trunks attack --name test --rate 50/1s --duration 5s | trunks report
```

### Save results to file, then report

```sh
echo "GET http://localhost:8080/" | trunks attack --name test --rate 100/1s --duration 30s > results.json
trunks report < results.json
trunks report --type json < results.json > metrics.json
```

### Generate an HTML latency plot

```sh
cat results.json | trunks plot --title "My Load Test" > plot.html
```

### Histogram report

```sh
cat results.json | trunks report --type "hist" --buckets "[0,5ms,10ms,25ms,50ms,100ms]"
```

### Streaming periodic reports

```sh
echo "GET http://localhost:8080/" | trunks attack --name test --rate 50/1s --duration 60s | trunks report --every 5s
```

### Max rate (unconstrained)

```sh
echo "GET http://localhost:8080/" | trunks attack --name test --rate 0 --duration 10s | trunks report
```

### Linear ramp-up

```sh
echo "GET http://localhost:8080/" | trunks attack --name ramp \
  --rate 10/1s --pace linear --slope 5 --duration 30s | trunks report
```

### Sine wave pattern

```sh
echo "GET http://localhost:8080/" | trunks attack --name sine \
  --rate 100/1s --pace sine --sine-amp 50/1s --sine-period 10s \
  --duration 60s | trunks report
```

### Multiple targets with custom headers

```sh
trunks attack --name api --rate 200/1s --duration 10s \
  -H "Authorization: Bearer token123" \
  -H "Content-Type: application/json" \
  --targets targets.txt | trunks report
```

### Unix domain socket

```sh
echo "GET http://localhost/" | trunks attack --name uds \
  --unix-socket /var/run/app.sock --rate 100/1s --duration 5s | trunks report
```

### mTLS

```sh
echo "GET https://secure.example.com/" | trunks attack --name mtls \
  --cert client.pem --key client-key.pem --root-certs ca.pem \
  --rate 50/1s --duration 10s | trunks report
```

### Transcode to CSV

```sh
cat results.json | trunks encode --to csv > results.csv
```

### Prometheus metrics

```sh
echo "GET http://localhost:8080/" | trunks attack --name test \
  --rate 100/1s --duration 60s \
  --prometheus-addr 0.0.0.0:8880 | trunks report
```

Then scrape `http://localhost:8880/metrics` with Prometheus.

## Distributed attacks

Like vegeta, trunks' output is newline-delimited JSON by default, making it trivial to
combine results from multiple attack machines:

```sh
# On machine 1
echo "GET http://target/" | trunks attack --name dist --rate 500/1s --duration 60s > results1.json

# On machine 2
echo "GET http://target/" | trunks attack --name dist --rate 500/1s --duration 60s > results2.json

# Combine and report (on any machine)
cat results1.json results2.json | trunks report
cat results1.json results2.json | trunks plot --title "Distributed 1000 req/s" > plot.html
```

The `report` and `plot` commands merge results from multiple files or concatenated
streams — use the same `--name` across machines for unified series in plots.

## Vegeta compatibility

Trunks' JSON output format is compatible with vegeta's JSON encoding, making migration
straightforward. The `http` target format is also compatible. If you're already using
vegeta, you can switch to trunks and continue using your existing target files and
reporting pipelines.

## Prometheus support

When `--prometheus-addr` is specified, trunks starts an HTTP server exposing metrics
at `/metrics` in Prometheus exposition format.

### Exported metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `request_seconds` | histogram | `method`, `url`, `status` | Request latency in seconds |
| `request_bytes_in` | counter | `method`, `url`, `status` | Total bytes received |
| `request_bytes_out` | counter | `method`, `url`, `status` | Total bytes sent |
| `request_fail_count` | counter | `method`, `url`, `status`, `message` | Count of failed requests |

Histogram buckets: 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s.

## Library usage

Add the `trunks` crate to your `Cargo.toml`:

```toml
[dependencies]
trunks = "0.1"
```

```rust
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use trunks::{Attack, ConstantPacer, Target, Targets};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let target = Arc::new(Target {
        method: "GET".parse()?,
        url: "http://localhost:8080/".parse()?,
        ..Default::default()
    });

    let targets: Targets<tokio::io::Empty> = vec![target].into();
    let stop = CancellationToken::new();

    let client = hyper::Client::new();
    let atk = Attack {
        name: "example".to_string(),
        client,
        duration: Duration::from_secs(5),
        pacer: Arc::new(ConstantPacer {
            freq: 50,
            per: Duration::from_secs(1),
        }),
        targets: Arc::new(Mutex::new(targets)),
        workers: 4,
        max_workers: 16,
        timeout: Duration::from_secs(30),
        max_body: -1,
        redirects: 10,
        chunked: false,
        stop,
    };

    let mut hits = atk.run();
    while let Some(result) = hits.next().await {
        match result {
            Ok(hit) => println!("{}: {} {}",
                hit.seq, hit.code, hit.latency.as_millis()),
            Err(e) => eprintln!("error: {}", e),
        }
    }

    Ok(())
}
```

## Limitations

### System resource limits

On many systems, the default number of open file descriptors is too low for high-rate
load testing. Each connection requires a file descriptor, so you may need to increase
the limit:

```sh
ulimit -n 65535
```

On macOS:

```sh
sudo launchctl limit maxfiles 65535 200000
```

### Timing precision

On Unix systems, trunks uses a minimum sleep threshold of 1ms before switching to
a spin loop for sub-millisecond pacing. On Windows, this threshold is 16ms due to
the platform's timer resolution.

## License

```
Copyright 2023 Tomás Senart.

Licensed under the Apache License, Version 2.0.
See LICENSE file for details.
```
