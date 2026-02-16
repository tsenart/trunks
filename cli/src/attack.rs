use clap::Args;
use duration_string::DurationString;
use eyre::Result;
use futures::StreamExt as _;
use hyper::client::HttpConnector;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Response, Server};

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, BufWriter, ReadBuf,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use trunks::{
    Attack, ConstantPacer, CsvCodec, JsonCodec, LinearPacer, MsgpackCodec, Pacer,
    PrometheusMetrics, SinePacer, TargetDefaults, TargetRead, TargetReader, Targets,
};

#[derive(Args, Debug)]
pub struct Opts {
    /// Attack name
    #[clap(long)]
    name: String,

    /// Targets file
    #[clap(long, default_value = "stdin")]
    targets: String,

    /// Targets format
    #[clap(long, default_value = "http")]
    format: String,

    /// Output file
    #[clap(long, default_value = "stdout")]
    output: String,

    /// Read targets lazily
    #[clap(long, default_value = "false")]
    lazy: bool,

    /// Duration of the test [0 = forever]
    #[clap(long, default_value = "0s")]
    duration: DurationString,

    /// Number of requests per time unit [default: 0/1s]
    /// Format: freq[/duration] e.g. "100", "100/1s", "50/500ms", "0" (max rate), "infinity"
    #[clap(long, default_value = "0/1s")]
    rate: String,

    /// Pacer type: constant, linear, sine [default: constant]
    #[clap(long, default_value = "constant")]
    pace: String,

    /// Linear pacer slope (hits/s² increase per second)
    #[clap(long, default_value_t = 0.0)]
    slope: f64,

    /// Sine pacer period (e.g. "10s", "1m")
    #[clap(long)]
    sine_period: Option<DurationString>,

    /// Sine pacer amplitude as rate (e.g. "50/1s")
    #[clap(long)]
    sine_amp: Option<String>,

    /// Sine pacer starting offset: mean-up, peak, mean-down, trough [default: mean-up]
    #[clap(long, default_value = "mean-up")]
    sine_offset: String,

    /// Initial number of workers
    #[clap(long, default_value_t = num_cpus::get())]
    workers: usize,

    /// Maximum number of workers
    #[clap(long, default_value_t = 0)]
    max_workers: usize,

    /// Timeout per request
    #[clap(long, default_value = "30s")]
    timeout: DurationString,

    /// Default request headers (repeatable), format "Key: Value"
    #[clap(long = "header", short = 'H')]
    headers: Vec<String>,

    /// Request body file path
    #[clap(long)]
    body: Option<String>,

    /// Skip TLS certificate verification
    #[clap(long, short = 'k', default_value_t = false)]
    insecure: bool,

    /// Custom root CA certificates (PEM file paths, repeatable)
    #[clap(long = "root-certs")]
    root_certs: Vec<String>,

    /// Client TLS certificate (PEM file path)
    #[clap(long)]
    cert: Option<String>,

    /// Client TLS private key (PEM file path)
    #[clap(long)]
    key: Option<String>,

    /// Use persistent connections
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    keepalive: bool,

    /// Max idle connections per target host
    #[clap(long, default_value_t = 10000)]
    connections: usize,

    /// Max response body bytes to capture (-1 = unlimited)
    #[clap(long, default_value_t = -1)]
    max_body: i64,

    /// Maximum number of redirects to follow. -1 = don't follow but mark success
    #[clap(long, default_value_t = 10)]
    redirects: i32,

    /// Output encoding format (json, csv, msgpack)
    #[clap(long, default_value = "json")]
    encode: String,

    /// Enable HTTP/2
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    http2: bool,

    /// Local IP address to bind to
    #[clap(long)]
    laddr: Option<String>,

    /// Maximum number of idle connections per host (0 = unlimited)
    #[clap(long, default_value_t = 0)]
    max_connections: usize,

    /// Connect via Unix domain socket
    #[cfg(unix)]
    #[clap(long)]
    unix_socket: Option<String>,

    /// Enable HTTP/2 cleartext (h2c) without TLS
    #[clap(long, default_value_t = false)]
    h2c: bool,

    /// Use chunked transfer encoding for request body
    #[clap(long, default_value_t = false)]
    chunked: bool,

    /// Custom proxy CONNECT headers (repeatable), format "Key: Value"
    #[clap(long = "proxy-header")]
    proxy_headers: Vec<String>,

    /// Enable TLS session resumption (enabled by default)
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    session_tickets: bool,

    /// Prometheus metrics endpoint address (e.g. "0.0.0.0:8880")
    #[clap(long)]
    prometheus_addr: Option<String>,

    /// Remap host connections (repeatable), format "from=to1,to2,..."
    #[clap(long = "connect-to")]
    connect_to: Vec<String>,

    /// DNS cache TTL (0s = cache forever, omit = no cache)
    #[clap(long = "dns-ttl")]
    dns_ttl: Option<DurationString>,

    /// Custom DNS resolver addresses (repeatable), format "ip[:port]"
    #[clap(long = "resolvers")]
    resolvers: Vec<String>,
}

async fn start_prometheus_server(addr: &str, metrics: Arc<Mutex<PrometheusMetrics>>) -> Result<()> {
    let addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| eyre::eyre!("invalid prometheus address: {}", e))?;
    let metrics = metrics.clone();

    let make_svc = make_service_fn(move |_| {
        let metrics = metrics.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |_req| {
                let metrics = metrics.clone();
                async move {
                    let m = metrics.lock().await;
                    let body = m.render();
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .header("Content-Type", "text/plain; version=0.0.4")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                }
            }))
        }
    });

    tokio::spawn(async move {
        if let Err(e) = Server::bind(&addr).serve(make_svc).await {
            eprintln!("Prometheus server error: {}", e);
        }
    });

    Ok(())
}

pub async fn attack(opts: &Opts) -> Result<()> {
    let base_rate = parse_rate(&opts.rate)?;

    let pacer: Box<dyn Pacer> = match opts.pace.as_str() {
        "constant" => Box::new(base_rate),
        "linear" => Box::new(LinearPacer {
            start_at: base_rate,
            slope: opts.slope,
        }),
        "sine" => {
            let period: Duration = (*opts
                .sine_period
                .as_ref()
                .ok_or_else(|| eyre::eyre!("--sine-period is required for sine pacer"))?)
            .into();
            let amp = match &opts.sine_amp {
                Some(s) => parse_rate(s)?,
                None => eyre::bail!("--sine-amp is required for sine pacer"),
            };
            let start_at = match opts.sine_offset.as_str() {
                "mean-up" => trunks::MEAN_UP,
                "peak" => trunks::PEAK,
                "mean-down" => trunks::MEAN_DOWN,
                "trough" => trunks::TROUGH,
                other => other
                    .parse::<f64>()
                    .map_err(|_| eyre::eyre!("invalid --sine-offset: {}", other))?,
            };
            Box::new(SinePacer {
                period,
                mean: base_rate,
                amp,
                start_at,
            })
        }
        other => eyre::bail!(
            "unknown --pace type: {} (expected constant, linear, sine)",
            other
        ),
    };

    let is_max_rate = pacer.rate(Duration::ZERO) == 0.0;
    if opts.max_workers == 0 && is_max_rate {
        eyre::bail!("-max-workers must be set when -rate is 0");
    }

    // Parse --header flags into HashMap<String, Vec<String>>
    let headers = if opts.headers.is_empty() {
        None
    } else {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for h in &opts.headers {
            let (k, v) = h.split_once(':').ok_or_else(|| {
                eyre::eyre!("invalid header format, expected 'Key: Value': {}", h)
            })?;
            map.entry(k.trim().to_string())
                .or_default()
                .push(v.trim().to_string());
        }
        Some(map)
    };

    // Read --body file
    let body = match &opts.body {
        Some(path) => Some(hyper::body::Bytes::from(tokio::fs::read(path).await?)),
        None => None,
    };

    let input = Input::from_filename(&opts.targets).await?;
    let mut output = Output::from_filename(&opts.output).await?;

    let mut target_reader =
        TargetReader::new(&opts.format, input, TargetDefaults { body, headers })?;

    let targets = if opts.lazy {
        Targets::Lazy(Box::new(target_reader))
    } else {
        let mut targets: Vec<_> = Vec::new();
        while let Ok(target) = target_reader.decode().await {
            targets.push(target);
        }
        Targets::from(targets)
    };

    // Parse --connect-to mappings
    let connect_to_map: HashMap<String, Vec<String>> = opts
        .connect_to
        .iter()
        .filter_map(|s| {
            let (from, to) = s.split_once('=')?;
            Some((
                from.to_string(),
                to.split(',').map(|s| s.trim().to_string()).collect(),
            ))
        })
        .collect();
    let dns_ttl = opts.dns_ttl.as_ref().map(|d| -> Duration { (*d).into() });
    let resolver = trunks::TrunksResolver::new(connect_to_map, dns_ttl, opts.resolvers.clone());

    // Parse --proxy-header flags into HashMap<String, String>
    let proxy_headers: std::collections::HashMap<String, String> = opts
        .proxy_headers
        .iter()
        .filter_map(|h| {
            let (k, v) = h.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let proxy_config = trunks::ProxyConfig::from_env(proxy_headers);
    if proxy_config.is_enabled() {
        if let Some(ref p) = proxy_config.http_proxy {
            eprintln!("Using HTTP proxy: {}", p);
        }
        if let Some(ref p) = proxy_config.https_proxy {
            eprintln!("Using HTTPS proxy: {}", p);
        }
    }

    // Build HTTP connector with custom resolver and local address binding
    let mut http = HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    if let Some(ref addr) = opts.laddr {
        let ip: std::net::IpAddr = addr
            .parse()
            .map_err(|_| eyre::eyre!("invalid local address: {}", addr))?;
        http.set_local_address(Some(ip));
    }

    // Wrap with proxy connector (transparent pass-through when no proxy is configured)
    let http = trunks::ProxyConnector::new(http, proxy_config.clone());

    // Build HTTP client pool settings
    let mut client_builder = Client::builder();
    let pool_size = if opts.max_connections > 0 {
        opts.max_connections
    } else {
        opts.connections
    };
    client_builder.pool_max_idle_per_host(pool_size);
    if !opts.keepalive {
        client_builder.pool_idle_timeout(Duration::ZERO);
    }

    let stop = CancellationToken::new();
    let targets = Arc::new(Mutex::new(targets));
    let pacer = Arc::new(pacer);

    #[cfg(unix)]
    if let Some(ref socket_path) = opts.unix_socket {
        // Unix domain socket: bypass DNS/TCP, connect directly to socket
        let connector = trunks::UnixConnector::new(socket_path);
        let client = client_builder.build::<_, hyper::Body>(connector);

        let atk = Attack::builder(opts.name.as_str(), client, pacer, targets)
            .duration(opts.duration.into())
            .workers(opts.workers)
            .max_workers(opts.max_workers)
            .timeout(opts.timeout.into())
            .max_body(opts.max_body)
            .redirects(opts.redirects)
            .chunked(opts.chunked)
            .stop(stop.clone())
            .build();

        return run_attack(atk, stop, opts, &mut output).await;
    }

    if opts.h2c {
        // h2c: HTTP/2 cleartext — no TLS wrapper, force HTTP/2
        let client = client_builder
            .http2_only(true)
            .build::<_, hyper::Body>(http);

        let atk = Attack::builder(opts.name.as_str(), client, pacer, targets)
            .duration(opts.duration.into())
            .workers(opts.workers)
            .max_workers(opts.max_workers)
            .timeout(opts.timeout.into())
            .max_body(opts.max_body)
            .redirects(opts.redirects)
            .chunked(opts.chunked)
            .stop(stop.clone())
            .build();

        run_attack(atk, stop, opts, &mut output).await
    } else {
        // Build TLS config
        let client_auth = match (&opts.cert, &opts.key) {
            (Some(cert_path), Some(key_path)) => {
                let certs = load_certs(cert_path)?;
                let key = load_key(key_path)?;
                ClientAuth::Cert(certs, key)
            }
            (None, None) => ClientAuth::None,
            _ => eyre::bail!("--cert and --key must both be provided for mTLS"),
        };

        let tls_config = build_tls_config(
            opts.insecure,
            &opts.root_certs,
            client_auth,
            opts.session_tickets,
        )?;

        let builder = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http();

        let https = if opts.http2 {
            builder.enable_http1().enable_http2().wrap_connector(http)
        } else {
            builder.enable_http1().wrap_connector(http)
        };

        let client = client_builder.build::<_, hyper::Body>(https);

        let atk = Attack::builder(opts.name.as_str(), client, pacer, targets)
            .duration(opts.duration.into())
            .workers(opts.workers)
            .max_workers(opts.max_workers)
            .timeout(opts.timeout.into())
            .max_body(opts.max_body)
            .redirects(opts.redirects)
            .chunked(opts.chunked)
            .stop(stop.clone())
            .build();

        run_attack(atk, stop, opts, &mut output).await
    }
}

async fn run_attack<C, P>(
    atk: Attack<C, P>,
    stop: CancellationToken,
    opts: &Opts,
    output: &mut Output,
) -> Result<()>
where
    C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    P: trunks::Pacer + 'static,
{
    let prom_metrics = Arc::new(Mutex::new(PrometheusMetrics::default()));
    if let Some(ref addr) = opts.prometheus_addr {
        start_prometheus_server(addr, prom_metrics.clone()).await?;
        eprintln!("Prometheus metrics at http://{}/metrics", addr);
    }

    let mut hits = atk.run();

    let encode_format = opts.encode.as_str();

    // Two-phase graceful stop (vegeta-style):
    // First Ctrl+C: stop sending new requests, drain in-flight workers
    // Second Ctrl+C: exit immediately
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        eprintln!("\nGraceful shutdown... (press Ctrl+C again to force exit)");
        stop.cancel();

        tokio::signal::ctrl_c().await.ok();
        eprintln!("\nForced exit");
        std::process::exit(0);
    });

    while let Some(result) = hits.next().await {
        match result {
            Ok(hit) => {
                if opts.prometheus_addr.is_some() {
                    let mut pm = prom_metrics.lock().await;
                    pm.update(&hit);
                }
                let res = match encode_format {
                    "csv" => CsvCodec.encode(output, &hit).await,
                    "msgpack" => MsgpackCodec.encode(output, &hit).await,
                    "json" => JsonCodec.encode(output, &hit).await,
                    other => {
                        eprintln!("Error: unknown encoding: {}", other);
                        return Ok(());
                    }
                };
                if let Err(err) = res {
                    eprintln!("Error: {}", err);
                }
            }
            Err(err) => {
                eprintln!("Error: {}", err);
            }
        }
    }

    Ok(())
}

/// Parse a rate string in the format "freq[/duration]" or "infinity".
/// Examples: "100" → 100/1s, "100/1s", "50/500ms", "0" → max rate, "infinity" → max rate
fn parse_rate(s: &str) -> Result<ConstantPacer> {
    if s.eq_ignore_ascii_case("infinity") {
        return Ok(ConstantPacer {
            freq: 0,
            per: Duration::from_secs(1),
        });
    }

    let parts: Vec<&str> = s.splitn(2, '/').collect();
    let freq: u64 = parts[0].parse().map_err(|_| {
        eyre::eyre!(
            "-rate format {:?} doesn't match the \"freq/duration\" format (i.e. 50/1s)",
            s
        )
    })?;

    if freq == 0 {
        return Ok(ConstantPacer {
            freq: 0,
            per: Duration::from_secs(1),
        });
    }

    let per = if parts.len() == 2 {
        let dur_str = parts[1];
        // Allow bare units like "s", "ms" → prepend "1"
        let dur_str = match dur_str {
            "ns" | "us" | "µs" | "ms" | "s" | "m" | "h" => format!("1{}", dur_str),
            _ => dur_str.to_string(),
        };
        let ds: DurationString = dur_str
            .parse()
            .map_err(|_| eyre::eyre!("invalid duration in rate: {:?}", parts[1]))?;
        ds.into()
    } else {
        Duration::from_secs(1)
    };

    Ok(ConstantPacer { freq, per })
}

#[derive(Debug)]
pub enum Input {
    Stdin(BufReader<tokio::io::Stdin>),
    File(BufReader<File>),
}

impl Input {
    pub async fn from_filename(name: &str) -> Result<Self> {
        match name {
            "stdin" => Ok(Input::Stdin(BufReader::new(tokio::io::stdin()))),
            _ => {
                let f = File::open(name).await?;
                Ok(Input::File(BufReader::new(f)))
            }
        }
    }

    /// Detect the encoding format by peeking at the first byte.
    /// Returns None if the input is empty.
    pub async fn detect_format(&mut self) -> std::io::Result<Option<&'static str>> {
        let buf = self.fill_buf().await?;
        if buf.is_empty() {
            return Ok(None);
        }
        let first = buf[0];
        Ok(Some(if first == b'{' {
            "json"
        } else if first.is_ascii_graphic() {
            "csv"
        } else {
            "msgpack"
        }))
    }
}

impl AsyncRead for Input {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Input::Stdin(reader) => Pin::new(reader).poll_read(cx, buf),
            Input::File(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

impl AsyncBufRead for Input {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        match self.get_mut() {
            Input::Stdin(reader) => Pin::new(reader).poll_fill_buf(cx),
            Input::File(reader) => Pin::new(reader).poll_fill_buf(cx),
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        match self.get_mut() {
            Input::Stdin(reader) => Pin::new(reader).consume(amt),
            Input::File(reader) => Pin::new(reader).consume(amt),
        }
    }
}

#[derive(Debug)]
pub enum Output {
    Stdout(BufWriter<tokio::io::Stdout>),
    File(BufWriter<File>),
}

impl Output {
    pub async fn from_filename(name: &str) -> Result<Self> {
        match name {
            "stdout" => Ok(Output::Stdout(BufWriter::new(tokio::io::stdout()))),
            _ => {
                let f = File::create(name).await?;
                Ok(Output::File(BufWriter::new(f)))
            }
        }
    }
}

impl AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.get_mut() {
            Output::Stdout(writer) => Pin::new(writer).poll_write(cx, buf),
            Output::File(writer) => Pin::new(writer).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Output::Stdout(writer) => Pin::new(writer).poll_flush(cx),
            Output::File(writer) => Pin::new(writer).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.get_mut() {
            Output::Stdout(writer) => Pin::new(writer).poll_shutdown(cx),
            Output::File(writer) => Pin::new(writer).poll_shutdown(cx),
        }
    }
}

enum ClientAuth {
    Cert(Vec<rustls::Certificate>, rustls::PrivateKey),
    None,
}

fn load_certs(path: &str) -> Result<Vec<rustls::Certificate>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

fn load_key(path: &str) -> Result<rustls::PrivateKey> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
    if let Some(key) = keys.into_iter().next() {
        return Ok(rustls::PrivateKey(key));
    }
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let keys = rustls_pemfile::rsa_private_keys(&mut reader)?;
    keys.into_iter()
        .next()
        .map(rustls::PrivateKey)
        .ok_or_else(|| eyre::eyre!("no private key found in {}", path))
}

fn build_tls_config(
    insecure: bool,
    root_cert_paths: &[String],
    client_auth: ClientAuth,
    session_tickets: bool,
) -> Result<rustls::ClientConfig> {
    let mut tls_config = if insecure {
        let builder = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoVerifier));
        match client_auth {
            ClientAuth::Cert(certs, key) => builder
                .with_single_cert(certs, key)
                .map_err(|e| eyre::eyre!("invalid client cert/key: {}", e))?,
            ClientAuth::None => builder.with_no_client_auth(),
        }
    } else {
        let mut root_store = rustls::RootCertStore::empty();
        if root_cert_paths.is_empty() {
            for cert in rustls_native_certs::load_native_certs()? {
                root_store
                    .add(&rustls::Certificate(cert.0))
                    .map_err(|e| eyre::eyre!("invalid native root cert: {}", e))?;
            }
        } else {
            for path in root_cert_paths {
                let certs = load_certs(path)?;
                for cert in certs {
                    root_store
                        .add(&cert)
                        .map_err(|e| eyre::eyre!("invalid root cert in {}: {}", path, e))?;
                }
            }
        }
        let builder = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);
        match client_auth {
            ClientAuth::Cert(certs, key) => builder
                .with_single_cert(certs, key)
                .map_err(|e| eyre::eyre!("invalid client cert/key: {}", e))?,
            ClientAuth::None => builder.with_no_client_auth(),
        }
    };

    if !session_tickets {
        tls_config.resumption = rustls::client::Resumption::disabled();
    }

    Ok(tls_config)
}

struct NoVerifier;

impl rustls::client::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
