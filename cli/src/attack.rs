use clap::Args;
use duration_string::DurationString;
use eyre::Result;
use futures::StreamExt as _;
use hyper::Client;
use num_cpus;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, BufWriter, ReadBuf};
use tokio::sync::Mutex;
use trunks::{Attack, Codec, TargetDefaults, TargetRead, TargetReader, Targets};

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

    /// Constant requests rate per second
    #[clap(long)]
    rate: usize,

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

    /// Use persistent connections
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    keepalive: bool,

    /// Max idle connections per target host
    #[clap(long, default_value_t = 10000)]
    connections: usize,

    /// Max response body bytes to capture (-1 = unlimited)
    #[clap(long, default_value_t = -1)]
    max_body: i64,

    /// Enable HTTP/2
    #[clap(long, default_value_t = true, action = clap::ArgAction::Set)]
    http2: bool,
}

pub async fn attack(opts: &Opts) -> Result<()> {
    if opts.max_workers == 0 && opts.rate == 0 {
        eyre::bail!("-max-workers must be set when -rate is 0");
    }

    // Parse --header flags into HashMap<String, Vec<String>>
    let headers = if opts.headers.is_empty() {
        None
    } else {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for h in &opts.headers {
            let (k, v) = h
                .split_once(':')
                .ok_or_else(|| eyre::eyre!("invalid header format, expected 'Key: Value': {}", h))?;
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

    let mut target_reader = TargetReader::new(
        &opts.format,
        input,
        TargetDefaults { body, headers },
    )?;

    let targets = if opts.lazy {
        Targets::Lazy(target_reader)
    } else {
        let mut targets: Vec<_> = Vec::new();
        while let Ok(target) = target_reader.decode().await {
            targets.push(target);
        }
        Targets::from(targets)
    };

    let pacer = trunks::ConstantPacer {
        freq: opts.rate as u64,
        per: Duration::from_secs(1),
    };

    // Build TLS config
    let https = if opts.insecure {
        let tls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let builder = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http();

        if opts.http2 {
            builder.enable_http1().enable_http2().build()
        } else {
            builder.enable_http1().build()
        }
    } else {
        let builder = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_or_http();

        if opts.http2 {
            builder.enable_http1().enable_http2().build()
        } else {
            builder.enable_http1().build()
        }
    };

    // Build HTTP client
    let mut client_builder = Client::builder();
    client_builder.pool_max_idle_per_host(opts.connections);
    if !opts.keepalive {
        client_builder.pool_idle_timeout(Duration::ZERO);
    }

    let atk = Attack {
        client: client_builder.build::<_, hyper::Body>(https),
        duration: opts.duration.into(),
        name: opts.name.clone(),
        pacer: Arc::new(pacer),
        targets: Arc::new(Mutex::new(targets)),
        workers: opts.workers,
        max_workers: opts.max_workers,
        timeout: opts.timeout.into(),
        max_body: opts.max_body,
    };

    let mut hits = atk.run();

    let codec = trunks::JsonCodec {};

    tokio::select! {
        _ = async {
            while let Some(result) = hits.next().await {
                match result {
                    Ok(hit) => {
                        if let Err(err) = codec.encode(&mut output, &hit).await {
                            eprintln!("Error: {}", err);
                        }
                    }
                    Err(err) => {
                        eprintln!("Error: {}", err);
                    }
                }
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\nInterrupted");
        }
    }

    Ok(())
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
