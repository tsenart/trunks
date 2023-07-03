use clap::Parser;
use duration_string::DurationString;
use eyre::Result;
use futures::StreamExt as _;
use hyper::Client;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncBufRead;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tokio::io::ReadBuf;
use tokio::sync::Mutex;
use trunks::Attack;
use trunks::Codec;
use trunks::TargetDefaults;
use trunks::TargetRead;
use trunks::TargetReader;
use trunks::Targets;

#[derive(Parser, Debug)]
#[clap(
    name = "trunks",
    about = "Son of Vegeta — a powerful HTTP load testing tool written in Rust"
)]
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
}

pub async fn attack(opts: &Opts) -> Result<()> {
    // if opts.max_workers == 0 && opts.rate == 0 {
    //     eyre::bail!("rate frequency and time unit must be bigger than zero");
    // }

    let input = Input::from_filename(&opts.targets).await?;
    let mut output = Output::from_filename(&opts.output).await?;

    // let mut body: Vec<u8> = Vec::new();
    // if let Some(body_bytes) = files.get(&opts.body) {
    //     body_bytes.read_to_end(&mut body)?;
    // }

    let mut target_reader = TargetReader::new(
        &opts.format,
        input,
        TargetDefaults {
            body: None,
            headers: None,
        },
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

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

    let atk = Attack {
        client: Client::builder().build::<_, hyper::Body>(https),
        duration: opts.duration.into(),
        name: opts.name.clone(),
        pacer: Arc::new(pacer),
        targets: Arc::new(Mutex::new(targets)),
    };

    let mut hits = atk.run();

    let codec = trunks::JsonCodec {};

    while let Some(result) = hits.next().await {
        match result {
            Ok(hit) => {
                codec.encode(&mut output, &hit).await?;
            }
            Err(err) => {
                panic!("{}", err)
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum Input {
    Stdin(BufReader<tokio::io::Stdin>),
    File(BufReader<File>),
}

impl Input {
    async fn from_filename(name: &str) -> Result<Self> {
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
enum Output {
    Stdout(BufWriter<tokio::io::Stdout>),
    File(BufWriter<File>),
}

impl Output {
    async fn from_filename(name: &str) -> Result<Self> {
        match name {
            "stdout" => Ok(Output::Stdout(BufWriter::new(tokio::io::stdout()))),
            _ => {
                let f = File::open(name).await?;
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
