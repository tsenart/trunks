use clap::Parser;
use duration_string::DurationString;
use eyre::Result;
use futures::pin_mut;
use futures::StreamExt as _;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncBufRead;
use tokio::io::AsyncRead;
use tokio::io::BufReader;
use tokio::io::ReadBuf;
use tokio::sync::Mutex;
use trunks::Attack;
use trunks::TargetReader;
use trunks::Targets;
use trunks::{Target, TargetRead};

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

    let targets_source = Reader::from_filename(&opts.targets).await?;

    // let mut body: Vec<u8> = Vec::new();
    // if let Some(body_bytes) = files.get(&opts.body) {
    //     body_bytes.read_to_end(&mut body)?;
    // }

    let mut target_reader = TargetReader::new(&opts.format, targets_source)?;
    let targets = if opts.lazy {
        Targets::Lazy(target_reader)
    } else {
        let mut targets: Vec<_> = Vec::new();
        let mut target = Target::default();
        while let Ok(_) = target_reader.decode(&mut target).await {
            targets.push(target);
            target = Target::default();
        }
        Targets::from(targets)
    };

    let pacer = trunks::ConstantPacer {
        freq: opts.rate as u64,
        per: Duration::from_secs(1),
    };

    let atk = Attack {
        client: reqwest::Client::new(),
        duration: opts.duration.into(),
        name: opts.name.clone(),
        pacer: Arc::new(pacer),
        targets: Arc::new(Mutex::new(targets)),
    };

    let hits = atk.run();

    pin_mut!(hits); // needed for iteration

    while let Some(_) = hits.next().await {}

    Ok(())
}

// All the below stuff is to have better perf with static dispatch.
#[derive(Debug)]
enum Reader {
    Stdin(BufReader<tokio::io::Stdin>),
    File(BufReader<File>),
}

impl Reader {
    async fn from_filename(name: &str) -> Result<Self> {
        match name {
            "stdin" => Ok(Reader::Stdin(BufReader::new(tokio::io::stdin()))),
            _ => {
                let f = File::open(name).await?;
                Ok(Reader::File(BufReader::new(f)))
            }
        }
    }
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Reader::Stdin(reader) => Pin::new(reader).poll_read(cx, buf),
            Reader::File(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

impl AsyncBufRead for Reader {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        match self.get_mut() {
            Reader::Stdin(reader) => Pin::new(reader).poll_fill_buf(cx),
            Reader::File(reader) => Pin::new(reader).poll_fill_buf(cx),
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        match self.get_mut() {
            Reader::Stdin(reader) => Pin::new(reader).consume(amt),
            Reader::File(reader) => Pin::new(reader).consume(amt),
        }
    }
}
