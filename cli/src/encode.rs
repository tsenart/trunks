use clap::Args;
use eyre::Result;
use tokio::io::AsyncBufReadExt;
use trunks::{Codec, CsvCodec, JsonCodec, MsgpackCodec};

use crate::attack::{Input, Output};

#[derive(Args, Debug)]
pub struct Opts {
    /// Output encoding (json, csv, msgpack)
    #[clap(long, default_value = "json")]
    pub to: String,

    /// Output file [default: stdout]
    #[clap(long, default_value = "stdout")]
    pub output: String,

    /// Input files [default: stdin]
    pub files: Vec<String>,
}

pub async fn encode(opts: &Opts) -> Result<()> {
    let sources: Vec<String> = if opts.files.is_empty() {
        vec!["stdin".to_string()]
    } else {
        opts.files.clone()
    };

    let mut output = Output::from_filename(&opts.output).await?;

    for source in &sources {
        let mut input = Input::from_filename(source).await?;

        // Auto-detect input encoding by peeking at first byte.
        let buf = input.fill_buf().await?;
        if buf.is_empty() {
            continue;
        }
        let first = buf[0];
        let input_format = if first == b'{' {
            "json"
        } else if first.is_ascii_graphic() {
            "csv"
        } else {
            "msgpack"
        };

        loop {
            let result = match input_format {
                "json" => JsonCodec.decode(&mut input).await,
                "csv" => CsvCodec.decode(&mut input).await,
                _ => MsgpackCodec.decode(&mut input).await,
            };
            match result {
                Ok(hit) => match opts.to.as_str() {
                    "csv" => CsvCodec.encode(&mut output, &hit).await?,
                    "msgpack" => MsgpackCodec.encode(&mut output, &hit).await?,
                    _ => JsonCodec.encode(&mut output, &hit).await?,
                },
                Err(_) => break,
            }
        }
    }

    Ok(())
}
