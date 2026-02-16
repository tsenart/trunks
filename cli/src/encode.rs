use clap::Args;
use eyre::Result;
use tokio::io::AsyncBufReadExt;
use trunks::{Codec, CsvCodec, JsonCodec};

use crate::attack::{Input, Output};

#[derive(Args, Debug)]
pub struct Opts {
    /// Output encoding (json, csv)
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
    let to_csv = opts.to == "csv";

    for source in &sources {
        let mut input = Input::from_filename(source).await?;

        // Auto-detect encoding by peeking at first byte.
        let buf = input.fill_buf().await?;
        if buf.is_empty() {
            continue;
        }
        let is_json = buf[0] == b'{';

        loop {
            let result = if is_json {
                JsonCodec.decode(&mut input).await
            } else {
                CsvCodec.decode(&mut input).await
            };
            match result {
                Ok(hit) => {
                    if to_csv {
                        CsvCodec.encode(&mut output, &hit).await?;
                    } else {
                        JsonCodec.encode(&mut output, &hit).await?;
                    }
                }
                Err(_) => break,
            }
        }
    }

    Ok(())
}
