use clap::Args;
use eyre::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use trunks::{Codec, CsvCodec, Hit, JsonCodec, MsgpackCodec};

use crate::attack::{Input, Output};

#[derive(Args, Debug)]
pub struct Opts {
    /// Plot title
    #[clap(long, default_value = "Vegeta Plot")]
    title: String,

    /// Output file [default: stdout]
    #[clap(long, default_value = "stdout")]
    output: String,

    /// Maximum number of points per series (LTTB downsampling threshold)
    #[clap(long, default_value_t = 4000)]
    threshold: usize,

    /// Input files [default: stdin]
    pub files: Vec<String>,
}

pub async fn plot(opts: &Opts) -> Result<()> {
    let sources: Vec<String> = if opts.files.is_empty() {
        vec!["stdin".to_string()]
    } else {
        opts.files.clone()
    };

    let mut hits: Vec<Hit> = Vec::new();
    for source in &sources {
        let mut input = Input::from_filename(source).await?;
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
                Ok(hit) => hits.push(hit),
                Err(_) => break,
            }
        }
    }

    let plot_opts = trunks::plot::PlotOpts {
        title: opts.title.clone(),
        threshold: opts.threshold,
    };

    let mut html_buf = Vec::new();
    trunks::plot::plot(
        &hits,
        &plot_opts,
        trunks::plot::error_labeler,
        &mut html_buf,
    )?;

    let mut output = Output::from_filename(&opts.output).await?;
    output.write_all(&html_buf).await?;
    output.flush().await?;

    Ok(())
}
