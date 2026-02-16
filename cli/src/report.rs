use clap::Args;
use eyre::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use trunks::{Codec, CsvCodec, Histogram, JsonCodec, Metrics};

use crate::attack::{Input, Output};

#[derive(Args, Debug)]
pub struct Opts {
    /// Report type (text, json, hist, hdrplot)
    #[clap(long, name = "type", default_value = "text")]
    pub report_type: String,

    /// Output file [default: stdout]
    #[clap(long, default_value = "stdout")]
    pub output: String,

    /// Histogram buckets, e.g. "[0,1ms,10ms]"
    #[clap(long, default_value = "")]
    pub buckets: String,

    /// Input files [default: stdin]
    pub files: Vec<String>,
}

pub async fn report(opts: &Opts) -> Result<()> {
    let sources: Vec<String> = if opts.files.is_empty() {
        vec!["stdin".to_string()]
    } else {
        opts.files.clone()
    };

    let mut metrics = Metrics::new();
    let mut histogram = if !opts.buckets.is_empty() {
        Some(Histogram::from_bucket_str(&opts.buckets)?)
    } else {
        None
    };

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
                    if let Some(ref mut h) = histogram {
                        h.add(&hit);
                    }
                    metrics.add(&hit);
                }
                Err(_) => break,
            }
        }
    }

    metrics.close();

    let mut output = Output::from_filename(&opts.output).await?;

    let mut buf = Vec::new();
    match opts.report_type.as_str() {
        "text" => trunks::report_text(&metrics, &mut buf)?,
        "json" => trunks::report_json(&metrics, &mut buf)?,
        "hist" => {
            let h = histogram.ok_or_else(|| eyre::eyre!("--buckets is required for hist report"))?;
            trunks::report_histogram(&h, &mut buf)?;
        }
        "hdrplot" => trunks::report_hdrplot(&metrics, &mut buf)?,
        other => eyre::bail!("unknown report type: {}", other),
    }
    output.write_all(&buf).await?;
    output.flush().await?;
    Ok(())
}
