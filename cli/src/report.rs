use clap::Args;
use duration_string::DurationString;
use eyre::Result;
use tokio::io::AsyncWriteExt;
use trunks::{Codec, CsvCodec, Histogram, JsonCodec, Metrics, MsgpackCodec};

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

    /// Periodic reporting interval (e.g. "1s", "5s"). Streams reports at this interval.
    #[clap(long)]
    pub every: Option<DurationString>,

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

    let mut output = Output::from_filename(&opts.output).await?;

    if let Some(ref every_dur) = opts.every {
        let interval_dur: std::time::Duration = (*every_dur).into();
        let mut ticker = tokio::time::interval(interval_dur);
        ticker.tick().await; // consume the immediate first tick

        for source in &sources {
            let mut input = Input::from_filename(source).await?;
            let Some(input_format) = input.detect_format().await? else {
                continue;
            };

            let mut done = false;
            while !done {
                tokio::select! {
                    _ = ticker.tick() => {
                        write_report(opts, &mut metrics, &mut histogram, &mut output).await?;
                        metrics = Metrics::new();
                        if let Some(ref mut h) = histogram {
                            *h = Histogram::from_bucket_str(&opts.buckets)?;
                        }
                    }
                    result = decode_hit(&mut input, input_format) => {
                        match result {
                            Ok(hit) => {
                                if let Some(ref mut h) = histogram {
                                    h.add(&hit);
                                }
                                metrics.add(&hit);
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                if !msg.contains("EOF") && !msg.contains("eof") && !msg.contains("empty") && !msg.contains("no CSV record") {
                                    eprintln!("Error decoding {}: {}", source, e);
                                }
                                done = true;
                            }
                        }
                    }
                }
            }
        }
        // Final report for remaining data.
        write_report(opts, &mut metrics, &mut histogram, &mut output).await
    } else {
        for source in &sources {
            let mut input = Input::from_filename(source).await?;
            let Some(input_format) = input.detect_format().await? else {
                continue;
            };

            loop {
                match decode_hit(&mut input, input_format).await {
                    Ok(hit) => {
                        if let Some(ref mut h) = histogram {
                            h.add(&hit);
                        }
                        metrics.add(&hit);
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if !msg.contains("EOF")
                            && !msg.contains("eof")
                            && !msg.contains("empty")
                            && !msg.contains("no CSV record")
                        {
                            eprintln!("Error decoding {}: {}", source, e);
                        }
                        break;
                    }
                }
            }
        }
        write_report(opts, &mut metrics, &mut histogram, &mut output).await
    }
}

async fn decode_hit(input: &mut Input, format: &str) -> eyre::Result<trunks::Hit> {
    match format {
        "json" => JsonCodec.decode(input).await,
        "csv" => CsvCodec.decode(input).await,
        _ => MsgpackCodec.decode(input).await,
    }
}

async fn write_report(
    opts: &Opts,
    metrics: &mut Metrics,
    histogram: &mut Option<Histogram>,
    output: &mut (impl AsyncWriteExt + Unpin),
) -> Result<()> {
    metrics.close();

    let mut buf = Vec::new();
    match opts.report_type.as_str() {
        "text" => trunks::report_text(metrics, &mut buf)?,
        "json" => trunks::report_json(metrics, &mut buf)?,
        "hist" => {
            let h = histogram
                .as_ref()
                .ok_or_else(|| eyre::eyre!("--buckets is required for hist report"))?;
            trunks::report_histogram(h, &mut buf)?;
        }
        "hdrplot" => trunks::report_hdrplot(metrics, &mut buf)?,
        other => eyre::bail!("unknown report type: {}", other),
    }
    output.write_all(&buf).await?;
    output.flush().await?;
    Ok(())
}
