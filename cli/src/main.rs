mod attack;
mod encode;
mod report;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "trunks", about = "Son of Vegeta — a powerful HTTP load testing tool written in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute an HTTP load test
    Attack(attack::Opts),
    /// Generate reports from attack results
    Report(report::Opts),
    /// Transcode attack results between encodings
    Encode(encode::Opts),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Attack(opts) => attack::attack(&opts).await,
        Command::Report(opts) => report::report(&opts).await,
        Command::Encode(opts) => encode::encode(&opts).await,
    }
}
