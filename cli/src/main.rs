mod attack;
use clap::Parser;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let attack_opts = attack::Opts::try_parse()?;

    attack::attack(&attack_opts).await?;

    Ok(())
}
