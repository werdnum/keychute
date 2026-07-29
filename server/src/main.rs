use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
#[command(name = "keychute-server", about = "Keychute secrets delivery broker")]
struct Args {
    /// Path to config YAML (or env KEYCHUTE_CONFIG)
    #[arg(long, env = "KEYCHUTE_CONFIG")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    let args = Args::parse();
    let config = keychute_server::config::Config::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;
    keychute_server::run(config).await
}
