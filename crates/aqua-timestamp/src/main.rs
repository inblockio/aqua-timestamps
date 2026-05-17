use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use aqua_timestamp::{
    build_app, config,
    identity::{IdentityClaimOverrides, ServiceIdentity},
    SealDriver,
};
use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "aqua-timestamp", version, about = "Aqua Aggregator service")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let cfg = config::load(&cli.config)
        .with_context(|| format!("failed to load config at {}", cli.config.display()))?;

    let addr: SocketAddr = cfg
        .server
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {:?}", cfg.server.listen))?;

    let identity = ServiceIdentity::from_env(&cfg.identity)
        .await
        .context("loading service identity")?;
    info!(
        server_did = %identity.server_did,
        address = %identity.address_eip55,
        dns = %identity.dns,
        "service identity loaded"
    );

    let (app, _state) = build_app(
        cfg,
        identity,
        IdentityClaimOverrides::default(),
        SealDriver::Interval,
    )
    .await?;

    info!(%addr, "aqua-timestamp starting");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        fmt::layer().json().boxed()
    } else {
        fmt::layer().boxed()
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}
