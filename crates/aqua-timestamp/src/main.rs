use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};

use anyhow::{Context, Result};
use axum::{
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tracing::info;

mod landing;

#[derive(Parser, Debug)]
#[command(name = "aqua-timestamp", version, about = "Aqua Aggregator service")]
struct Cli {
    /// Path to the TOML config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Config {
    server: ServerConfig,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    listen: String,
}

struct AppState {
    started_at: Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let cfg = load_config(&cli.config)
        .with_context(|| format!("failed to load config at {}", cli.config.display()))?;

    let addr: SocketAddr = cfg
        .server
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {:?}", cfg.server.listen))?;

    let state = Arc::new(AppState {
        started_at: Instant::now(),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(landing_page))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

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

fn load_config(path: &std::path::Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let cfg: Config = toml::from_str(&text)?;
    Ok(cfg)
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    uptime_secs: u64,
    version: &'static str,
}

async fn health(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        uptime_secs: state.started_at.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn landing_page() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(landing::HTML),
    )
        .into_response()
}
