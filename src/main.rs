use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use soup_rendezvous::config::Config;
use soup_rendezvous::db::Db;
use soup_rendezvous::db::sqlite::SqliteDb;
use soup_rendezvous::http::{AppState, HttpLimits, build_router};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,soup_rendezvous=debug".into()),
        )
        .init();

    let db: Arc<dyn Db> = if cfg.db_path == ":memory:" {
        Arc::new(SqliteDb::open_in_memory()?)
    } else {
        Arc::new(SqliteDb::open(&cfg.db_path)?)
    };

    let limits = HttpLimits {
        max_body_bytes: cfg.max_body_bytes,
        rate_per_sec: cfg.rate_per_sec,
        rate_burst: cfg.rate_burst,
        pubkey_quota_bytes: cfg.pubkey_quota_bytes,
        clock_skew_secs: cfg.clock_skew_secs,
        timeout_secs: cfg.timeout_secs,
    };

    let state = AppState {
        db,
        limits: Arc::new(limits),
    };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(addr = %cfg.bind, db_path = %cfg.db_path, "soup-rendezvous listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
