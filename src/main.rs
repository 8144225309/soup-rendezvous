use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use soup_rendezvous::config::Config;
use soup_rendezvous::db::Db;
use soup_rendezvous::db::sqlite::SqliteDb;
use soup_rendezvous::http::{AppState, build_router};

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

    let state = AppState { db };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!(addr = %cfg.bind, db_path = %cfg.db_path, "soup-rendezvous listening");
    axum::serve(listener, app).await?;
    Ok(())
}
