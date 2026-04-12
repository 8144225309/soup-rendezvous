use std::net::SocketAddr;

use clap::Parser;

/// Runtime configuration. All fields can be set on the command line or
/// via environment variables (`SOUP_*`).
#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct Config {
    /// Address to bind the HTTP server to. Always bind to loopback in
    /// dev; production runs behind caddy or another reverse proxy that
    /// handles TLS and exposes the public listener.
    #[arg(long, env = "SOUP_BIND", default_value = "127.0.0.1:8090")]
    pub bind: SocketAddr,

    /// Path to the SQLite database file. Use ":memory:" for an
    /// ephemeral in-memory database (only useful for tests / demos).
    #[arg(long, env = "SOUP_DB", default_value = "soup-rendezvous.db")]
    pub db_path: String,
}
