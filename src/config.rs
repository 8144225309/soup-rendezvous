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

    /// Maximum body size in bytes for any single request.
    #[arg(long, env = "SOUP_MAX_BODY", default_value_t = 65536)]
    pub max_body_bytes: usize,

    /// Per-IP requests per second sustained rate.
    #[arg(long, env = "SOUP_RATE_PER_SEC", default_value_t = 5)]
    pub rate_per_sec: u32,

    /// Per-IP burst capacity above the sustained rate.
    #[arg(long, env = "SOUP_RATE_BURST", default_value_t = 30)]
    pub rate_burst: u32,

    /// Maximum bytes a single coordination key may store across all
    /// of its events combined.
    #[arg(long, env = "SOUP_PUBKEY_QUOTA", default_value_t = 1_048_576)]
    pub pubkey_quota_bytes: u64,

    /// Maximum allowed clock skew between client `created_at` and the
    /// server's wall clock, in seconds. Events outside this window are
    /// rejected as bad requests.
    #[arg(long, env = "SOUP_CLOCK_SKEW", default_value_t = 300)]
    pub clock_skew_secs: i64,

    /// Total per-request timeout in seconds.
    #[arg(long, env = "SOUP_TIMEOUT", default_value_t = 30)]
    pub timeout_secs: u64,
}
