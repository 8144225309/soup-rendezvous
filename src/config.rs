//! TOML config loader for running one binary against multiple networks.
//!
//! A single config file holds settings for mainnet, signet, testnet4,
//! or whatever instance names the operator picks. The `--network` flag
//! selects which section to use at runtime.
//!
//! Shape:
//!
//! ```toml
//! # shared defaults, applied when a network section omits them
//! relays = ["wss://nos.lol", "wss://relay.damus.io"]
//! vouch_expiry_days = 30
//!
//! [networks.signet]
//! key_file = "/var/lib/soup-rendezvous-signet/coordinator.nsec"
//! lightning_dir = "/var/lib/cln-signet"
//!
//! [networks.mainnet]
//! key_file = "/var/lib/soup-rendezvous-mainnet/coordinator.nsec"
//! lightning_dir = "/var/lib/cln-mainnet"
//! # per-network override:
//! vouch_expiry_days = 14
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub relays: Option<Vec<String>>,

    #[serde(default)]
    pub vouch_expiry_days: Option<u64>,

    /// SOCKS5 proxy `host:port` (e.g. `127.0.0.1:9050` for local tor).
    /// All Nostr websocket traffic is routed through it when set.
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// Maximum number of simultaneously-active vouches the coordinator
    /// will issue for a single LN node (default 10). Each proof-of-channel
    /// request from a fresh Nostr identity counts against the budget
    /// for the LN node being proved. Prevents one LN operator from
    /// flooding the coordinator's vouch list via Nostr-key rotation.
    #[serde(default)]
    pub max_active_vouches_per_ln_node: Option<u32>,

    /// Path to bitcoind's data directory for proof-of-utxo verification.
    /// When set, coordinator shells out to `bitcoin-cli --datadir=<...>
    /// verifymessage` and `gettxout`. Required for proof-of-utxo; if
    /// unset, UTXO proof requests are rejected with
    /// `btc_verification_not_configured`.
    #[serde(default)]
    pub bitcoin_dir: Option<PathBuf>,

    /// Minimum UTXO balance (in sats) required to accept a
    /// proof-of-utxo. Default 0 is permissive — any unspent output
    /// counts. Raise on mainnet for a real Sybil floor (e.g. 100000
    /// for ~$60 per Sybil address).
    #[serde(default)]
    pub min_utxo_balance_sat: Option<u64>,

    /// Allow proof-of-peer verification (weakest, non-chain-anchored
    /// tier). Default false. Turning on is a network-by-network
    /// decision: signet/testnet4 usually want `true` for bootstrap;
    /// mainnet should leave `false` unless you've thought carefully
    /// about wallet-side filtering.
    #[serde(default)]
    pub allow_peer_verification: Option<bool>,

    /// Maximum simultaneously-active peer-tier vouches the coordinator
    /// will issue per LN node pubkey (default 3). Tighter than the
    /// 10-max for channel/utxo because peer has no chain anchor and
    /// we don't want to amplify weakly-verified attestations.
    #[serde(default)]
    pub max_active_vouches_per_peer: Option<u32>,

    #[serde(default)]
    pub networks: HashMap<String, NetworkSection>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkSection {
    pub key_file: PathBuf,
    pub lightning_dir: PathBuf,

    #[serde(default)]
    pub relays: Option<Vec<String>>,

    #[serde(default)]
    pub vouch_expiry_days: Option<u64>,

    #[serde(default)]
    pub proxy_url: Option<String>,

    #[serde(default)]
    pub max_active_vouches_per_ln_node: Option<u32>,

    #[serde(default)]
    pub bitcoin_dir: Option<PathBuf>,

    #[serde(default)]
    pub min_utxo_balance_sat: Option<u64>,

    #[serde(default)]
    pub allow_peer_verification: Option<bool>,

    #[serde(default)]
    pub max_active_vouches_per_peer: Option<u32>,
}

/// Effective configuration after merging: per-network section wins
/// over top-level defaults, and any of those is overridden by the
/// caller when they pass an explicit CLI value.
#[derive(Debug)]
pub struct Resolved {
    pub key_file: PathBuf,
    pub lightning_dir: Option<PathBuf>,
    pub relays: String,
    pub vouch_expiry_days: u64,
    pub proxy_url: Option<String>,
    pub max_active_vouches_per_ln_node: u32,
    pub bitcoin_dir: Option<PathBuf>,
    pub min_utxo_balance_sat: u64,
    pub allow_peer_verification: bool,
    pub max_active_vouches_per_peer: u32,
}

impl ConfigFile {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let parsed: ConfigFile =
            toml::from_str(&bytes).with_context(|| format!("parsing {}", path.display()))?;
        Ok(parsed)
    }

    /// Pull out the network section, applying top-level defaults
    /// for anything the section didn't override.
    pub fn resolve(&self, network: &str) -> Result<Resolved> {
        let section = self.networks.get(network).with_context(|| {
            format!(
                "network '{}' not found in config; known networks: {}",
                network,
                self.networks
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

        let relays = section
            .relays
            .as_ref()
            .or(self.relays.as_ref())
            .context("no relays configured (either global `relays` or per-network override required)")?;
        if relays.is_empty() {
            bail!("relay list is empty");
        }

        let vouch_expiry_days = section
            .vouch_expiry_days
            .or(self.vouch_expiry_days)
            .unwrap_or(30);

        let proxy_url = section.proxy_url.clone().or_else(|| self.proxy_url.clone());

        let max_active_vouches_per_ln_node = section
            .max_active_vouches_per_ln_node
            .or(self.max_active_vouches_per_ln_node)
            .unwrap_or(10);

        let bitcoin_dir = section
            .bitcoin_dir
            .clone()
            .or_else(|| self.bitcoin_dir.clone());

        let min_utxo_balance_sat = section
            .min_utxo_balance_sat
            .or(self.min_utxo_balance_sat)
            .unwrap_or(0);

        let allow_peer_verification = section
            .allow_peer_verification
            .or(self.allow_peer_verification)
            .unwrap_or(false);

        let max_active_vouches_per_peer = section
            .max_active_vouches_per_peer
            .or(self.max_active_vouches_per_peer)
            .unwrap_or(3);

        Ok(Resolved {
            key_file: section.key_file.clone(),
            lightning_dir: Some(section.lightning_dir.clone()),
            relays: relays.join(","),
            vouch_expiry_days,
            proxy_url,
            max_active_vouches_per_ln_node,
            bitcoin_dir,
            min_utxo_balance_sat,
            allow_peer_verification,
            max_active_vouches_per_peer,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> &'static str {
        r#"
relays = ["wss://nos.lol", "wss://relay.damus.io"]
vouch_expiry_days = 30

[networks.signet]
key_file = "/var/lib/soup-rendezvous-signet/coordinator.nsec"
lightning_dir = "/var/lib/cln-signet"

[networks.mainnet]
key_file = "/var/lib/soup-rendezvous-mainnet/coordinator.nsec"
lightning_dir = "/var/lib/cln-mainnet"
vouch_expiry_days = 14
relays = ["wss://relay.primal.net"]
"#
    }

    #[test]
    fn loads_and_resolves_default_network() {
        let cfg: ConfigFile = toml::from_str(sample()).unwrap();
        let resolved = cfg.resolve("signet").unwrap();
        assert_eq!(
            resolved.relays,
            "wss://nos.lol,wss://relay.damus.io"
        );
        assert_eq!(resolved.vouch_expiry_days, 30);
        assert_eq!(
            resolved.key_file,
            PathBuf::from("/var/lib/soup-rendezvous-signet/coordinator.nsec")
        );
    }

    #[test]
    fn per_network_overrides_win() {
        let cfg: ConfigFile = toml::from_str(sample()).unwrap();
        let resolved = cfg.resolve("mainnet").unwrap();
        assert_eq!(resolved.relays, "wss://relay.primal.net");
        assert_eq!(resolved.vouch_expiry_days, 14);
    }

    #[test]
    fn unknown_network_errors() {
        let cfg: ConfigFile = toml::from_str(sample()).unwrap();
        let err = cfg.resolve("nope").unwrap_err().to_string();
        assert!(err.contains("not found"));
    }
}
