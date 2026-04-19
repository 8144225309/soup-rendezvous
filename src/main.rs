use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nostr::nips::nip44;
use nostr_sdk::prelude::*;
use tracing_subscriber::EnvFilter;

use soup_rendezvous::config::ConfigFile;
use soup_rendezvous::events;
use soup_rendezvous::kinds;

#[derive(Parser)]
#[command(
    name = "soup-rendezvous",
    version,
    about = "Coordination protocol for multi-party Bitcoin signing, built on Nostr."
)]
struct Cli {
    /// Path to a TOML config file with per-network sections. When set,
    /// `--network` selects which section to use and supplies the
    /// nsec path, CLN lightning-dir, relays, and vouch expiry. Any
    /// explicit CLI flag still wins over the config value.
    #[arg(long, env = "SOUP_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Network name within the config file (e.g. mainnet / signet /
    /// testnet4). Required when --config is used with a multi-network
    /// config.
    #[arg(long, env = "SOUP_NETWORK", global = true)]
    network: Option<String>,

    /// Path to the Nostr secret key file (nsec or hex).
    #[arg(long, env = "SOUP_KEY_FILE", default_value = "soup-coordinator.nsec")]
    key_file: PathBuf,

    /// Nostr relay URLs, comma-separated.
    #[arg(
        long,
        env = "SOUP_RELAYS",
        default_value = "wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net,wss://relay.nostr.band,wss://relay.snort.social,wss://offchain.pub,wss://nostr.fmt.wiz.biz"
    )]
    relays: String,

    /// Path to CLN lightning-rpc directory (for checkmessage verification).
    #[arg(long, env = "SOUP_LIGHTNING_DIR")]
    lightning_dir: Option<PathBuf>,

    /// Default vouch lifetime in days. Applied to every vouch published
    /// by the `vouch` subcommand and the daemon's auto-vouch path. Hosts
    /// must re-prove before this window closes or their vouch expires
    /// (NIP-40). 30 days is the recommended baseline.
    #[arg(long, env = "SOUP_VOUCH_EXPIRY_DAYS", default_value_t = 30)]
    vouch_expiry_days: u64,

    /// SOCKS5 proxy address (host:port) for all Nostr websocket traffic.
    /// Point at a local tor daemon (typically 127.0.0.1:9050) to hide
    /// the coordinator's IP from relay operators. Not a mixnet —
    /// relays still learn the npub, but the TCP endpoint is Tor-exit.
    #[arg(long, env = "SOUP_PROXY_URL")]
    proxy_url: Option<String>,

    /// Maximum active vouches the coordinator will issue per single
    /// LN node (default 10). An LSP rotating Nostr keys across factories
    /// can still get multiple vouches for the same LN node, but not
    /// unbounded. Prevents amplification attacks where one node floods
    /// the coordinator's attestation list under many Nostr identities.
    #[arg(long, env = "SOUP_MAX_ACTIVE_VOUCHES_PER_LN_NODE", default_value_t = 10)]
    max_active_vouches_per_ln_node: u32,

    /// Path to bitcoind data directory. Required for proof-of-utxo
    /// verification; coordinator shells out to `bitcoin-cli
    /// --datadir=<...>` for verifymessage and gettxout. If unset,
    /// UTXO requests are rejected with `btc_verification_not_configured`.
    #[arg(long, env = "SOUP_BITCOIN_DIR")]
    bitcoin_dir: Option<PathBuf>,

    /// Minimum UTXO balance in sats to accept a proof-of-utxo
    /// (default 0, permissive). Raise on mainnet for a real Sybil
    /// floor. 100000 sats ≈ $60 at current prices.
    #[arg(long, env = "SOUP_MIN_UTXO_BALANCE_SAT", default_value_t = 0)]
    min_utxo_balance_sat: u64,

    /// Enable proof-of-peer (weakest non-chain-anchored tier). OFF
    /// by default — mainnet deployments should keep it off. Test
    /// networks and explicit bootstrap scenarios can flip to true.
    #[arg(long, env = "SOUP_ALLOW_PEER_VERIFICATION", default_value_t = false)]
    allow_peer_verification: bool,

    /// Max simultaneously-active peer-tier vouches the coordinator
    /// will issue per LN node pubkey. Tighter than channel/utxo
    /// (default 3 vs 10) because peer has no chain anchor.
    #[arg(long, env = "SOUP_MAX_ACTIVE_VOUCHES_PER_PEER", default_value_t = 3)]
    max_active_vouches_per_peer: u32,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Nostr keypair and save to the key file.
    Init,

    /// Print the public key (npub and hex).
    Whoami,

    /// Publish the root discovery thread to the configured relays.
    PublishRoot {
        #[arg(default_value = "soup-rendezvous: multi-party Bitcoin signing coordination")]
        description: String,
    },

    /// Generate a proof-of-channel challenge string.
    Challenge,

    /// Verify an LN node proof and publish a vouch event.
    Vouch {
        /// The host's Nostr pubkey (hex or npub) to vouch for.
        host_pubkey: String,
        /// The LN node ID (33-byte hex pubkey from `lightning-cli getinfo`).
        node_id: String,
        /// The zbase-encoded signature from `lightning-cli signmessage`.
        zbase: String,
        /// The challenge string that was signed.
        challenge: String,
        /// Number of channels the node has (from getinfo or manual check).
        #[arg(long, default_value_t = 0)]
        channels: u32,
        /// Total channel capacity in sats.
        #[arg(long, default_value = "0")]
        capacity_sat: String,
    },

    /// Revoke a previously-published vouch.
    /// Republishes kind 38101 with same d-tag (host pubkey) and
    /// content {"status":"revoked",...}. Because vouches are
    /// parameterized-replaceable, relays automatically supersede
    /// the prior "active" vouch.
    RevokeVouch {
        /// The host's Nostr pubkey (hex or npub) whose vouch to revoke.
        host_pubkey: String,
        /// Human-readable reason (recorded in the event).
        #[arg(long, default_value = "revoked by coordinator")]
        reason: String,
    },

    /// List vouches (verified LN node proofs) from the relays.
    ListVouches {
        /// Only show vouches from this coordinator (npub or hex).
        /// Defaults to own pubkey if not specified.
        #[arg(long)]
        coordinator: Option<String>,
    },

    /// (Host) Send a proof-of-channel request DM to a coordinator.
    /// Constructs a challenge with the coordinator's npub, signs it with
    /// the local CLN node, and sends the result as an encrypted DM.
    RequestVouch {
        /// The coordinator's Nostr pubkey (hex or npub) to request a vouch from.
        coordinator_pubkey: String,
        /// Path to the CLN lightning-rpc directory for signmessage.
        #[arg(long, env = "SOUP_LIGHTNING_DIR")]
        lightning_dir: PathBuf,
    },

    /// (Host) Send a proof-of-UTXO request DM to a coordinator.
    /// Constructs a challenge with the coordinator's npub, signs it
    /// with `bitcoin-cli signmessage`, and sends the result (plus the
    /// UTXO outpoint) as an encrypted DM. For individuals with on-chain
    /// bitcoin who don't have LN channels.
    RequestVouchUtxo {
        /// The coordinator's Nostr pubkey (hex or npub) to request a vouch from.
        coordinator_pubkey: String,
        /// Bitcoin address holding the UTXO used as proof.
        #[arg(long)]
        btc_address: String,
        /// UTXO txid (64 hex chars).
        #[arg(long)]
        utxo_txid: String,
        /// UTXO vout index.
        #[arg(long)]
        utxo_vout: u32,
        /// LN node id (33-byte compressed pubkey, 66 hex chars). Required
        /// since the unified vouch carries contact info; this is the node
        /// wallets will dial to discover your factories.
        #[arg(long)]
        ln_node_id: String,
        /// Optional comma-separated LN addresses (host:port) — only needed
        /// if your LN node is not in BOLT-7 gossip.
        #[arg(long)]
        ln_addresses: Option<String>,
        /// Path to bitcoind data directory for signmessage.
        #[arg(long, env = "SOUP_BITCOIN_DIR")]
        bitcoin_dir: PathBuf,
        /// Optional bitcoind wallet name (passed as -rpcwallet to
        /// bitcoin-cli signmessage) for multi-wallet setups.
        #[arg(long)]
        bitcoin_wallet: Option<String>,
    },

    /// (Host) Send a single DM containing one or more proofs the host
    /// can produce, ordered by preference (strongest first). The
    /// coordinator tries each in order and publishes a vouch at the
    /// first tier that verifies. One DM, one response. Use this if
    /// you have more than one proof method available and want
    /// automatic fallback to the strongest-that-works tier.
    RequestVouchMulti {
        /// The coordinator's Nostr pubkey (hex or npub).
        coordinator_pubkey: String,
        /// Include a proof-of-channel attempt. Requires --lightning-dir.
        #[arg(long)]
        include_channel: bool,
        /// Include a proof-of-UTXO attempt. Requires --bitcoin-dir,
        /// --btc-address, --utxo-txid, --utxo-vout.
        #[arg(long)]
        include_utxo: bool,
        /// Include a proof-of-peer attempt. Requires --lightning-dir
        /// and --peer-addresses.
        #[arg(long)]
        include_peer: bool,
        /// CLN lightning-rpc dir (used for channel signmessage and
        /// peer-tier getinfo).
        #[arg(long, env = "SOUP_LIGHTNING_DIR")]
        lightning_dir: Option<PathBuf>,
        /// bitcoind datadir (used for UTXO signmessage + verifymessage).
        #[arg(long, env = "SOUP_BITCOIN_DIR")]
        bitcoin_dir: Option<PathBuf>,
        /// Bitcoin address for proof-of-UTXO.
        #[arg(long)]
        btc_address: Option<String>,
        /// UTXO txid for proof-of-UTXO.
        #[arg(long)]
        utxo_txid: Option<String>,
        /// UTXO vout for proof-of-UTXO.
        #[arg(long)]
        utxo_vout: Option<u32>,
        /// LN node id for proof-of-UTXO (host-declared contact, not
        /// verified). Required when --include-utxo is set.
        #[arg(long)]
        utxo_ln_node_id: Option<String>,
        /// Optional comma-separated LN addresses for the utxo-tier
        /// vouch (only needed if your LN node is not in BOLT-7 gossip).
        #[arg(long)]
        utxo_ln_addresses: Option<String>,
        /// Bitcoind wallet name for signmessage (multi-wallet setups).
        #[arg(long)]
        bitcoin_wallet: Option<String>,
        /// Comma-separated LN addresses for proof-of-peer.
        #[arg(long)]
        peer_addresses: Option<String>,
    },

    /// (Host) Send a proof-of-peer DM to a coordinator. The coordinator
    /// will dial your advertised LN address(es) and use the BOLT-8
    /// handshake as the proof. Weakest tier — use only if you don't
    /// have channels (proof-of-channel) or on-chain UTXOs
    /// (proof-of-utxo). Some coordinators (including mainnet by default)
    /// reject proof-of-peer entirely.
    RequestVouchPeer {
        /// The coordinator's Nostr pubkey (hex or npub) to request a vouch from.
        coordinator_pubkey: String,
        /// Comma-separated LN addresses your node accepts incoming
        /// connections on (e.g. "host:9735,ipv6.example.com:9735").
        #[arg(long)]
        addresses: String,
        /// Path to CLN lightning-rpc directory — used to auto-detect
        /// your own LN node_id via getinfo.
        #[arg(long, env = "SOUP_LIGHTNING_DIR")]
        lightning_dir: PathBuf,
    },

    /// Run the coordinator daemon.
    /// Subscribes for proof requests sent as NIP-44 encrypted DMs to our
    /// pubkey, verifies each tier the host submitted, and publishes a
    /// vouch on success. Host-driven one-shot flow — no round-trips.
    Daemon,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,soup_rendezvous=debug".into()),
        )
        .init();

    let mut cli = Cli::parse();

    // If a config file was given, fold the selected network section
    // into `cli` before running any subcommand. Direct CLI flags are
    // not merged back — the user picks one source of truth per run.
    if let Some(config_path) = cli.config.clone() {
        let network = cli
            .network
            .clone()
            .context("--network is required when --config is provided")?;
        let config = ConfigFile::load(&config_path)?;
        let resolved = config.resolve(&network)?;
        cli.key_file = resolved.key_file;
        cli.lightning_dir = resolved.lightning_dir;
        cli.relays = resolved.relays;
        cli.vouch_expiry_days = resolved.vouch_expiry_days;
        cli.max_active_vouches_per_ln_node = resolved.max_active_vouches_per_ln_node;
        cli.min_utxo_balance_sat = resolved.min_utxo_balance_sat;
        cli.allow_peer_verification = resolved.allow_peer_verification;
        cli.max_active_vouches_per_peer = resolved.max_active_vouches_per_peer;
        if cli.proxy_url.is_none() {
            cli.proxy_url = resolved.proxy_url;
        }
        if cli.bitcoin_dir.is_none() {
            cli.bitcoin_dir = resolved.bitcoin_dir;
        }
        tracing::info!(
            network = %network,
            config = %config_path.display(),
            "loaded config"
        );
    }

    match cli.command {
        Command::Init => cmd_init(&cli.key_file),
        Command::Whoami => cmd_whoami(&cli.key_file),
        Command::PublishRoot { description } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            cmd_publish_root(&client, &description).await
        }
        Command::Challenge => {
            let keys = load_keys(&cli.key_file)?;
            cmd_challenge(&keys)
        }
        Command::Vouch {
            host_pubkey,
            node_id,
            zbase,
            challenge,
            channels,
            capacity_sat,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            cmd_vouch(
                &client,
                cli.lightning_dir.as_deref(),
                &host_pubkey,
                &node_id,
                &zbase,
                &challenge,
                channels,
                &capacity_sat,
                cli.vouch_expiry_days,
                cli.max_active_vouches_per_ln_node,
            )
            .await
        }
        Command::RevokeVouch {
            host_pubkey,
            reason,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            cmd_revoke_vouch(&client, &host_pubkey, &reason, cli.vouch_expiry_days).await
        }
        Command::ListVouches { coordinator } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            cmd_list_vouches(&client, &keys, coordinator.as_deref()).await
        }
        Command::RequestVouch {
            coordinator_pubkey,
            lightning_dir,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            cmd_request_vouch(&client, &keys, &coordinator_pubkey, &lightning_dir).await
        }
        Command::RequestVouchUtxo {
            coordinator_pubkey,
            btc_address,
            utxo_txid,
            utxo_vout,
            ln_node_id,
            ln_addresses,
            bitcoin_dir,
            bitcoin_wallet,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            let ln_addresses_vec: Vec<String> = ln_addresses
                .as_deref()
                .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
                .unwrap_or_default();
            cmd_request_vouch_utxo(
                &client,
                &keys,
                &coordinator_pubkey,
                &btc_address,
                &utxo_txid,
                utxo_vout,
                &ln_node_id,
                &ln_addresses_vec,
                &bitcoin_dir,
                bitcoin_wallet.as_deref(),
            )
            .await
        }
        Command::RequestVouchPeer {
            coordinator_pubkey,
            addresses,
            lightning_dir,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            cmd_request_vouch_peer(
                &client,
                &keys,
                &coordinator_pubkey,
                &addresses,
                &lightning_dir,
            )
            .await
        }
        Command::RequestVouchMulti {
            coordinator_pubkey,
            include_channel,
            include_utxo,
            include_peer,
            lightning_dir,
            bitcoin_dir,
            btc_address,
            utxo_txid,
            utxo_vout,
            utxo_ln_node_id,
            utxo_ln_addresses,
            bitcoin_wallet,
            peer_addresses,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            let utxo_ln_addresses_vec: Vec<String> = utxo_ln_addresses
                .as_deref()
                .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
                .unwrap_or_default();
            cmd_request_vouch_multi(
                &client,
                &keys,
                &coordinator_pubkey,
                include_channel,
                include_utxo,
                include_peer,
                lightning_dir.as_deref(),
                bitcoin_dir.as_deref(),
                btc_address.as_deref(),
                utxo_txid.as_deref(),
                utxo_vout,
                utxo_ln_node_id.as_deref(),
                &utxo_ln_addresses_vec,
                bitcoin_wallet.as_deref(),
                peer_addresses.as_deref(),
            )
            .await
        }
        Command::Daemon => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys, cli.proxy_url.as_deref()).await?;
            cmd_daemon(
                &client,
                &keys,
                &cli.key_file,
                cli.network.as_deref(),
                cli.lightning_dir.as_deref(),
                cli.bitcoin_dir.as_deref(),
                cli.min_utxo_balance_sat,
                cli.allow_peer_verification,
                cli.max_active_vouches_per_peer,
                cli.vouch_expiry_days,
                cli.max_active_vouches_per_ln_node,
            )
            .await
        }
    }
}

// --- commands ---

fn cmd_init(key_file: &PathBuf) -> Result<()> {
    if key_file.exists() {
        bail!(
            "key file already exists at {}, refusing to overwrite",
            key_file.display()
        );
    }
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32()?;
    std::fs::write(key_file, &nsec).context("writing key file")?;
    println!("keypair generated");
    println!("  nsec: {nsec}");
    println!("  npub: {}", keys.public_key().to_bech32()?);
    println!("  hex:  {}", keys.public_key());
    println!("saved to {}", key_file.display());
    Ok(())
}

fn cmd_whoami(key_file: &PathBuf) -> Result<()> {
    let keys = load_keys(key_file)?;
    println!("npub: {}", keys.public_key().to_bech32()?);
    println!("hex:  {}", keys.public_key());
    Ok(())
}

async fn cmd_publish_root(client: &Client, description: &str) -> Result<()> {
    let builder = events::build_root_thread(description);
    let output = client.send_event_builder(builder).await?;
    println!("root thread published");
    println!("  event id: {}", output.id());
    Ok(())
}

fn cmd_challenge(keys: &Keys) -> Result<()> {
    let random_bytes: [u8; 16] = rand::random();
    let coordinator_npub = keys.public_key().to_bech32()?;
    let challenge = format!(
        "soup-rendezvous:proof-of-channel:v0:{}:{}:{}",
        coordinator_npub,
        hex::encode(random_bytes),
        Timestamp::now().as_secs()
    );
    println!("challenge: {challenge}");
    println!();
    println!("give this to the host. they sign it with their CLN node:");
    println!("  lightning-cli signmessage \"{challenge}\"");
    println!();
    println!("IMPORTANT: the host should verify before signing:");
    println!("  - message starts with soup-rendezvous:proof-of-channel:v0:");
    println!("  - the npub matches the coordinator they intend to vouch with");
    println!("  - the timestamp is recent");
    println!();
    println!("then run:");
    println!("  soup-rendezvous vouch <host-npub> <node-id> <zbase> \"{challenge}\"");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_vouch(
    client: &Client,
    lightning_dir: Option<&std::path::Path>,
    host_pubkey_str: &str,
    node_id: &str,
    zbase: &str,
    challenge: &str,
    channels: u32,
    capacity_sat: &str,
    expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
) -> Result<()> {
    let host_pk = if host_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(host_pubkey_str)?
    } else {
        PublicKey::from_hex(host_pubkey_str)?
    };

    // Validate the challenge format to prevent cross-protocol replay
    let coordinator_npub = client.signer().await?.get_public_key().await?.to_bech32()?;
    validate_challenge(challenge, &coordinator_npub)?;

    // Verify the signature using lightning-cli checkmessage
    if let Some(ln_dir) = lightning_dir {
        println!("verifying signature via lightning-cli...");
        let output = std::process::Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", ln_dir.display()))
            .arg("checkmessage")
            .arg(challenge)
            .arg(zbase)
            .output()
            .context("failed to run lightning-cli checkmessage")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            bail!("checkmessage failed: {stdout} {stderr}");
        }

        let result: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse checkmessage output")?;

        let verified = result["verified"].as_bool().unwrap_or(false);
        let recovered_pubkey = result["pubkey"].as_str().unwrap_or("");

        if !verified {
            bail!("signature verification failed: checkmessage returned verified=false");
        }

        if recovered_pubkey != node_id {
            bail!(
                "node_id mismatch: claimed {} but signature recovers to {}",
                node_id,
                recovered_pubkey
            );
        }

        println!("  verified: true");
        println!("  recovered pubkey matches claimed node_id");
    } else {
        println!("warning: no --lightning-dir set, skipping signature verification");
        println!("  the operator should manually verify with:");
        println!(
            "  lightning-cli checkmessage \"{}\" \"{}\"",
            challenge, zbase
        );
        println!("  and confirm the returned pubkey matches: {}", node_id);
        println!();
    }

    // Cap the number of active vouches per LN node.
    let coordinator_pk = client.signer().await?.get_public_key().await?;
    let active_count =
        count_active_vouches_for_ln_node(client, &coordinator_pk, node_id, &host_pk.to_hex())
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "relay query failed, proceeding anyway (fail-open)");
                0
            });
    if active_count >= max_active_vouches_per_ln_node as usize {
        bail!(
            "too many active vouches for LN node {node_id}: {active_count} already exist (cap {max_active_vouches_per_ln_node}); revoke stale vouches or wait for them to expire"
        );
    }

    // Publish the vouch event — unified format publishes only contact
    // info (ln_node_id) plus tier/freshness; channels/capacity are
    // accepted from the host but not republished.
    let expires_at = Timestamp::now().as_secs() + expiry_days * 86400;
    let builder = events::build_vouch(
        &host_pk,
        events::VouchTier::Channel,
        node_id,
        &[],
        None,
        expires_at,
    );
    let output = client.send_event_builder(builder).await?;
    println!("vouch published");
    println!("  event id:    {}", output.id());
    println!("  host nostr:  {}", host_pk);
    println!("  ln node:     {}", node_id);
    println!("  channels:    {} (verified, not republished)", channels);
    println!("  capacity:    {} sat (verified, not republished)", capacity_sat);
    println!("  expires in:  {} days (host must re-prove before then)", expiry_days);
    Ok(())
}

async fn cmd_revoke_vouch(
    client: &Client,
    host_pubkey_str: &str,
    reason: &str,
    expiry_days: u64,
) -> Result<()> {
    let host_pk = if host_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(host_pubkey_str)?
    } else {
        PublicKey::from_hex(host_pubkey_str)?
    };

    // Tier defaults to Channel for the published `l` tag — relays
    // supersede on (kind, author, d-tag), so the published tier value
    // doesn't gate replacement, but Channel is the historic default
    // and any tier wins because the d-tag matches.
    let expires_at = Timestamp::now().as_secs() + expiry_days * 86400;
    let builder = events::build_revoke_vouch(&host_pk, events::VouchTier::Channel, expires_at);
    let output = client.send_event_builder(builder).await?;
    println!("vouch revoked");
    println!("  event id:   {}", output.id());
    println!("  host nostr: {}", host_pk);
    println!("  reason:     {} (operator-side audit only; not in published event)", reason);
    println!();
    println!("relays will supersede the prior 'active' vouch for this host.");
    Ok(())
}

async fn cmd_list_vouches(
    client: &Client,
    keys: &Keys,
    coordinator_str: Option<&str>,
) -> Result<()> {
    let coordinator_pk = match coordinator_str {
        Some(s) if s.starts_with("npub") => PublicKey::from_bech32(s)?,
        Some(s) => PublicKey::from_hex(s)?,
        None => keys.public_key(),
    };

    let filter = Filter::new().kind(kinds::VOUCH).author(coordinator_pk);
    let all_events = client.fetch_events(filter, Duration::from_secs(10)).await?;

    // Client-side filter: some relays don't respect the `authors` filter
    // for custom kinds, so we double-check here.
    let coordinator_hex = coordinator_pk.to_hex();
    let events: Vec<Event> = all_events
        .into_iter()
        .filter(|ev| ev.pubkey.to_hex() == coordinator_hex)
        .collect();

    if events.is_empty() {
        println!(
            "no vouches found from coordinator {} ({} total on relay, none matched)",
            coordinator_pk,
            0 // can't count all_events after into_iter consumed it
        );
        return Ok(());
    }

    println!("found {} vouch(es):\n", events.len());
    for ev in events.iter() {
        let ln_node = events::get_tag_value(ev, "ln_node_id").unwrap_or_else(|| "?".into());
        let host_p_tag = ev.tags.iter().find_map(|t| {
            if t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)) {
                t.content().map(|s| s.to_string())
            } else {
                None
            }
        });

        println!("  vouched by: {}", ev.pubkey);
        if let Some(hp) = host_p_tag {
            println!("  host nostr: {hp}");
        }
        println!("  ln node:    {ln_node}");
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&ev.content) {
            if let Some(ch) = parsed["channel_count"].as_u64() {
                println!("  channels:   {ch}");
            }
            if let Some(cap) = parsed["capacity_sat"].as_str() {
                println!("  capacity:   {cap} sat");
            }
        }
        println!("  date:       {}", ev.created_at);
        println!();
    }
    Ok(())
}


async fn cmd_request_vouch(
    client: &Client,
    keys: &Keys,
    coordinator_pubkey_str: &str,
    lightning_dir: &std::path::Path,
) -> Result<()> {
    let coord_pk = if coordinator_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(coordinator_pubkey_str)?
    } else {
        PublicKey::from_hex(coordinator_pubkey_str)?
    };
    let coord_npub = coord_pk.to_bech32()?;

    // Construct challenge using the coordinator's npub
    let random_bytes: [u8; 16] = rand::random();
    let challenge = format!(
        "soup-rendezvous:proof-of-channel:v0:{}:{}:{}",
        coord_npub,
        hex::encode(random_bytes),
        Timestamp::now().as_secs()
    );

    println!("requesting vouch from {coord_npub}");
    println!("challenge: {challenge}");

    // Sign via lightning-cli
    let output = std::process::Command::new("lightning-cli")
        .arg(format!("--lightning-dir={}", lightning_dir.display()))
        .arg("signmessage")
        .arg(&challenge)
        .output()
        .context("failed to run lightning-cli signmessage")?;
    if !output.status.success() {
        bail!(
            "signmessage failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let sign_result: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse signmessage output")?;
    let zbase = sign_result["zbase"]
        .as_str()
        .context("no zbase in signmessage output")?;

    // Get node info for channel count + capacity
    let info_output = std::process::Command::new("lightning-cli")
        .arg(format!("--lightning-dir={}", lightning_dir.display()))
        .arg("getinfo")
        .output()
        .context("failed to run lightning-cli getinfo")?;
    let info: serde_json::Value =
        serde_json::from_slice(&info_output.stdout).context("failed to parse getinfo")?;
    let node_id = info["id"].as_str().context("no id in getinfo")?;
    let channels = info["num_active_channels"].as_u64().unwrap_or(0) as u32;

    // Build the proof request JSON
    let request = serde_json::json!({
        "type": "proof_of_channel",
        "node_id": node_id,
        "zbase": zbase,
        "challenge": challenge,
        "channels": channels,
        "capacity_sat": "0",
    });

    // Encrypt to coordinator's pubkey
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &coord_pk,
        request.to_string(),
        nip44::Version::default(),
    )?;

    // Send as NIP-44 DM (kind 4)
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(coord_pk));
    let dm_output = client.send_event_builder(dm).await?;

    println!("proof request sent (encrypted to coordinator)");
    println!("  event id: {}", dm_output.id());
    println!("  node_id:  {node_id}");
    println!("  channels: {channels}");
    println!();
    println!("wait for the coordinator's daemon to verify and publish a vouch.");
    println!("check with: soup-rendezvous list-vouches --coordinator {coord_npub}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_request_vouch_utxo(
    client: &Client,
    keys: &Keys,
    coordinator_pubkey_str: &str,
    btc_address: &str,
    utxo_txid: &str,
    utxo_vout: u32,
    ln_node_id: &str,
    ln_addresses: &[String],
    bitcoin_dir: &std::path::Path,
    bitcoin_wallet: Option<&str>,
) -> Result<()> {
    let coord_pk = if coordinator_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(coordinator_pubkey_str)?
    } else {
        PublicKey::from_hex(coordinator_pubkey_str)?
    };
    let coord_npub = coord_pk.to_bech32()?;

    // Construct a proof-of-UTXO challenge.
    let random_bytes: [u8; 16] = rand::random();
    let challenge = format!(
        "soup-rendezvous:proof-of-utxo:v0:{}:{}:{}",
        coord_npub,
        hex::encode(random_bytes),
        Timestamp::now().as_secs()
    );

    println!("requesting UTXO vouch from {coord_npub}");
    println!("challenge: {challenge}");

    // Sign via bitcoin-cli signmessage. Requires the address to be in
    // the node's wallet (so the node can access the private key).
    let mut cmd = std::process::Command::new("bitcoin-cli");
    cmd.arg(format!("-datadir={}", bitcoin_dir.display()));
    if let Some(w) = bitcoin_wallet {
        cmd.arg(format!("-rpcwallet={}", w));
    }
    let sign_output = cmd
        .arg("signmessage")
        .arg(btc_address)
        .arg(&challenge)
        .output()
        .context("failed to run bitcoin-cli signmessage")?;
    if !sign_output.status.success() {
        bail!(
            "signmessage failed (address must be in your bitcoind wallet): {}",
            String::from_utf8_lossy(&sign_output.stderr)
        );
    }
    let signature = String::from_utf8_lossy(&sign_output.stdout).trim().to_string();

    // Build the proof request payload. ln_node_id is host-declared
    // contact (not verified by the UTXO proof — first-dial failure
    // invalidates a bad declaration at no protocol cost).
    let mut request = serde_json::json!({
        "type": "proof_of_utxo",
        "btc_address": btc_address,
        "signature": signature,
        "challenge": challenge,
        "utxo_txid": utxo_txid,
        "utxo_vout": utxo_vout,
        "ln_node_id": ln_node_id,
    });
    if !ln_addresses.is_empty() {
        request["ln_addresses"] = serde_json::json!(ln_addresses);
    }

    // Encrypt + send as kind-4 DM.
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &coord_pk,
        request.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(coord_pk));
    let dm_output = client.send_event_builder(dm).await?;

    println!("UTXO proof request sent (encrypted to coordinator)");
    println!("  event id:    {}", dm_output.id());
    println!("  btc_address: {btc_address}");
    println!("  utxo:        {utxo_txid}:{utxo_vout}");
    println!();
    println!("wait for the coordinator's daemon to verify and publish a vouch.");
    println!("check with: soup-rendezvous list-vouches --coordinator {coord_npub}");
    Ok(())
}

async fn cmd_request_vouch_peer(
    client: &Client,
    keys: &Keys,
    coordinator_pubkey_str: &str,
    addresses_csv: &str,
    lightning_dir: &std::path::Path,
) -> Result<()> {
    let coord_pk = if coordinator_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(coordinator_pubkey_str)?
    } else {
        PublicKey::from_hex(coordinator_pubkey_str)?
    };
    let coord_npub = coord_pk.to_bech32()?;

    // Split and trim the addresses list.
    let addresses: Vec<String> = addresses_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if addresses.is_empty() {
        bail!("addresses list is empty (use --addresses host:9735,other:9735)");
    }

    // Auto-detect own LN node_id via getinfo.
    let info_output = std::process::Command::new("lightning-cli")
        .arg(format!("--lightning-dir={}", lightning_dir.display()))
        .arg("getinfo")
        .output()
        .context("failed to run lightning-cli getinfo")?;
    if !info_output.status.success() {
        bail!(
            "getinfo failed: {}",
            String::from_utf8_lossy(&info_output.stderr)
        );
    }
    let info: serde_json::Value =
        serde_json::from_slice(&info_output.stdout).context("failed to parse getinfo")?;
    let ln_node_id = info["id"]
        .as_str()
        .context("no id in getinfo output")?
        .to_string();

    // Construct a proof-of-peer challenge.
    let random_bytes: [u8; 16] = rand::random();
    let challenge = format!(
        "soup-rendezvous:proof-of-peer:v0:{}:{}:{}",
        coord_npub,
        hex::encode(random_bytes),
        Timestamp::now().as_secs()
    );

    println!("requesting peer-tier vouch from {coord_npub}");
    println!("challenge: {challenge}");

    // No signature in the payload — the BOLT-8 handshake initiated
    // by the coordinator is the proof.
    let request = serde_json::json!({
        "type": "proof_of_peer",
        "ln_node_id": ln_node_id,
        "addresses": addresses,
        "challenge": challenge,
    });

    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &coord_pk,
        request.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(coord_pk));
    let dm_output = client.send_event_builder(dm).await?;

    println!("peer proof request sent (encrypted to coordinator)");
    println!("  event id:   {}", dm_output.id());
    println!("  ln_node_id: {ln_node_id}");
    println!("  addresses:  {:?}", addresses);
    println!();
    println!("coordinator will attempt a BOLT-8 connection to one of your addresses.");
    println!("your LN daemon needs to be reachable and accepting peers.");
    println!("check with: soup-rendezvous list-vouches --coordinator {coord_npub}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_request_vouch_multi(
    client: &Client,
    keys: &Keys,
    coordinator_pubkey_str: &str,
    include_channel: bool,
    include_utxo: bool,
    include_peer: bool,
    lightning_dir: Option<&std::path::Path>,
    bitcoin_dir: Option<&std::path::Path>,
    btc_address: Option<&str>,
    utxo_txid: Option<&str>,
    utxo_vout: Option<u32>,
    utxo_ln_node_id: Option<&str>,
    utxo_ln_addresses: &[String],
    bitcoin_wallet: Option<&str>,
    peer_addresses: Option<&str>,
) -> Result<()> {
    if !include_channel && !include_utxo && !include_peer {
        bail!("must include at least one of --include-channel / --include-utxo / --include-peer");
    }

    let coord_pk = if coordinator_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(coordinator_pubkey_str)?
    } else {
        PublicKey::from_hex(coordinator_pubkey_str)?
    };
    let coord_npub = coord_pk.to_bech32()?;

    let mut proofs: Vec<serde_json::Value> = Vec::new();
    let random_bytes: [u8; 16] = rand::random();
    let ts = Timestamp::now().as_secs();

    // Channel proof (strongest — placed first)
    if include_channel {
        let ln_dir =
            lightning_dir.context("--include-channel requires --lightning-dir")?;
        let challenge = format!(
            "soup-rendezvous:proof-of-channel:v0:{}:{}:{}",
            coord_npub,
            hex::encode(random_bytes),
            ts
        );

        let sign_output = std::process::Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", ln_dir.display()))
            .arg("signmessage")
            .arg(&challenge)
            .output()
            .context("lightning-cli signmessage failed")?;
        if !sign_output.status.success() {
            bail!(
                "signmessage failed: {}",
                String::from_utf8_lossy(&sign_output.stderr)
            );
        }
        let sign_result: serde_json::Value =
            serde_json::from_slice(&sign_output.stdout).context("parse signmessage")?;
        let zbase = sign_result["zbase"]
            .as_str()
            .context("no zbase in signmessage")?;

        let info_output = std::process::Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", ln_dir.display()))
            .arg("getinfo")
            .output()
            .context("lightning-cli getinfo failed")?;
        let info: serde_json::Value =
            serde_json::from_slice(&info_output.stdout).context("parse getinfo")?;
        let node_id = info["id"].as_str().context("no id in getinfo")?;
        let channels = info["num_active_channels"].as_u64().unwrap_or(0) as u32;

        proofs.push(serde_json::json!({
            "type": "proof_of_channel",
            "node_id": node_id,
            "zbase": zbase,
            "challenge": challenge,
            "channels": channels,
            "capacity_sat": "0",
        }));
    }

    // UTXO proof (co-equal chain-anchored)
    if include_utxo {
        let btc_dir = bitcoin_dir.context("--include-utxo requires --bitcoin-dir")?;
        let addr = btc_address.context("--include-utxo requires --btc-address")?;
        let txid = utxo_txid.context("--include-utxo requires --utxo-txid")?;
        let vout = utxo_vout.context("--include-utxo requires --utxo-vout")?;

        let challenge = format!(
            "soup-rendezvous:proof-of-utxo:v0:{}:{}:{}",
            coord_npub,
            hex::encode(random_bytes),
            ts
        );

        let mut cmd = std::process::Command::new("bitcoin-cli");
        cmd.arg(format!("-datadir={}", btc_dir.display()));
        if let Some(w) = bitcoin_wallet {
            cmd.arg(format!("-rpcwallet={w}"));
        }
        let sign_output = cmd
            .arg("signmessage")
            .arg(addr)
            .arg(&challenge)
            .output()
            .context("bitcoin-cli signmessage failed")?;
        if !sign_output.status.success() {
            bail!(
                "bitcoin-cli signmessage failed: {}",
                String::from_utf8_lossy(&sign_output.stderr)
            );
        }
        let signature = String::from_utf8_lossy(&sign_output.stdout).trim().to_string();

        // For multi-method DMs, if a channel proof is also being sent
        // and the host didn't pass --utxo-ln-node-id, default to the
        // channel's node id (same node, both proofs).
        let utxo_node = match utxo_ln_node_id {
            Some(s) => s.to_string(),
            None => {
                if include_channel && lightning_dir.is_some() {
                    let info_output = std::process::Command::new("lightning-cli")
                        .arg(format!("--lightning-dir={}", lightning_dir.unwrap().display()))
                        .arg("getinfo")
                        .output()
                        .context("lightning-cli getinfo failed for utxo ln_node_id derivation")?;
                    let info: serde_json::Value =
                        serde_json::from_slice(&info_output.stdout).context("parse getinfo")?;
                    info["id"].as_str().context("no id in getinfo")?.to_string()
                } else {
                    bail!(
                        "--include-utxo requires --utxo-ln-node-id (the LN node wallets should dial), or pair with --include-channel + --lightning-dir for auto-detect"
                    );
                }
            }
        };

        let mut p = serde_json::json!({
            "type": "proof_of_utxo",
            "btc_address": addr,
            "signature": signature,
            "challenge": challenge,
            "utxo_txid": txid,
            "utxo_vout": vout,
            "ln_node_id": utxo_node,
        });
        if !utxo_ln_addresses.is_empty() {
            p["ln_addresses"] = serde_json::json!(utxo_ln_addresses);
        }
        proofs.push(p);
    }

    // Peer proof (weakest — placed last)
    if include_peer {
        let ln_dir =
            lightning_dir.context("--include-peer requires --lightning-dir")?;
        let addrs = peer_addresses.context("--include-peer requires --peer-addresses")?;
        let addresses: Vec<String> = addrs
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if addresses.is_empty() {
            bail!("--peer-addresses is empty");
        }

        let info_output = std::process::Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", ln_dir.display()))
            .arg("getinfo")
            .output()
            .context("lightning-cli getinfo failed")?;
        let info: serde_json::Value =
            serde_json::from_slice(&info_output.stdout).context("parse getinfo")?;
        let ln_node_id = info["id"].as_str().context("no id in getinfo")?.to_string();

        let challenge = format!(
            "soup-rendezvous:proof-of-peer:v0:{}:{}:{}",
            coord_npub,
            hex::encode(random_bytes),
            ts
        );

        proofs.push(serde_json::json!({
            "type": "proof_of_peer",
            "ln_node_id": ln_node_id,
            "addresses": addresses,
            "challenge": challenge,
        }));
    }

    let request = serde_json::json!({
        "type": "proof_multi",
        "proofs": proofs,
    });

    println!("requesting multi-method vouch from {coord_npub}");
    println!("  methods: {} proof(s) in order of preference", proofs.len());

    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &coord_pk,
        request.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(coord_pk));
    let dm_output = client.send_event_builder(dm).await?;

    println!("multi proof request sent (encrypted to coordinator)");
    println!("  event id: {}", dm_output.id());
    println!();
    println!("coordinator will try methods in order and publish a vouch at the first one that succeeds.");
    println!("check with: soup-rendezvous list-vouches --coordinator {coord_npub}");
    Ok(())
}

/// Extension trait for `Mutex` lock acquisition that recovers from
/// poisoning instead of panicking. A poisoned mutex means some prior
/// task panicked while holding the lock; the protected data is still
/// structurally valid (Rust's type system guarantees this), so the
/// only real risk is a partially-updated counter. We log loudly and
/// keep serving — one bad DM shouldn't brick the whole daemon.
trait LockRecover<T> {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockRecover<T> for std::sync::Mutex<T> {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| {
            tracing::error!(
                "state mutex was poisoned — a prior task panicked while holding the lock; recovering and continuing"
            );
            poisoned.into_inner()
        })
    }
}

/// Rate limiter, replay cache, and observability counters for the daemon.
/// All state is in-memory; cleared on restart. For our scale
/// (a handful of requests per day) this is plenty.
#[derive(Default)]
struct DaemonState {
    /// Per-sender request timestamps (for rate limiting)
    per_sender: std::collections::HashMap<PublicKey, Vec<u64>>,
    /// Global request timestamps for chain-anchored methods
    /// (proof-of-channel, proof-of-utxo). Caps at GLOBAL_CHAIN_ANCHORED_HOURLY.
    global_chain_anchored: Vec<u64>,
    /// Global request timestamps for proof-of-peer. Separate bucket so
    /// peer floods can't starve legitimate chain-anchored traffic.
    global_peer: Vec<u64>,
    /// Seen (pubkey, challenge_hash) to reject replays
    seen: std::collections::HashSet<[u8; 32]>,
    /// Oldest-first queue of seen entries with timestamps, for eviction
    seen_order: std::collections::VecDeque<(u64, [u8; 32])>,

    /// Authoritative in-memory view of our own active vouches. Keyed
    /// by d-tag (host Nostr pubkey hex). Populated at startup from a
    /// relay query, then maintained incrementally on each publish or
    /// revoke the daemon emits. Periodic re-sync catches drift.
    active_vouches: std::collections::HashMap<String, ActiveVouch>,
    /// True once the startup relay query has populated `active_vouches`.
    /// Incoming proof requests are rejected with `state_not_loaded`
    /// until this flips, so we never under-count at cap check time.
    vouch_table_loaded: bool,
    /// Unix timestamp of the most recent successful sync from relays.
    vouch_table_last_synced_at: u64,

    // Observability counters (monotonic since daemon start)
    proofs_received: u64,
    proofs_verified: u64,
    proofs_rejected_format: u64,
    proofs_rejected_signature: u64,
    proofs_rejected_cap_hit: u64,
    proofs_rate_limited: u64,
    proofs_replayed: u64,
    vouches_published: u64,
    dms_decrypt_failed: u64,

    /// Max `created_at` of any kind-4 DM we've pulled off relays this
    /// session. Persisted to `last_seen_dm.txt` next to the key file so
    /// that across daemon restarts we subscribe with `.since(last_seen)`
    /// and pick up DMs that arrived while we were offline.
    last_seen_created_at: u64,
    /// Backlog size logged once at startup: number of events the
    /// notification handler dispatched with `created_at <= startup_now`.
    /// Purely observational.
    backlog_processed: u64,
    /// Durable dedup map: every DM whose handler we've run to completion
    /// (success or structured failure), keyed by event id with the DM's
    /// `created_at` as value. Persisted to `processed_events.txt` via
    /// atomic full-file rewrite on each advance, so a restart never
    /// re-invokes the handler for an event we already saw — no duplicate
    /// vouches, no duplicate confirmation DMs. Entries older than
    /// PROCESSED_EVENTS_TTL_SECS are pruned at startup. Keeping the
    /// timestamp alongside the id lets us rewrite the whole file
    /// atomically rather than relying on a tearable append.
    processed_events: std::collections::HashMap<EventId, u64>,
    /// Count of events short-circuited because their id was already in
    /// `processed_events`. Observability for the exactly-once path.
    duplicates_skipped: u64,
}

/// One active vouch in the in-memory table. `identifier` is the
/// thing being attested and differs per source (LN node pubkey for
/// channel, bitcoin address for utxo, peer pubkey for peer).
#[derive(Debug, Clone)]
struct ActiveVouch {
    source: VerificationSource,
    identifier: String,
    expires_at: u64,
    status: VouchStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VouchStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationSource {
    LnChannel,
    BtcUtxo,
    #[allow(dead_code)] // populated by Patch B2 (proof-of-peer)
    LnPeer,
}

impl VerificationSource {
    fn as_str(&self) -> &'static str {
        match self {
            Self::LnChannel => "ln_channel",
            Self::BtcUtxo => "btc_utxo",
            Self::LnPeer => "ln_peer",
        }
    }

    fn from_content_str(s: &str) -> Option<Self> {
        match s {
            "ln_channel" => Some(Self::LnChannel),
            "btc_utxo" => Some(Self::BtcUtxo),
            "ln_peer" => Some(Self::LnPeer),
            _ => None,
        }
    }
}

impl DaemonState {
    /// Render current counters as a single log-friendly string.
    fn metrics_summary(&self) -> String {
        format!(
            "metrics: received={} verified={} vouches={} rejected_format={} rejected_sig={} rejected_cap={} rate_limited={} replayed={} decrypt_failed={} seen_cache={} tracked_senders={} vouch_table_size={} vouch_table_last_synced_at={} bucket_chain_anchored={}/{} bucket_peer={}/{} last_seen_dm={} backlog_processed={} processed_events_set={} duplicates_skipped={}",
            self.proofs_received,
            self.proofs_verified,
            self.vouches_published,
            self.proofs_rejected_format,
            self.proofs_rejected_signature,
            self.proofs_rejected_cap_hit,
            self.proofs_rate_limited,
            self.proofs_replayed,
            self.dms_decrypt_failed,
            self.seen.len(),
            self.per_sender.len(),
            self.active_vouches.len(),
            self.vouch_table_last_synced_at,
            self.global_chain_anchored.len(),
            GLOBAL_CHAIN_ANCHORED_HOURLY,
            self.global_peer.len(),
            GLOBAL_PEER_HOURLY,
            self.last_seen_created_at,
            self.backlog_processed,
            self.processed_events.len(),
            self.duplicates_skipped,
        )
    }

    /// Count active vouches for a given (source, identifier) pair,
    /// excluding the d-tag corresponding to the Nostr pubkey being
    /// (re-)vouched. One cap primitive shared by every proof method.
    fn count_active_by_source_and_identifier(
        &self,
        source: VerificationSource,
        identifier: &str,
        exclude_d_tag: &str,
    ) -> usize {
        let now = Timestamp::now().as_secs();
        self.active_vouches
            .iter()
            .filter(|(d, v)| {
                v.status == VouchStatus::Active
                    && v.expires_at > now
                    && v.source == source
                    && v.identifier == identifier
                    && d.as_str() != exclude_d_tag
            })
            .count()
    }

    /// Record a newly-published active vouch in the table, superseding
    /// any prior entry under the same d-tag (parameterized-replaceable
    /// semantics match ours on relays).
    fn record_active_vouch(
        &mut self,
        d_tag: String,
        source: VerificationSource,
        identifier: String,
        expires_at: u64,
    ) {
        self.active_vouches.insert(
            d_tag,
            ActiveVouch {
                source,
                identifier,
                expires_at,
                status: VouchStatus::Active,
            },
        );
    }
}

const PER_SENDER_HOURLY: usize = 5;
const PER_SENDER_MINUTELY: usize = 1;
const GLOBAL_CHAIN_ANCHORED_HOURLY: usize = 80;
const GLOBAL_PEER_HOURLY: usize = 20;
const REPLAY_TTL_SECS: u64 = 600; // 10 minutes

/// How long we remember that a given event id was handled. Bounded so
/// the dedup file doesn't grow forever; well past the challenge
/// freshness window (5 min) and any plausible relay backlog.
const PROCESSED_EVENTS_TTL_SECS: u64 = 7 * 24 * 3600; // 7 days

/// Which global rate-limit bucket a proof request counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofKind {
    ChainAnchored,
    Peer,
}

impl DaemonState {
    /// Check rate limits for a sender. Returns Err with a reason if
    /// rate-limited, Ok if the request should proceed. On Ok, records
    /// the timestamp in the per-sender tracker and the appropriate
    /// global bucket for the proof kind.
    fn check_rate(&mut self, sender: &PublicKey, kind: ProofKind) -> Result<()> {
        let now = Timestamp::now().as_secs();

        // Evict old per-sender entries (> 1 hour). Keep the HashMap
        // tight by dropping senders whose entries are all stale —
        // otherwise their empty Vec lingers forever under a dead key.
        self.per_sender
            .retain(|_pk, ts| ts.iter().any(|&t| now.saturating_sub(t) < 3600));
        let entry = self.per_sender.entry(*sender).or_default();
        entry.retain(|&ts| now.saturating_sub(ts) < 3600);

        // Burst: max 1 request per minute from the same sender
        let recent = entry
            .iter()
            .filter(|&&ts| now.saturating_sub(ts) < 60)
            .count();
        if recent >= PER_SENDER_MINUTELY {
            bail!("rate limited: sender sent a request in the last minute");
        }

        // Hourly per-sender cap
        if entry.len() >= PER_SENDER_HOURLY {
            bail!("rate limited: sender exceeded {PER_SENDER_HOURLY} requests/hour");
        }

        // Global cap — per-bucket so peer traffic can't starve chain-anchored.
        match kind {
            ProofKind::ChainAnchored => {
                self.global_chain_anchored
                    .retain(|&ts| now.saturating_sub(ts) < 3600);
                if self.global_chain_anchored.len() >= GLOBAL_CHAIN_ANCHORED_HOURLY {
                    bail!(
                        "rate limited: global cap of {GLOBAL_CHAIN_ANCHORED_HOURLY} chain-anchored requests/hour reached"
                    );
                }
                self.global_chain_anchored.push(now);
            }
            ProofKind::Peer => {
                self.global_peer.retain(|&ts| now.saturating_sub(ts) < 3600);
                if self.global_peer.len() >= GLOBAL_PEER_HOURLY {
                    bail!(
                        "rate limited: global cap of {GLOBAL_PEER_HOURLY} peer requests/hour reached"
                    );
                }
                self.global_peer.push(now);
            }
        }

        // Record per-sender
        entry.push(now);
        Ok(())
    }

    /// Check whether we've seen this (sender, challenge) combination.
    /// Returns Err if seen (replay), Ok and records it if new.
    fn check_replay(&mut self, sender: &PublicKey, challenge: &str) -> Result<()> {
        let now = Timestamp::now().as_secs();

        // Evict expired entries
        while let Some(&(ts, _)) = self.seen_order.front() {
            if now.saturating_sub(ts) >= REPLAY_TTL_SECS {
                if let Some((_, h)) = self.seen_order.pop_front() {
                    self.seen.remove(&h);
                }
            } else {
                break;
            }
        }

        // Compute hash
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(sender.to_hex().as_bytes());
        h.update(b":");
        h.update(challenge.as_bytes());
        let hash: [u8; 32] = h.finalize().into();

        if self.seen.contains(&hash) {
            bail!("replay: same (sender, challenge) seen within {REPLAY_TTL_SECS}s");
        }

        self.seen.insert(hash);
        self.seen_order.push_back((now, hash));
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_daemon(
    client: &Client,
    keys: &Keys,
    key_file: &std::path::Path,
    network: Option<&str>,
    lightning_dir: Option<&std::path::Path>,
    bitcoin_dir: Option<&std::path::Path>,
    min_utxo_balance_sat: u64,
    allow_peer_verification: bool,
    max_active_vouches_per_peer: u32,
    vouch_expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
) -> Result<()> {
    let coordinator_npub = keys.public_key().to_bech32()?;
    let coordinator_pk = keys.public_key();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        network = network.unwrap_or("<unset>"),
        npub = %coordinator_npub,
        vouch_expiry_days,
        max_active_vouches_per_ln_node,
        allow_peer_verification,
        max_active_vouches_per_peer,
        "daemon starting"
    );

    // --- Startup config sanity checks ---
    // Every silent misconfig here causes the daemon to reject every
    // proof request of some tier with a generic rejection reason. We
    // surface them loudly at startup so operators catch the problem
    // before a host wastes round trips trying to get vouched.
    if lightning_dir.is_none() {
        tracing::warn!(
            "no --lightning-dir set: proof-of-channel requests will be rejected (can't shell out to lightning-cli)"
        );
    }
    if bitcoin_dir.is_none() {
        tracing::warn!(
            "no --bitcoin-dir set: proof-of-utxo requests will be rejected (can't shell out to bitcoin-cli)"
        );
    }
    if lightning_dir.is_none() && bitcoin_dir.is_none() && !allow_peer_verification {
        tracing::error!(
            "no verification tier is usable: --lightning-dir, --bitcoin-dir, and allow_peer_verification are all disabled — every proof request will be rejected"
        );
    }
    if allow_peer_verification {
        tracing::warn!(
            "proof-of-peer verification is ENABLED — peer-tier vouches have no chain anchor; only appropriate for test networks or bootstrap use"
        );
        if lightning_dir.is_none() {
            tracing::warn!(
                "allow_peer_verification=true but --lightning-dir is unset: peer-tier requests will still fail (the BOLT-8 dial uses lightning-cli connect)"
            );
        }
        if network == Some("mainnet") {
            tracing::error!(
                "allow_peer_verification=true on MAINNET — this is almost never what you want; peer-tier has no Sybil floor and wallets should be filtering it out, but listing it here widens the attack surface. Set allow_peer_verification = false for [networks.mainnet] unless you have a concrete reason."
            );
        }
    }

    // Resume from the last DM timestamp we persisted (if any) so a
    // restart picks up requests that arrived while we were down.
    // Re-processing an already-handled DM is benign: the 5-min challenge
    // freshness window rejects stale ones, replayed ones are idempotent
    // (same parameterized-replaceable d-tag), and the vouch table's
    // cap check uses our own authoritative publishes.
    let last_seen_path = last_seen_dm_path(key_file);
    let startup_now = Timestamp::now().as_secs();
    let since_ts = match last_seen_path
        .as_ref()
        .and_then(|p| load_last_seen_dm(p).map(|ts| (p, ts)))
    {
        Some((path, ts)) => {
            let gap_secs = startup_now.saturating_sub(ts);
            tracing::info!(
                last_seen_ts = ts,
                gap_seconds = gap_secs,
                path = %path.display(),
                "resuming DM scan from persisted last_seen_dm; backlog from this window will be replayed"
            );
            ts
        }
        None => {
            if let Some(p) = last_seen_path.as_ref() {
                tracing::info!(
                    path = %p.display(),
                    "no prior last_seen_dm found; starting from now (fresh state)"
                );
            } else {
                tracing::warn!(
                    "key_file has no parent dir; cannot persist last_seen_dm — backlog on restart will be lost"
                );
            }
            startup_now
        }
    };

    let filter = Filter::new()
        .kind(Kind::Custom(4))
        .pubkey(coordinator_pk)
        .since(Timestamp::from(since_ts));
    client.subscribe(filter, None).await?;
    tracing::info!(
        since_ts,
        "subscribed for incoming DMs (channel/utxo/peer/multi)"
    );

    let client = client.clone();
    let keys = keys.clone();
    let ln_dir = lightning_dir.map(|p| p.to_path_buf());
    let btc_dir = bitcoin_dir.map(|p| p.to_path_buf());
    // Load the durable event-id dedup set so we never re-invoke the
    // handler for a DM we already processed. Paired with last_seen_dm:
    // last_seen bounds the relay subscription window, processed_events
    // dedupes any overlap within that window.
    let processed_events_path = processed_events_path(key_file);
    let processed_set = processed_events_path
        .as_ref()
        .map(|p| load_processed_events(p, startup_now))
        .unwrap_or_default();

    let state = std::sync::Arc::new(std::sync::Mutex::new(DaemonState {
        last_seen_created_at: since_ts,
        processed_events: processed_set,
        ..DaemonState::default()
    }));

    // Initial sync of the in-memory vouch table from relays. Retries
    // every 30s on failure so a transient relay issue doesn't leave
    // the daemon permanently refusing requests with state_not_loaded.
    {
        let state = state.clone();
        let client = client.clone();
        tokio::spawn(async move {
            loop {
                match sync_vouch_table(&client, &coordinator_pk, &state).await {
                    Ok(n) => {
                        tracing::info!(
                            vouch_table_size = n,
                            "initial vouch table sync complete"
                        );
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "initial vouch table sync failed, retrying in 30s");
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            }
        });
    }

    // Periodic vouch-table re-sync (every hour) to catch drift between
    // the in-memory view and what relays actually hold.
    {
        let state = state.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3600));
            ticker.tick().await; // skip the immediate first tick
            loop {
                ticker.tick().await;
                if let Err(e) = sync_vouch_table(&client, &coordinator_pk, &state).await {
                    tracing::warn!(error = %e, "periodic vouch table re-sync failed");
                }
            }
        });
    }

    // Spawn periodic metrics logger (every 60s)
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(60));
            ticker.tick().await; // skip the immediate first tick
            loop {
                ticker.tick().await;
                let summary = state
                    .lock_state()
                    .metrics_summary();
                tracing::info!("{summary}");
            }
        });
    }

    client
        .handle_notifications(|notification| {
            let client = client.clone();
            let keys = keys.clone();
            let ln_dir = ln_dir.clone();
            let btc_dir = btc_dir.clone();
            let state = state.clone();
            let last_seen_path = last_seen_path.clone();
            let processed_events_path = processed_events_path.clone();
            async move {
                if let RelayPoolNotification::Event { event, .. } = notification
                    && event.kind == Kind::Custom(4)
                    && event.tags.public_keys().any(|pk| pk == &coordinator_pk)
                {
                    let event_ts = event.created_at.as_secs();
                    let is_backlog = event_ts < startup_now;

                    // Durable exactly-once guard: if we've already run
                    // the handler for this event id, short-circuit so
                    // no duplicate vouch is published and no duplicate
                    // confirmation DM is sent. Done before any work.
                    let already_processed = {
                        let s = state.lock_state();
                        s.processed_events.contains_key(&event.id)
                    };
                    if already_processed {
                        {
                            let mut s = state.lock_state();
                            s.duplicates_skipped += 1;
                        }
                        tracing::info!(
                            sender = %event.pubkey,
                            event_id = %event.id,
                            event_ts,
                            "skipping already-processed DM (exactly-once dedup hit)"
                        );
                        return Ok(false);
                    }

                    if is_backlog {
                        let age = startup_now.saturating_sub(event_ts);
                        tracing::info!(
                            sender = %event.pubkey,
                            event_id = %event.id,
                            event_ts,
                            age_seconds = age,
                            "backlog DM replayed from offline window (not yet processed; running handler)"
                        );
                    }

                    if let Err(e) = handle_proof_request(
                        &client,
                        &keys,
                        ln_dir.as_deref(),
                        btc_dir.as_deref(),
                        min_utxo_balance_sat,
                        allow_peer_verification,
                        max_active_vouches_per_peer,
                        &event,
                        &state,
                        vouch_expiry_days,
                        max_active_vouches_per_ln_node,
                    )
                    .await
                    {
                        tracing::warn!(sender = %event.pubkey, error = %e, "request rejected");
                    }

                    // Record this event id as processed so a restart
                    // never re-invokes the handler for it, then advance
                    // the last_seen_dm high-water mark. Both files are
                    // written via atomic tmp+rename; snapshot the
                    // processed map under the lock, drop the lock, then
                    // write. Inter-file drift is safe: whichever file
                    // wins, the exactly-once guard at the top of the
                    // handler short-circuits on the replayed event.
                    let (processed_snapshot, persist_last_seen) = {
                        let mut s = state.lock_state();
                        s.processed_events.insert(event.id, event_ts);
                        let persist_last_seen = if event_ts > s.last_seen_created_at {
                            s.last_seen_created_at = event_ts;
                            if is_backlog {
                                s.backlog_processed += 1;
                            }
                            Some(event_ts)
                        } else {
                            None
                        };
                        let snapshot: Vec<(u64, EventId)> = s
                            .processed_events
                            .iter()
                            .map(|(id, ts)| (*ts, *id))
                            .collect();
                        (snapshot, persist_last_seen)
                    };
                    if let Some(path) = &processed_events_path {
                        save_processed_events(path, &processed_snapshot);
                    }
                    if let (Some(ts), Some(path)) = (persist_last_seen, &last_seen_path) {
                        save_last_seen_dm(path, ts);
                    }
                }
                Ok(false) // continue
            }
        })
        .await?;

    Ok(())
}

/// Path where the daemon persists the most recent DM `created_at` it
/// has observed, so that after a restart it resumes the subscription
/// with `.since(last_seen)` and replays the offline backlog. Sits next
/// to the key file because that directory is already writable by the
/// daemon under our systemd config.
fn last_seen_dm_path(key_file: &std::path::Path) -> Option<std::path::PathBuf> {
    key_file.parent().map(|p| p.join("last_seen_dm.txt"))
}

fn load_last_seen_dm(path: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn save_last_seen_dm(path: &std::path::Path, ts: u64) {
    if let Err(e) = write_file_atomic(path, ts.to_string().as_bytes()) {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "failed to persist last_seen_dm atomically; offline-backlog resume after next restart may miss events"
        );
    }
}

/// Write a file atomically: stage bytes in `<path>.tmp`, fsync the data,
/// then rename onto `path`. Rename is atomic on POSIX, and on NTFS as
/// long as source and target are on the same volume (they are — both
/// sit in the daemon state directory next to the nsec). Callers can
/// trust that either the old contents or the new contents are visible
/// after a crash, never a torn half-written file.
fn write_file_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Best-effort parent-dir fsync so the rename itself is durable on
    // POSIX after a power loss. No-op on Windows (opening a directory
    // as a file isn't supported) where NTFS's rename + metadata
    // journaling already give us what we need.
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Path of the persistent event-id dedup file, next to the key file.
fn processed_events_path(key_file: &std::path::Path) -> Option<std::path::PathBuf> {
    key_file.parent().map(|p| p.join("processed_events.txt"))
}

/// Read `processed_events.txt`, drop entries older than TTL, and return
/// the surviving map. Also rewrites the file atomically if any pruning
/// happened, so the file is bounded over time. Any parse error on a
/// single line is skipped.
///
/// Format: one entry per line, `<created_at_secs> <event_id_hex>`.
fn load_processed_events(
    path: &std::path::Path,
    now: u64,
) -> std::collections::HashMap<EventId, u64> {
    use std::collections::HashMap;
    let mut map: HashMap<EventId, u64> = HashMap::new();
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return map,
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "processed_events read failed; starting with empty set (restart may reprocess some DMs)"
            );
            return map;
        }
    };
    let mut dropped = 0u64;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ' ');
        let ts = match parts.next().and_then(|s| s.parse::<u64>().ok()) {
            Some(t) => t,
            None => continue,
        };
        let id_hex = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        if now.saturating_sub(ts) >= PROCESSED_EVENTS_TTL_SECS {
            dropped += 1;
            continue;
        }
        let id = match EventId::from_hex(id_hex) {
            Ok(id) => id,
            Err(_) => continue,
        };
        map.insert(id, ts);
    }
    if dropped > 0 {
        let snapshot: Vec<(u64, EventId)> =
            map.iter().map(|(id, ts)| (*ts, *id)).collect();
        save_processed_events(path, &snapshot);
    }
    tracing::info!(
        loaded = map.len(),
        pruned = dropped,
        path = %path.display(),
        "processed_events dedup set loaded"
    );
    map
}

/// Write the full processed-events set atomically. Called after every
/// DM the handler completes, replacing the prior file contents. A
/// crash at any point leaves either the old file or the new file — the
/// exactly-once guard at the top of the handler tolerates either case.
fn save_processed_events(path: &std::path::Path, entries: &[(u64, EventId)]) {
    let mut sorted: Vec<&(u64, EventId)> = entries.iter().collect();
    sorted.sort_by_key(|(ts, _)| *ts);
    let mut body = String::with_capacity(sorted.len() * 80);
    for (ts, id) in sorted {
        body.push_str(&format!("{ts} {}\n", id.to_hex()));
    }
    if let Err(e) = write_file_atomic(path, body.as_bytes()) {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            "failed to persist processed_events atomically; exactly-once guarantee may degrade across the next restart"
        );
    }
}

/// Validate a proof-of-channel challenge string. Returns Ok if valid,
/// Err with a specific reason if not. Used by both cmd_vouch and
/// the daemon's handle_proof_request.
fn validate_challenge(challenge: &str, expected_npub: &str) -> Result<()> {
    let parts: Vec<&str> = challenge.split(':').collect();
    if parts.len() != 6
        || parts[0] != "soup-rendezvous"
        || parts[1] != "proof-of-channel"
        || parts[2] != "v0"
    {
        bail!(
            "invalid challenge format: must be soup-rendezvous:proof-of-channel:v0:<npub>:<hex>:<ts>"
        );
    }
    if parts[3] != expected_npub {
        bail!(
            "challenge contains wrong coordinator npub: expected {}, got {}",
            expected_npub,
            parts[3]
        );
    }
    let challenge_ts: u64 = parts[5].parse().context("invalid timestamp in challenge")?;
    let now = Timestamp::now().as_secs();
    let skew = now.abs_diff(challenge_ts);
    if skew > 300 {
        bail!(
            "challenge expired: timestamp is {} seconds from now (max 300)",
            skew
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_proof_request(
    client: &Client,
    keys: &Keys,
    lightning_dir: Option<&std::path::Path>,
    bitcoin_dir: Option<&std::path::Path>,
    min_utxo_balance_sat: u64,
    allow_peer_verification: bool,
    max_active_vouches_per_peer: u32,
    event: &Event,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
) -> Result<()> {
    let start = std::time::Instant::now();
    let sender = event.pubkey;
    let mut claimed_id = String::from("<pre-parse>");
    let mut proof_type = String::from("unknown");

    let result = handle_proof_request_core(
        client,
        keys,
        lightning_dir,
        bitcoin_dir,
        min_utxo_balance_sat,
        allow_peer_verification,
        max_active_vouches_per_peer,
        event,
        state,
        vouch_expiry_days,
        max_active_vouches_per_ln_node,
        &mut claimed_id,
        &mut proof_type,
    )
    .await;

    let outcome = match &result {
        Ok(_) => "verified".to_string(),
        Err(e) => {
            let msg = e.to_string();
            let category = msg
                .split(':')
                .next()
                .unwrap_or("error")
                .trim()
                .replace(' ', "_");
            format!("rejected:{category}")
        }
    };

    tracing::info!(
        audit = "proof_request",
        sender = %sender,
        proof_type = %proof_type,
        claimed_id = %claimed_id,
        outcome = %outcome,
        latency_ms = start.elapsed().as_millis() as u64,
    );

    result
}

/// True if `s` is exactly 64 lowercase hex characters — the format
/// bitcoin tx hashes are rendered in by every RPC we interact with.
fn is_valid_txid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Coarse bitcoin address validator. Accepts:
///   - legacy base58 (starts with 1, 3, m, n, 2; 25-35 chars of base58 alphabet)
///   - bech32 / bech32m (starts with bc1, tb1, bcrt1; 14-90 total chars)
/// This is an input-sanitization filter, not a consensus check. The
/// real address validity test happens in bitcoin-cli verifymessage /
/// gettxout. We just reject obviously malformed strings before
/// spawning a subprocess.
fn is_valid_btc_address(s: &str) -> bool {
    const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const BECH32_ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    let len = s.len();
    if !(14..=90).contains(&len) {
        return false;
    }

    // Legacy / P2SH / signet-legacy prefixes.
    if matches!(s.as_bytes().first(), Some(b'1' | b'3' | b'm' | b'n' | b'2')) {
        return s.bytes().all(|b| BASE58_ALPHABET.contains(&b));
    }

    // bech32 / bech32m.
    let lower = s.to_ascii_lowercase();
    for hrp in &["bc1", "tb1", "bcrt1"] {
        if let Some(rest) = lower.strip_prefix(hrp) {
            return rest.bytes().all(|b| BECH32_ALPHABET.contains(&b));
        }
    }

    false
}

/// Try a single channel-tier proof inside a multi-method DM.
///
/// Does everything the single-method handler does EXCEPT rate-limit
/// and replay cache checks — those happen once at the multi-method
/// entry. On success, publishes the vouch, updates the table, and
/// sends a confirmation DM. Returns Err on any verification failure
/// so the multi-method caller can fall through to the next proof.
#[allow(clippy::too_many_arguments)]
async fn try_channel_for_multi(
    client: &Client,
    keys: &Keys,
    lightning_dir: Option<&std::path::Path>,
    proof: &serde_json::Value,
    sender: &PublicKey,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
    coordinator_npub: &str,
    audit_claimed_id: &mut String,
) -> Result<()> {
    let node_id = proof["node_id"]
        .as_str()
        .context("missing node_id field")?;
    *audit_claimed_id = node_id.to_string();
    let zbase = proof["zbase"].as_str().context("missing zbase field")?;
    let challenge = proof["challenge"]
        .as_str()
        .context("missing challenge field")?;
    let channels = proof["channels"].as_u64().unwrap_or(0) as u32;
    let capacity_sat = proof["capacity_sat"].as_str().unwrap_or("0");

    validate_challenge(challenge, coordinator_npub)?;

    {
        let s = state.lock_state();
        let active_count = s.count_active_by_source_and_identifier(
            VerificationSource::LnChannel,
            node_id,
            &sender.to_hex(),
        );
        if active_count >= max_active_vouches_per_ln_node as usize {
            bail!(
                "vouch_cap_hit: LN node {node_id} already has {active_count} active vouches"
            );
        }
    }

    let ln_dir = lightning_dir.context("no lightning_dir configured")?;
    let output = std::process::Command::new("lightning-cli")
        .arg(format!("--lightning-dir={}", ln_dir.display()))
        .arg("checkmessage")
        .arg(challenge)
        .arg(zbase)
        .output()
        .context("failed to run lightning-cli checkmessage")?;
    if !output.status.success() {
        bail!("checkmessage_failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse checkmessage output")?;
    if !parsed["verified"].as_bool().unwrap_or(false) {
        bail!("signature_invalid_or_not_in_gossip: checkmessage verified=false");
    }
    let recovered_pubkey = parsed["pubkey"].as_str().unwrap_or("");
    if recovered_pubkey != node_id {
        bail!("node_id_mismatch: signature recovers to {recovered_pubkey}, not {node_id}");
    }

    let expires_at = Timestamp::now().as_secs() + vouch_expiry_days * 86400;
    let builder = events::build_vouch(
        sender,
        events::VouchTier::Channel,
        node_id,
        &[],
        None,
        expires_at,
    );
    let vouch_output = client.send_event_builder(builder).await?;
    {
        let mut s = state.lock_state();
        s.vouches_published += 1;
        s.proofs_verified += 1;
        s.record_active_vouch(
            sender.to_hex(),
            VerificationSource::LnChannel,
            node_id.to_string(),
            expires_at,
        );
    }
    let _ = (channels, capacity_sat); // accepted in payload, not republished
    tracing::info!(
        sender = %sender,
        node_id = %node_id,
        vouch_id = %vouch_output.id(),
        "channel vouch published (via multi)"
    );

    let confirmation = serde_json::json!({
        "type": "vouch_confirmation",
        "vouch_event_id": vouch_output.id().to_hex(),
        "tier_used": "channel",
        "node_id": node_id,
        "message": "vouched",
    });
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        sender,
        confirmation.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(*sender));
    client.send_event_builder(dm).await?;
    Ok(())
}

/// Try a single UTXO-tier proof inside a multi-method DM.
/// See `try_channel_for_multi` docstring for the contract.
#[allow(clippy::too_many_arguments)]
async fn try_utxo_for_multi(
    client: &Client,
    keys: &Keys,
    bitcoin_dir: Option<&std::path::Path>,
    min_utxo_balance_sat: u64,
    proof: &serde_json::Value,
    sender: &PublicKey,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
    coordinator_npub: &str,
    audit_claimed_id: &mut String,
) -> Result<()> {
    let btc_address = proof["btc_address"]
        .as_str()
        .context("missing btc_address field")?;
    *audit_claimed_id = btc_address.to_string();
    let signature = proof["signature"]
        .as_str()
        .context("missing signature field")?;
    let challenge = proof["challenge"]
        .as_str()
        .context("missing challenge field")?;
    let utxo_txid = proof["utxo_txid"]
        .as_str()
        .context("missing utxo_txid field")?;
    let utxo_vout = proof["utxo_vout"]
        .as_u64()
        .context("missing utxo_vout field")? as u32;
    // Host-declared LN contact for the published vouch. NOT verified
    // by the UTXO proof — the chain anchor is the bitcoin address. The
    // host's word for which LN node to dial is enough for wallets;
    // first-dial failure invalidates the binding at no cost.
    let ln_node_id = proof["ln_node_id"]
        .as_str()
        .context("missing ln_node_id field (required since vouches are contact pointers)")?;
    let ln_addresses: Vec<String> = proof["ln_addresses"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    if !is_valid_txid(utxo_txid) {
        bail!("format_invalid: utxo_txid must be 64 lowercase hex characters");
    }
    if !is_valid_btc_address(btc_address) {
        bail!("format_invalid: btc_address not recognized");
    }

    validate_utxo_challenge(challenge, coordinator_npub)?;

    let btc_hash = events::btc_address_hash(btc_address);

    {
        let s = state.lock_state();
        let active_count = s.count_active_by_source_and_identifier(
            VerificationSource::BtcUtxo,
            &btc_hash,
            &sender.to_hex(),
        );
        if active_count >= max_active_vouches_per_ln_node as usize {
            bail!(
                "vouch_cap_hit: bitcoin address (hash {btc_hash}) already has {active_count} active vouches"
            );
        }
    }

    let btc_dir =
        bitcoin_dir.context("btc_verification_not_configured: no bitcoin_dir set")?;
    if !verify_btc_signature(btc_dir, btc_address, signature, challenge)? {
        bail!("signature_invalid: verifymessage returned false");
    }
    let verified_balance_sat =
        check_utxo(btc_dir, utxo_txid, utxo_vout, btc_address, min_utxo_balance_sat)?;

    let expires_at = Timestamp::now().as_secs() + vouch_expiry_days * 86400;
    let builder = events::build_vouch(
        sender,
        events::VouchTier::Utxo,
        ln_node_id,
        &ln_addresses,
        Some(&btc_hash),
        expires_at,
    );
    let vouch_output = client.send_event_builder(builder).await?;
    {
        let mut s = state.lock_state();
        s.vouches_published += 1;
        s.proofs_verified += 1;
        s.record_active_vouch(
            sender.to_hex(),
            VerificationSource::BtcUtxo,
            btc_hash.clone(),
            expires_at,
        );
    }
    let _ = verified_balance_sat; // verified ≥ floor; not republished
    tracing::info!(
        sender = %sender,
        btc_address_hash = %btc_hash,
        ln_node_id = %ln_node_id,
        vouch_id = %vouch_output.id(),
        "utxo vouch published (via multi)"
    );

    let confirmation = serde_json::json!({
        "type": "vouch_confirmation",
        "vouch_event_id": vouch_output.id().to_hex(),
        "tier_used": "utxo",
        "ln_node_id": ln_node_id,
        "message": "vouched",
    });
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        sender,
        confirmation.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(*sender));
    client.send_event_builder(dm).await?;
    Ok(())
}

/// Try a single peer-tier proof inside a multi-method DM.
/// See `try_channel_for_multi` docstring for the contract.
#[allow(clippy::too_many_arguments)]
async fn try_peer_for_multi(
    client: &Client,
    keys: &Keys,
    lightning_dir: Option<&std::path::Path>,
    max_active_vouches_per_peer: u32,
    proof: &serde_json::Value,
    sender: &PublicKey,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    coordinator_npub: &str,
    audit_claimed_id: &mut String,
) -> Result<()> {
    let ln_node_id = proof["ln_node_id"]
        .as_str()
        .context("missing ln_node_id field")?;
    *audit_claimed_id = ln_node_id.to_string();
    let challenge = proof["challenge"]
        .as_str()
        .context("missing challenge field")?;
    let addresses: Vec<String> = proof["addresses"]
        .as_array()
        .context("missing addresses array")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    if addresses.is_empty() {
        bail!("format_invalid: addresses array is empty");
    }

    validate_peer_challenge(challenge, coordinator_npub)?;

    {
        let s = state.lock_state();
        let active_count = s.count_active_by_source_and_identifier(
            VerificationSource::LnPeer,
            ln_node_id,
            &sender.to_hex(),
        );
        if active_count >= max_active_vouches_per_peer as usize {
            bail!(
                "vouch_cap_hit: peer {ln_node_id} already has {active_count} active peer-tier vouches"
            );
        }
    }

    let ln_dir = lightning_dir.context("no lightning_dir configured for peer verification")?;
    let peer_result = try_peer_connect(ln_dir, ln_node_id, &addresses)?;

    let expires_at = Timestamp::now().as_secs() + vouch_expiry_days * 86400;
    let builder = events::build_vouch(
        sender,
        events::VouchTier::Peer,
        &peer_result.verified_pubkey,
        &addresses,
        None,
        expires_at,
    );
    let vouch_output = client.send_event_builder(builder).await?;
    {
        let mut s = state.lock_state();
        s.vouches_published += 1;
        s.proofs_verified += 1;
        s.record_active_vouch(
            sender.to_hex(),
            VerificationSource::LnPeer,
            peer_result.verified_pubkey.clone(),
            expires_at,
        );
    }
    let _ = peer_result.features_hex; // observed during handshake, not republished
    tracing::info!(
        sender = %sender,
        ln_node_id = %peer_result.verified_pubkey,
        addresses = ?addresses,
        vouch_id = %vouch_output.id(),
        "peer vouch published (via multi)"
    );

    let confirmation = serde_json::json!({
        "type": "vouch_confirmation",
        "vouch_event_id": vouch_output.id().to_hex(),
        "tier_used": "peer",
        "ln_node_id": peer_result.verified_pubkey,
        "message": "vouched",
    });
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        sender,
        confirmation.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(*sender));
    client.send_event_builder(dm).await?;
    Ok(())
}

/// Handle an incoming `proof_multi` DM: a single request carrying one
/// or more per-method proofs, ordered by the host's preference. The
/// coordinator tries each in order and publishes a vouch at the first
/// tier that verifies. Rate-limit and replay-cache checks run once
/// for the whole DM; per-method verification + cap checks run per
/// proof. On all-methods-failed, aggregates reasons and rejects.
#[allow(clippy::too_many_arguments)]
async fn handle_multi_proof(
    client: &Client,
    keys: &Keys,
    lightning_dir: Option<&std::path::Path>,
    bitcoin_dir: Option<&std::path::Path>,
    min_utxo_balance_sat: u64,
    allow_peer_verification: bool,
    max_active_vouches_per_peer: u32,
    request: &serde_json::Value,
    sender: &PublicKey,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
    audit_claimed_id: &mut String,
    audit_proof_type: &mut String,
) -> Result<()> {
    {
        let mut s = state.lock_state();
        s.proofs_received += 1;
    }

    let proofs = request["proofs"]
        .as_array()
        .context("format_invalid: missing proofs array")?;
    if proofs.is_empty() {
        state
            .lock_state()
            .proofs_rejected_format += 1;
        bail!("format_invalid: empty proofs array");
    }

    // Pick rate-limit bucket: ChainAnchored if any chain-anchored proof
    // is present, Peer otherwise. Counts once for the whole DM.
    let has_chain_anchored = proofs.iter().any(|p| {
        matches!(
            p["type"].as_str(),
            Some("proof_of_channel") | Some("proof_of_utxo")
        )
    });
    let kind = if has_chain_anchored {
        ProofKind::ChainAnchored
    } else {
        ProofKind::Peer
    };
    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_rate(sender, kind) {
            s.proofs_rate_limited += 1;
            return Err(e);
        }
    }

    // Replay cache keyed on the first proof's challenge (hosts SHOULD
    // reuse a single challenge across the bundle, but even if they
    // don't this still provides replay protection for the common case).
    let first_challenge = proofs[0]["challenge"]
        .as_str()
        .context("format_invalid: first proof has no challenge")?;
    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_replay(sender, first_challenge) {
            s.proofs_replayed += 1;
            return Err(e);
        }
    }

    tracing::info!(
        sender = %sender,
        num_proofs = proofs.len(),
        "proof-of-multi request received"
    );

    let coordinator_npub = keys.public_key().to_bech32()?;
    let mut errors: Vec<String> = Vec::new();

    for proof in proofs {
        let proof_type = proof["type"].as_str().unwrap_or("");
        let outcome: Result<VerificationSource> = match proof_type {
            "proof_of_channel" => try_channel_for_multi(
                client,
                keys,
                lightning_dir,
                proof,
                sender,
                state,
                vouch_expiry_days,
                max_active_vouches_per_ln_node,
                &coordinator_npub,
                audit_claimed_id,
            )
            .await
            .map(|()| VerificationSource::LnChannel),

            "proof_of_utxo" => try_utxo_for_multi(
                client,
                keys,
                bitcoin_dir,
                min_utxo_balance_sat,
                proof,
                sender,
                state,
                vouch_expiry_days,
                max_active_vouches_per_ln_node,
                &coordinator_npub,
                audit_claimed_id,
            )
            .await
            .map(|()| VerificationSource::BtcUtxo),

            "proof_of_peer" => {
                if !allow_peer_verification {
                    Err(anyhow::anyhow!(
                        "peer_verification_disabled: coordinator does not accept peer proofs"
                    ))
                } else {
                    try_peer_for_multi(
                        client,
                        keys,
                        lightning_dir,
                        max_active_vouches_per_peer,
                        proof,
                        sender,
                        state,
                        vouch_expiry_days,
                        &coordinator_npub,
                        audit_claimed_id,
                    )
                    .await
                    .map(|()| VerificationSource::LnPeer)
                }
            }

            other => Err(anyhow::anyhow!("unknown_proof_type: {other}")),
        };

        match outcome {
            Ok(source) => {
                *audit_proof_type = source.as_str().to_string();
                return Ok(());
            }
            Err(e) => errors.push(format!("{proof_type}: {e}")),
        }
    }

    // Every submitted proof failed.
    {
        let mut s = state.lock_state();
        s.proofs_rejected_signature += 1;
    }
    bail!("all_methods_failed: {}", errors.join("; "));
}

/// Handle an incoming proof-of-UTXO request. Mirrors the structure
/// of the proof-of-channel handler but verifies via bitcoin-cli
/// instead of lightning-cli.
#[allow(clippy::too_many_arguments)]
async fn handle_utxo_proof(
    client: &Client,
    keys: &Keys,
    bitcoin_dir: Option<&std::path::Path>,
    min_utxo_balance_sat: u64,
    request: &serde_json::Value,
    sender: &PublicKey,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
    audit_claimed_id: &mut String,
) -> Result<()> {
    {
        let mut s = state.lock_state();
        s.proofs_received += 1;
    }

    // Rate limit + replay cache (shared primitives).
    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_rate(sender, ProofKind::ChainAnchored) {
            s.proofs_rate_limited += 1;
            return Err(e);
        }
    }

    // Parse required fields.
    let btc_address = request["btc_address"]
        .as_str()
        .context("missing btc_address field")?;
    *audit_claimed_id = btc_address.to_string();
    let signature = request["signature"]
        .as_str()
        .context("missing signature field")?;
    let challenge = request["challenge"]
        .as_str()
        .context("missing challenge field")?;
    let utxo_txid = request["utxo_txid"]
        .as_str()
        .context("missing utxo_txid field")?;
    let utxo_vout = request["utxo_vout"]
        .as_u64()
        .context("missing utxo_vout field (expected u32)")? as u32;
    // Host-declared LN contact for the published vouch. Required as
    // of the unified-vouch format — vouches are contact pointers and
    // utxo-tier needs an LN node to dial. Not verified here (the chain
    // anchor is the bitcoin address); first-dial failure invalidates
    // a bad declaration at no protocol cost.
    let ln_node_id = request["ln_node_id"]
        .as_str()
        .context("missing ln_node_id field (required since vouches are contact pointers)")?;
    let ln_addresses: Vec<String> = request["ln_addresses"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // Format-validate before spending any subprocess work. These
    // checks are cheap and reject malformed inputs in microseconds
    // instead of paying for a bitcoin-cli round trip that would also
    // reject them, just slower.
    if !is_valid_txid(utxo_txid) {
        state
            .lock_state()
            .proofs_rejected_format += 1;
        bail!("format_invalid: utxo_txid must be 64 lowercase hex characters");
    }
    if !is_valid_btc_address(btc_address) {
        state
            .lock_state()
            .proofs_rejected_format += 1;
        bail!(
            "format_invalid: btc_address is not a recognized bitcoin address format"
        );
    }

    // Validate the challenge format (prefix, npub, freshness).
    let coordinator_npub = keys.public_key().to_bech32()?;
    if let Err(e) = validate_utxo_challenge(challenge, &coordinator_npub) {
        state
            .lock_state()
            .proofs_rejected_format += 1;
        return Err(e);
    }

    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_replay(sender, challenge) {
            s.proofs_replayed += 1;
            return Err(e);
        }
    }

    // Per-bitcoin-address cap check BEFORE subprocess work. Uses a
    // truncated SHA-256 of the address as the cap key so the in-memory
    // and on-relay views stay consistent (the published vouch carries
    // only the hash, not the address).
    let btc_hash = events::btc_address_hash(btc_address);
    {
        let s = state.lock_state();
        let active_count = s.count_active_by_source_and_identifier(
            VerificationSource::BtcUtxo,
            &btc_hash,
            &sender.to_hex(),
        );
        if active_count >= max_active_vouches_per_ln_node as usize {
            drop(s);
            state
                .lock_state()
                .proofs_rejected_cap_hit += 1;
            bail!(
                "vouch cap hit: bitcoin address (hash {btc_hash}) already has {active_count} active vouches (cap {max_active_vouches_per_ln_node})"
            );
        }
    }

    let btc_dir = bitcoin_dir
        .context("btc_verification_not_configured: coordinator has no bitcoin_dir set")?;

    // Cryptographic check: signature was made by the claimed address.
    if !verify_btc_signature(btc_dir, btc_address, signature, challenge)? {
        state
            .lock_state()
            .proofs_rejected_signature += 1;
        bail!(
            "signature verification failed: verifymessage returned false for address {btc_address}"
        );
    }

    // UTXO check: exists, unspent, matches address, meets threshold.
    let verified_balance_sat =
        check_utxo(btc_dir, utxo_txid, utxo_vout, btc_address, min_utxo_balance_sat)?;

    state.lock_state().proofs_verified += 1;

    // Publish the vouch with NIP-40 expiration.
    let expires_at = Timestamp::now().as_secs() + vouch_expiry_days * 86400;
    let builder = events::build_vouch(
        sender,
        events::VouchTier::Utxo,
        ln_node_id,
        &ln_addresses,
        Some(&btc_hash),
        expires_at,
    );
    let vouch_output = client.send_event_builder(builder).await?;
    {
        let mut s = state.lock_state();
        s.vouches_published += 1;
        s.record_active_vouch(
            sender.to_hex(),
            VerificationSource::BtcUtxo,
            btc_hash.clone(),
            expires_at,
        );
    }
    let _ = (utxo_txid, utxo_vout, verified_balance_sat); // verified, not republished
    tracing::info!(
        sender = %sender,
        btc_address_hash = %btc_hash,
        ln_node_id = %ln_node_id,
        vouch_id = %vouch_output.id(),
        "utxo vouch published"
    );

    // Send confirmation DM back.
    let confirmation = serde_json::json!({
        "type": "vouch_confirmation",
        "vouch_event_id": vouch_output.id().to_hex(),
        "ln_node_id": ln_node_id,
        "message": "vouched",
    });
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        sender,
        confirmation.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(*sender));
    client.send_event_builder(dm).await?;
    tracing::info!(sender = %sender, "confirmation DM sent");

    Ok(())
}

/// Handle an incoming proof-of-peer request. Weakest-tier verification:
/// the host's BOLT-8 Noise handshake with the coordinator's CLN proves
/// key possession at the claimed address, but there's no chain anchor.
/// Off by default on mainnet (`allow_peer_verification = false`).
#[allow(clippy::too_many_arguments)]
async fn handle_peer_proof(
    client: &Client,
    keys: &Keys,
    lightning_dir: Option<&std::path::Path>,
    allow_peer_verification: bool,
    max_active_vouches_per_peer: u32,
    request: &serde_json::Value,
    sender: &PublicKey,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    audit_claimed_id: &mut String,
) -> Result<()> {
    if !allow_peer_verification {
        bail!(
            "peer_verification_disabled: this coordinator does not accept proof-of-peer requests"
        );
    }

    {
        let mut s = state.lock_state();
        s.proofs_received += 1;
    }

    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_rate(sender, ProofKind::Peer) {
            s.proofs_rate_limited += 1;
            return Err(e);
        }
    }

    // Parse required fields.
    let ln_node_id = request["ln_node_id"]
        .as_str()
        .context("missing ln_node_id field")?;
    *audit_claimed_id = ln_node_id.to_string();
    let challenge = request["challenge"]
        .as_str()
        .context("missing challenge field")?;
    let addresses: Vec<String> = request["addresses"]
        .as_array()
        .context("missing addresses array")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    if addresses.is_empty() {
        state
            .lock_state()
            .proofs_rejected_format += 1;
        bail!("format_invalid: addresses array is empty");
    }

    // Challenge format + freshness.
    let coordinator_npub = keys.public_key().to_bech32()?;
    if let Err(e) = validate_peer_challenge(challenge, &coordinator_npub) {
        state
            .lock_state()
            .proofs_rejected_format += 1;
        return Err(e);
    }

    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_replay(sender, challenge) {
            s.proofs_replayed += 1;
            return Err(e);
        }
    }

    // Per-peer-pubkey cap check — tighter than channel/utxo because
    // peer has no chain anchor.
    {
        let s = state.lock_state();
        let active_count = s.count_active_by_source_and_identifier(
            VerificationSource::LnPeer,
            ln_node_id,
            &sender.to_hex(),
        );
        if active_count >= max_active_vouches_per_peer as usize {
            drop(s);
            state
                .lock_state()
                .proofs_rejected_cap_hit += 1;
            bail!(
                "vouch cap hit: peer {ln_node_id} already has {active_count} active peer-tier vouches (cap {max_active_vouches_per_peer})"
            );
        }
    }

    // Attempt BOLT-8 handshake. Handshake success == key possession.
    let ln_dir = lightning_dir
        .context("peer_verification_no_lightning_dir: coordinator has no lightning_dir set")?;
    let peer_result = match try_peer_connect(ln_dir, ln_node_id, &addresses) {
        Ok(r) => r,
        Err(e) => {
            state
                .lock_state()
                .proofs_rejected_signature += 1;
            return Err(e);
        }
    };

    state.lock_state().proofs_verified += 1;

    // Publish the vouch.
    let expires_at = Timestamp::now().as_secs() + vouch_expiry_days * 86400;
    let builder = events::build_vouch(
        sender,
        events::VouchTier::Peer,
        &peer_result.verified_pubkey,
        &addresses,
        None,
        expires_at,
    );
    let vouch_output = client.send_event_builder(builder).await?;
    {
        let mut s = state.lock_state();
        s.vouches_published += 1;
        s.record_active_vouch(
            sender.to_hex(),
            VerificationSource::LnPeer,
            peer_result.verified_pubkey.clone(),
            expires_at,
        );
    }
    let _ = peer_result.features_hex.clone(); // observed during handshake, not republished
    tracing::info!(
        sender = %sender,
        ln_node_id = %peer_result.verified_pubkey,
        addresses = ?addresses,
        vouch_id = %vouch_output.id(),
        "peer vouch published"
    );

    // Confirmation DM back.
    let confirmation = serde_json::json!({
        "type": "vouch_confirmation",
        "vouch_event_id": vouch_output.id().to_hex(),
        "ln_node_id": peer_result.verified_pubkey,
        "message": "vouched",
    });
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        sender,
        confirmation.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(*sender));
    client.send_event_builder(dm).await?;
    tracing::info!(sender = %sender, "confirmation DM sent");

    Ok(())
}

/// Validate a proof-of-peer challenge. Same shape as channel/utxo
/// with a different action tag. Note the DM payload carries the
/// challenge but no signature — the BOLT-8 Noise handshake is the
/// proof. The challenge exists for freshness + replay protection.
fn validate_peer_challenge(challenge: &str, expected_npub: &str) -> Result<()> {
    let parts: Vec<&str> = challenge.split(':').collect();
    if parts.len() != 6
        || parts[0] != "soup-rendezvous"
        || parts[1] != "proof-of-peer"
        || parts[2] != "v0"
    {
        bail!(
            "invalid challenge format: must be soup-rendezvous:proof-of-peer:v0:<npub>:<hex>:<ts>"
        );
    }
    if parts[3] != expected_npub {
        bail!(
            "challenge contains wrong coordinator npub: expected {}, got {}",
            expected_npub,
            parts[3]
        );
    }
    let challenge_ts: u64 = parts[5].parse().context("invalid timestamp in challenge")?;
    let now = Timestamp::now().as_secs();
    let skew = now.abs_diff(challenge_ts);
    if skew > 300 {
        bail!(
            "challenge expired: timestamp is {} seconds from now (max 300)",
            skew
        );
    }
    Ok(())
}

/// Validate a proof-of-UTXO challenge string. Same shape as the
/// channel version but with a different action tag.
fn validate_utxo_challenge(challenge: &str, expected_npub: &str) -> Result<()> {
    let parts: Vec<&str> = challenge.split(':').collect();
    if parts.len() != 6
        || parts[0] != "soup-rendezvous"
        || parts[1] != "proof-of-utxo"
        || parts[2] != "v0"
    {
        bail!(
            "invalid challenge format: must be soup-rendezvous:proof-of-utxo:v0:<npub>:<hex>:<ts>"
        );
    }
    if parts[3] != expected_npub {
        bail!(
            "challenge contains wrong coordinator npub: expected {}, got {}",
            expected_npub,
            parts[3]
        );
    }
    let challenge_ts: u64 = parts[5].parse().context("invalid timestamp in challenge")?;
    let now = Timestamp::now().as_secs();
    let skew = now.abs_diff(challenge_ts);
    if skew > 300 {
        bail!(
            "challenge expired: timestamp is {} seconds from now (max 300)",
            skew
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_proof_request_core(
    client: &Client,
    keys: &Keys,
    lightning_dir: Option<&std::path::Path>,
    bitcoin_dir: Option<&std::path::Path>,
    min_utxo_balance_sat: u64,
    allow_peer_verification: bool,
    max_active_vouches_per_peer: u32,
    event: &Event,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
    vouch_expiry_days: u64,
    max_active_vouches_per_ln_node: u32,
    audit_claimed_id: &mut String,
    audit_proof_type: &mut String,
) -> Result<()> {
    let sender = event.pubkey;

    // Decrypt the NIP-44 DM
    let plaintext = match nip44::decrypt(keys.secret_key(), &sender, &event.content) {
        Ok(p) => p,
        Err(e) => {
            state
                .lock_state()
                .dms_decrypt_failed += 1;
            return Err(anyhow::anyhow!(
                "failed to decrypt DM (not NIP-44 or not addressed to us): {}",
                e
            ));
        }
    };

    // Parse the request
    let request: serde_json::Value =
        serde_json::from_str(&plaintext).context("request payload is not valid json")?;

    let req_type = request["type"].as_str().unwrap_or("");

    // Route on proof type. Use VerificationSource::as_str() so the
    // audit-log proof_type labels live in one place.
    match req_type {
        "proof_of_channel" => {
            *audit_proof_type = String::from(VerificationSource::LnChannel.as_str());
        }
        "proof_of_utxo" => {
            *audit_proof_type = String::from(VerificationSource::BtcUtxo.as_str());
            return handle_utxo_proof(
                client,
                keys,
                bitcoin_dir,
                min_utxo_balance_sat,
                &request,
                &sender,
                state,
                vouch_expiry_days,
                max_active_vouches_per_ln_node,
                audit_claimed_id,
            )
            .await;
        }
        "proof_of_peer" => {
            *audit_proof_type = String::from(VerificationSource::LnPeer.as_str());
            return handle_peer_proof(
                client,
                keys,
                lightning_dir,
                allow_peer_verification,
                max_active_vouches_per_peer,
                &request,
                &sender,
                state,
                vouch_expiry_days,
                audit_claimed_id,
            )
            .await;
        }
        "proof_multi" => {
            *audit_proof_type = String::from("multi");
            return handle_multi_proof(
                client,
                keys,
                lightning_dir,
                bitcoin_dir,
                min_utxo_balance_sat,
                allow_peer_verification,
                max_active_vouches_per_peer,
                &request,
                &sender,
                state,
                vouch_expiry_days,
                max_active_vouches_per_ln_node,
                audit_claimed_id,
                audit_proof_type,
            )
            .await;
        }
        other => {
            tracing::debug!(
                sender = %sender,
                req_type = other,
                "ignoring unknown proof type DM"
            );
            return Ok(());
        }
    }

    // From this point we know it's a proof_of_channel request.
    {
        let mut s = state.lock_state();
        s.proofs_received += 1;
    }

    // Rate limit check (before doing any expensive crypto work)
    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_rate(&sender, ProofKind::ChainAnchored) {
            s.proofs_rate_limited += 1;
            return Err(e);
        }
    }

    let node_id = request["node_id"]
        .as_str()
        .context("missing node_id field")?;
    *audit_claimed_id = node_id.to_string();
    let zbase = request["zbase"].as_str().context("missing zbase field")?;
    let challenge = request["challenge"]
        .as_str()
        .context("missing challenge field")?;
    let channels = request["channels"].as_u64().unwrap_or(0) as u32;
    let capacity_sat = request["capacity_sat"].as_str().unwrap_or("0");

    tracing::info!(
        sender = %sender,
        node_id = %node_id,
        channels,
        "proof-of-channel request received"
    );

    // Refuse to process anything until the vouch table has been loaded
    // from relays at startup. This prevents under-counting at cap check
    // time during the brief window before the initial sync completes.
    if !state.lock_state().vouch_table_loaded {
        bail!("state_not_loaded: coordinator is still loading vouch table from relays, retry in a few seconds");
    }

    // Validate the challenge
    let coordinator_npub = keys.public_key().to_bech32()?;
    if let Err(e) = validate_challenge(challenge, &coordinator_npub) {
        state
            .lock_state()
            .proofs_rejected_format += 1;
        return Err(e);
    }

    // Replay check (same sender + challenge within 10 min => drop)
    {
        let mut s = state.lock_state();
        if let Err(e) = s.check_replay(&sender, challenge) {
            s.proofs_replayed += 1;
            return Err(e);
        }
    }

    // Per-LN-node cap check BEFORE verification — cheap in-memory
    // lookup. Safe pre-verification because the cap counts only our
    // own published vouches (authoritative), not the caller's claim.
    {
        let s = state.lock_state();
        let active_count = s.count_active_by_source_and_identifier(
            VerificationSource::LnChannel,
            node_id,
            &sender.to_hex(),
        );
        if active_count >= max_active_vouches_per_ln_node as usize {
            drop(s);
            state
                .lock_state()
                .proofs_rejected_cap_hit += 1;
            bail!(
                "vouch cap hit: LN node {node_id} already has {active_count} active vouches (cap {max_active_vouches_per_ln_node})"
            );
        }
    }

    // Verify signature via lightning-cli
    let ln_dir = lightning_dir.context("daemon running without --lightning-dir, cannot verify")?;
    let output = std::process::Command::new("lightning-cli")
        .arg(format!("--lightning-dir={}", ln_dir.display()))
        .arg("checkmessage")
        .arg(challenge)
        .arg(zbase)
        .output()
        .context("failed to run lightning-cli checkmessage")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!("checkmessage failed: {stdout} {stderr}");
    }

    let result: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("failed to parse checkmessage output")?;

    let verified = result["verified"].as_bool().unwrap_or(false);
    let recovered_pubkey = result["pubkey"].as_str().unwrap_or("");

    if !verified {
        state
            .lock_state()
            .proofs_rejected_signature += 1;
        bail!("signature verification failed: checkmessage returned verified=false");
    }
    if recovered_pubkey != node_id {
        state
            .lock_state()
            .proofs_rejected_signature += 1;
        bail!(
            "node_id mismatch: claimed {} but signature recovers to {}",
            node_id,
            recovered_pubkey
        );
    }

    state.lock_state().proofs_verified += 1;

    // Publish the vouch with NIP-40 expiration. Host must re-prove
    // before this window closes or the vouch is dropped by relays.
    let expires_at = Timestamp::now().as_secs() + vouch_expiry_days * 86400;
    let builder = events::build_vouch(
        &sender,
        events::VouchTier::Channel,
        node_id,
        &[],
        None,
        expires_at,
    );
    let vouch_output = client.send_event_builder(builder).await?;
    {
        let mut s = state.lock_state();
        s.vouches_published += 1;
        s.record_active_vouch(
            sender.to_hex(),
            VerificationSource::LnChannel,
            node_id.to_string(),
            expires_at,
        );
    }
    let _ = (channels, capacity_sat); // accepted in payload, not republished
    tracing::info!(
        sender = %sender,
        node_id = %node_id,
        vouch_id = %vouch_output.id(),
        "vouch published"
    );

    // Send confirmation DM back
    let confirmation = serde_json::json!({
        "type": "vouch_confirmation",
        "vouch_event_id": vouch_output.id().to_hex(),
        "node_id": node_id,
        "message": "vouched",
    });
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &sender,
        confirmation.to_string(),
        nip44::Version::default(),
    )?;
    let dm = EventBuilder::new(Kind::Custom(4), encrypted).tag(Tag::public_key(sender));
    client.send_event_builder(dm).await?;
    tracing::info!(sender = %sender, "confirmation DM sent");

    Ok(())
}

// --- helpers ---

fn load_keys(key_file: &PathBuf) -> Result<Keys> {
    let content = std::fs::read_to_string(key_file)
        .with_context(|| format!("reading key file at {}", key_file.display()))?;
    let trimmed = content.trim();
    let secret = if trimmed.starts_with("nsec") {
        SecretKey::from_bech32(trimmed)?
    } else {
        SecretKey::from_hex(trimmed)?
    };
    Ok(Keys::new(secret))
}

/// Count active vouches this coordinator has issued for a given LN
/// node via a relay query. Used by the one-shot CLI `vouch` path
/// where the daemon's in-memory table isn't available.
async fn count_active_vouches_for_ln_node(
    client: &Client,
    coordinator_pubkey: &PublicKey,
    ln_node_id: &str,
    exclude_d_tag: &str,
) -> Result<usize> {
    let filter = Filter::new()
        .kind(kinds::VOUCH)
        .author(*coordinator_pubkey)
        .limit(500);

    let events = client.fetch_events(filter, Duration::from_secs(5)).await?;

    let count = events
        .into_iter()
        .filter(events::vouch_is_active)
        .filter(|e| events::vouch_ln_node_id(e).as_deref() == Some(ln_node_id))
        .filter(|e| events::get_d_tag(e).as_deref() != Some(exclude_d_tag))
        .count();

    Ok(count)
}

/// Query relays for every vouch this coordinator has published and
/// rebuild the in-memory table from authoritative Nostr state. Called
/// at daemon startup and periodically thereafter to catch drift.
///
/// Returns `Ok(count)` on success (number of entries loaded). On
/// error, leaves the existing table untouched so transient relay
/// flakes don't flush our state.
async fn sync_vouch_table(
    client: &Client,
    coordinator_pubkey: &PublicKey,
    state: &std::sync::Arc<std::sync::Mutex<DaemonState>>,
) -> Result<usize> {
    let filter = Filter::new()
        .kind(kinds::VOUCH)
        .author(*coordinator_pubkey)
        .limit(1000);

    let events = client
        .fetch_events(filter, Duration::from_secs(10))
        .await
        .context("relay query for vouch table sync")?;

    let mut fresh = std::collections::HashMap::new();
    let now = Timestamp::now().as_secs();

    for event in events.into_iter() {
        let Some(d_tag) = events::get_d_tag(&event) else {
            continue;
        };

        // Pull NIP-40 expiration from tags
        let mut expires_at = 0u64;
        for tag in event.tags.iter() {
            if tag.kind() == TagKind::Expiration
                && let Some(s) = tag.content()
                && let Ok(e) = s.parse::<u64>()
            {
                expires_at = e;
                break;
            }
        }

        // Drop events already past their NIP-40 expiration — relays may
        // still serve them briefly but they have no active authority.
        if expires_at != 0 && expires_at <= now {
            continue;
        }

        // Parse content — status, verification_source, and the
        // method-specific identifier field.
        let content_v: serde_json::Value = match serde_json::from_str(&event.content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let status = content_v
            .get("status")
            .and_then(|s| s.as_str())
            .map(|s| {
                if s == "revoked" {
                    VouchStatus::Revoked
                } else {
                    VouchStatus::Active
                }
            })
            .unwrap_or(VouchStatus::Active);

        // Tier comes from the `["l", ...]` tag (the unified format
        // dropped the redundant `verification_source` content field).
        // Falls back to LnChannel for legacy events that predate either.
        let source = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::L)))
            .and_then(|t| t.content())
            .and_then(events::VouchTier::from_l_tag)
            .map(|t| match t {
                events::VouchTier::Channel => VerificationSource::LnChannel,
                events::VouchTier::Utxo => VerificationSource::BtcUtxo,
                events::VouchTier::Peer => VerificationSource::LnPeer,
            })
            .or_else(|| {
                content_v
                    .get("verification_source")
                    .and_then(|s| s.as_str())
                    .and_then(VerificationSource::from_content_str)
            })
            .unwrap_or(VerificationSource::LnChannel);

        // Extract the cap-tracking identifier per tier:
        // - channel/peer: ln_node_id (same as the contact pubkey)
        // - utxo: the daemon-internal `btc_hash` tag (truncated SHA-256
        //   of the verified bitcoin address). Lets cap state survive
        //   restarts without leaking the address. Legacy events with a
        //   plaintext `btc_address` content field fall back to that.
        let identifier = match source {
            VerificationSource::LnChannel | VerificationSource::LnPeer => {
                events::vouch_ln_node_id(&event).or_else(|| {
                    // Legacy peer-tier events used "peer_pubkey" content key.
                    content_v
                        .get("peer_pubkey")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
            }
            VerificationSource::BtcUtxo => events::get_tag_value(&event, "btc_hash").or_else(|| {
                content_v
                    .get("btc_address")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            }),
        };
        let Some(identifier) = identifier else {
            continue;
        };

        fresh.insert(
            d_tag,
            ActiveVouch {
                source,
                identifier,
                expires_at,
                status,
            },
        );
    }

    let count = fresh.len();

    let mut guard = state.lock_state();

    // Log drift if this isn't the initial sync.
    if guard.vouch_table_loaded {
        let prev_size = guard.active_vouches.len();
        if prev_size != count {
            tracing::warn!(
                prev_size,
                new_size = count,
                "vouch table re-sync changed entry count"
            );
        }
    }

    guard.active_vouches = fresh;
    guard.vouch_table_loaded = true;
    guard.vouch_table_last_synced_at = now;

    Ok(count)
}

/// Result of a successful BOLT-8 peer handshake attempt.
struct PeerConnectResult {
    verified_pubkey: String,
    features_hex: Option<String>,
}

/// Initiate an outbound BOLT-8 peer connection via the local CLN,
/// trying each advertised address in turn. On success the Noise
/// handshake has proven the remote controls the claimed pubkey;
/// we immediately disconnect since the handshake itself was the
/// proof and there's no reason to stay peered.
fn try_peer_connect(
    lightning_dir: &std::path::Path,
    peer_id: &str,
    addresses: &[String],
) -> Result<PeerConnectResult> {
    if addresses.is_empty() {
        bail!("peer_connect_failed: no addresses provided for {peer_id}");
    }

    let mut last_err = String::new();
    for addr in addresses {
        let target = format!("{peer_id}@{addr}");
        let output = std::process::Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", lightning_dir.display()))
            .arg("connect")
            .arg(&target)
            .output()
            .context("failed to run lightning-cli connect")?;

        if !output.status.success() {
            last_err = format!(
                "{addr}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            continue;
        }

        let parsed: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(p) => p,
            Err(e) => {
                last_err = format!("{addr}: parse error: {e}");
                continue;
            }
        };

        let recovered_id = parsed["id"].as_str().unwrap_or_default();
        if recovered_id != peer_id {
            last_err = format!(
                "{addr}: handshake auth mismatch (got {recovered_id}, expected {peer_id})"
            );
            continue;
        }

        let features_hex = parsed["features"].as_str().map(String::from);

        // We've proven key possession via the handshake. Disconnect now —
        // staying peered is pointless and wastes a socket.
        let _ = std::process::Command::new("lightning-cli")
            .arg(format!("--lightning-dir={}", lightning_dir.display()))
            .arg("disconnect")
            .arg(peer_id)
            .output();

        return Ok(PeerConnectResult {
            verified_pubkey: recovered_id.to_string(),
            features_hex,
        });
    }

    bail!("peer_connect_failed: {last_err}");
}

/// Verify a Bitcoin message signature via `bitcoin-cli verifymessage`.
/// Supports any address format bitcoind supports (P2PKH legacy,
/// P2WPKH bech32 on recent versions). Returns Ok(true) only if the
/// signature was produced by the private key controlling the address.
fn verify_btc_signature(
    bitcoin_dir: &std::path::Path,
    btc_address: &str,
    signature: &str,
    message: &str,
) -> Result<bool> {
    let output = std::process::Command::new("bitcoin-cli")
        .arg(format!("-datadir={}", bitcoin_dir.display()))
        .arg("verifymessage")
        .arg(btc_address)
        .arg(signature)
        .arg(message)
        .output()
        .context("failed to run bitcoin-cli verifymessage")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("verifymessage failed: {stderr}");
    }

    // bitcoin-cli prints "true" or "false" on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim() == "true")
}

/// Check a UTXO via `bitcoin-cli gettxout`. Confirms it exists, is
/// unspent, matches the expected address, and meets the minimum
/// balance. Returns the actual balance in sats on success.
fn check_utxo(
    bitcoin_dir: &std::path::Path,
    txid: &str,
    vout: u32,
    expected_address: &str,
    min_balance_sat: u64,
) -> Result<u64> {
    let output = std::process::Command::new("bitcoin-cli")
        .arg(format!("-datadir={}", bitcoin_dir.display()))
        .arg("gettxout")
        .arg(txid)
        .arg(vout.to_string())
        .output()
        .context("failed to run bitcoin-cli gettxout")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gettxout failed: {stderr}");
    }

    let stdout_raw = output.stdout;
    // `gettxout` prints an empty response (just whitespace) for spent
    // or non-existent outputs.
    if stdout_raw.is_empty() || stdout_raw.iter().all(|b| b.is_ascii_whitespace()) {
        bail!("utxo_not_found: txid {txid}:{vout} is spent or does not exist");
    }

    let parsed: serde_json::Value =
        serde_json::from_slice(&stdout_raw).context("failed to parse gettxout output")?;

    // Check the scriptPubKey's address list contains the expected address.
    let empty_vec: Vec<serde_json::Value> = vec![];
    let addresses = parsed["scriptPubKey"]["addresses"]
        .as_array()
        .unwrap_or(&empty_vec);
    let address_str = parsed["scriptPubKey"]["address"]
        .as_str()
        .unwrap_or_default();
    let matches = address_str == expected_address
        || addresses
            .iter()
            .any(|a| a.as_str() == Some(expected_address));
    if !matches {
        bail!(
            "address_mismatch: UTXO pays to a different address than the claimed {expected_address}"
        );
    }

    // value is returned in BTC as a float; convert to sats.
    let value_btc = parsed["value"]
        .as_f64()
        .context("no value field in gettxout output")?;
    let value_sat = (value_btc * 100_000_000.0).round() as u64;

    if value_sat < min_balance_sat {
        bail!(
            "balance_below_threshold: UTXO holds {value_sat} sat, threshold is {min_balance_sat}"
        );
    }

    Ok(value_sat)
}

async fn connect(relays_csv: &str, keys: &Keys, proxy_url: Option<&str>) -> Result<Client> {
    let client = if let Some(proxy) = proxy_url {
        let addr: std::net::SocketAddr = proxy
            .parse()
            .with_context(|| format!("invalid proxy address '{proxy}' (want host:port, e.g. 127.0.0.1:9050)"))?;
        tracing::info!(proxy = %addr, "routing nostr traffic through SOCKS5 proxy");
        let connection = Connection::new().proxy(addr);
        let opts = ClientOptions::new().connection(connection);
        Client::builder()
            .signer(keys.clone())
            .opts(opts)
            .build()
    } else {
        Client::new(keys.clone())
    };
    for relay in relays_csv.split(',') {
        let relay = relay.trim();
        if !relay.is_empty() {
            client.add_relay(relay).await?;
        }
    }
    client.connect().await;
    Ok(client)
}
