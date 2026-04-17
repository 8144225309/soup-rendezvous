use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nostr::nips::nip44;
use nostr_sdk::prelude::*;
use tracing_subscriber::EnvFilter;

use soup_rendezvous::events;
use soup_rendezvous::kinds;

#[derive(Parser)]
#[command(
    name = "soup-rendezvous",
    version,
    about = "Coordination protocol for multi-party Bitcoin signing, built on Nostr."
)]
struct Cli {
    /// Path to the Nostr secret key file (nsec or hex).
    #[arg(long, env = "SOUP_KEY_FILE", default_value = "soup-coordinator.nsec")]
    key_file: PathBuf,

    /// Nostr relay URLs, comma-separated.
    #[arg(
        long,
        env = "SOUP_RELAYS",
        default_value = "wss://relay.damus.io,wss://nos.lol"
    )]
    relays: String,

    /// Path to CLN lightning-rpc directory (for checkmessage verification).
    #[arg(long, env = "SOUP_LIGHTNING_DIR")]
    lightning_dir: Option<PathBuf>,

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

    /// Publish a factory advertisement.
    TestAd {
        /// The root thread event ID (hex) to reply to.
        root_id: String,
        /// Human-readable factory name.
        #[arg(default_value = "test-factory-alpha")]
        name: String,
    },

    /// Publish a status update for a factory.
    UpdateStatus {
        /// The advertisement event ID (hex).
        ad_id: String,
        /// Number of accepted joiners.
        accepted: u32,
        /// Maximum members.
        max_members: u32,
        /// Status message.
        #[arg(default_value = "slots filling up")]
        message: String,
    },

    /// List advertisements and their activity from the relays.
    ListAds {
        /// Only show ads replying to this root event ID (hex).
        #[arg(long)]
        root_id: Option<String>,
        /// Only show ads created within this many days (default 30).
        #[arg(long, default_value_t = 30)]
        since_days: u64,
    },

    /// Join a factory (publish an encrypted attestation to the host).
    Join {
        /// The advertisement event ID (hex) to join.
        ad_id: String,
        /// Your CLN node pubkey (hex).
        #[arg(long, default_value = "03aabbccdd")]
        cln_pubkey: String,
        /// Your CLN node endpoint.
        #[arg(long, default_value = "127.0.0.1:9735")]
        cln_endpoint: String,
        /// Optional message to the host.
        #[arg(long, default_value = "requesting to join")]
        message: String,
    },

    /// Show a full cohort: ad, status updates, attestations, and seal.
    ShowCohort {
        /// The advertisement event ID (hex).
        ad_id: String,
    },

    /// (Host) Review encrypted attestations for your factory.
    ReviewJoins {
        /// The advertisement event ID (hex).
        ad_id: String,
    },

    /// Generate a proof-of-node challenge string.
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

    /// List vouches (verified LN node proofs) from the relays.
    ListVouches {
        /// Only show vouches from this coordinator (npub or hex).
        /// Defaults to own pubkey if not specified.
        #[arg(long)]
        coordinator: Option<String>,
    },

    /// (Host) Accept a joiner and send them a confirmation DM.
    Accept {
        /// The advertisement event ID (hex).
        ad_id: String,
        /// The joiner's Nostr pubkey (hex or npub) to accept.
        joiner_pubkey: String,
        /// Slot number to assign.
        #[arg(long)]
        slot: u32,
        /// Current accepted count (for status update).
        #[arg(long)]
        accepted: u32,
        /// Max members (for status update).
        #[arg(long)]
        max_members: u32,
    },

    /// (Host) Seal a factory with a list of accepted joiner npubs.
    Seal {
        /// The advertisement event ID (hex).
        ad_id: String,
        /// Comma-separated list of accepted joiner npubs or hex pubkeys.
        members: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,soup_rendezvous=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init => cmd_init(&cli.key_file),
        Command::Whoami => cmd_whoami(&cli.key_file),
        Command::PublishRoot { description } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_publish_root(&client, &description).await
        }
        Command::TestAd { root_id, name } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_test_ad(&client, &root_id, &name).await
        }
        Command::UpdateStatus {
            ad_id,
            accepted,
            max_members,
            message,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_update_status(&client, &ad_id, accepted, max_members, &message).await
        }
        Command::ListAds {
            root_id,
            since_days,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_list_ads(&client, root_id.as_deref(), since_days).await
        }
        Command::Join {
            ad_id,
            cln_pubkey,
            cln_endpoint,
            message,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_join(&client, &keys, &ad_id, &cln_pubkey, &cln_endpoint, &message).await
        }
        Command::ShowCohort { ad_id } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_show_cohort(&client, &keys, &ad_id).await
        }
        Command::ReviewJoins { ad_id } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_review_joins(&client, &keys, &ad_id).await
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
            let client = connect(&cli.relays, &keys).await?;
            cmd_vouch(
                &client,
                cli.lightning_dir.as_deref(),
                &host_pubkey,
                &node_id,
                &zbase,
                &challenge,
                channels,
                &capacity_sat,
            )
            .await
        }
        Command::ListVouches { coordinator } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_list_vouches(&client, &keys, coordinator.as_deref()).await
        }
        Command::Accept {
            ad_id,
            joiner_pubkey,
            slot,
            accepted,
            max_members,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_accept(
                &client,
                &keys,
                &ad_id,
                &joiner_pubkey,
                slot,
                accepted,
                max_members,
            )
            .await
        }
        Command::Seal { ad_id, members } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_seal(&client, &keys, &ad_id, &members).await
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
        "soup-rendezvous:proof-of-node:v0:{}:{}:{}",
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
    println!("  - message starts with soup-rendezvous:proof-of-node:v0:");
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
) -> Result<()> {
    let host_pk = if host_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(host_pubkey_str)?
    } else {
        PublicKey::from_hex(host_pubkey_str)?
    };

    // Validate the challenge format to prevent cross-protocol replay
    let coordinator_npub = client.signer().await?.get_public_key().await?.to_bech32()?;
    let parts: Vec<&str> = challenge.split(':').collect();
    if parts.len() != 6
        || parts[0] != "soup-rendezvous"
        || parts[1] != "proof-of-node"
        || parts[2] != "v0"
    {
        bail!(
            "invalid challenge format: must be soup-rendezvous:proof-of-node:v0:<npub>:<hex>:<ts>"
        );
    }
    if parts[3] != coordinator_npub {
        bail!(
            "challenge contains wrong coordinator npub: expected {}, got {}",
            coordinator_npub,
            parts[3]
        );
    }
    let challenge_ts: u64 = parts[5].parse().context("invalid timestamp in challenge")?;
    let now = Timestamp::now().as_secs();
    let skew = now.abs_diff(challenge_ts);
    if skew > 300 {
        bail!(
            "challenge expired: timestamp is {} seconds old (max 300)",
            skew
        );
    }

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

    // Publish the vouch event
    let builder = events::build_vouch(&host_pk, node_id, channels, capacity_sat);
    let output = client.send_event_builder(builder).await?;
    println!("vouch published");
    println!("  event id:    {}", output.id());
    println!("  host nostr:  {}", host_pk);
    println!("  ln node:     {}", node_id);
    println!("  channels:    {}", channels);
    println!("  capacity:    {} sat", capacity_sat);
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

async fn cmd_test_ad(client: &Client, root_id_hex: &str, name: &str) -> Result<()> {
    let root_id = EventId::from_hex(root_id_hex).context("invalid root event id hex")?;

    let payload = events::SuperScalarPayload {
        lsp_pubkey: "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        lsp_endpoints: vec!["127.0.0.1:9735".into()],
        lsp_nostr_relays: vec!["wss://relay.damus.io".into()],
        total_funding_sat: "10000000".into(),
        client_contribution_sat: "1000000".into(),
        lsp_liquidity_sat: "2000000".into(),
        leaf_arity: 2,
        epoch_count: 30,
        lifetime_blocks: 4320,
        dying_period_blocks: 432,
        lsp_fee_sat: "5000".into(),
        lsp_fee_ppm: 1000,
    };
    let content = serde_json::to_string_pretty(&payload)?;
    let expiry = Timestamp::now().as_secs() + 7 * 86400;

    let builder = events::build_advertisement(
        &root_id,
        name,
        "superscalar/v1",
        4,
        8,
        &["test", "development"],
        expiry,
        &content,
    );

    let output = client.send_event_builder(builder).await?;
    println!("advertisement published");
    println!("  event id: {}", output.id());
    println!("  name:     {name}");
    Ok(())
}

async fn cmd_update_status(
    client: &Client,
    ad_id_hex: &str,
    accepted: u32,
    max_members: u32,
    message: &str,
) -> Result<()> {
    let ad_id = EventId::from_hex(ad_id_hex).context("invalid ad event id hex")?;
    let builder = events::build_status_update(
        &ad_id,
        "superscalar/v1",
        if accepted >= max_members {
            "full"
        } else {
            "filling"
        },
        accepted,
        max_members,
        message,
    );
    let output = client.send_event_builder(builder).await?;
    println!("status update published");
    println!("  event id: {}", output.id());
    println!("  slots:    {accepted}/{max_members}");
    Ok(())
}

async fn cmd_list_ads(client: &Client, root_id_hex: Option<&str>, since_days: u64) -> Result<()> {
    let since_ts = Timestamp::from(
        Timestamp::now()
            .as_secs()
            .saturating_sub(since_days * 86400),
    );
    let mut filter = Filter::new().kind(kinds::ADVERTISEMENT).since(since_ts);
    if let Some(hex) = root_id_hex {
        let root_id = EventId::from_hex(hex).context("invalid root event id hex")?;
        filter = filter.event(root_id);
    }

    let ads = client.fetch_events(filter, Duration::from_secs(10)).await?;

    if ads.is_empty() {
        println!("no advertisements found");
        return Ok(());
    }

    println!("found {} advertisement(s):\n", ads.len());

    for ad in ads.iter() {
        let name = events::get_d_tag(ad).unwrap_or_else(|| "?".into());
        let scheme = events::get_tag_value(ad, "scheme").unwrap_or_else(|| "?".into());
        let slots = events::get_tag_value(ad, "slots").unwrap_or_else(|| "?/?".into());

        println!("  id:     {}", ad.id);
        println!("  name:   {name}");
        println!("  scheme: {scheme}");
        println!("  slots:  {slots}");
        println!("  author: {}", ad.pubkey);

        // Fetch status updates for this ad
        let status_filter = Filter::new().kind(kinds::STATUS_UPDATE).event(ad.id);
        let statuses = client
            .fetch_events(status_filter, Duration::from_secs(5))
            .await
            .unwrap_or_default();

        if !statuses.is_empty() {
            println!("  activity:");
            for status in statuses.iter() {
                let s_slots = events::get_tag_value(status, "slots").unwrap_or_else(|| "?".into());
                let s_status =
                    events::get_tag_value(status, "status").unwrap_or_else(|| "?".into());
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&status.content) {
                    let msg = parsed["message"].as_str().unwrap_or("");
                    println!("    [{s_status}] {s_slots} — {msg}");
                } else {
                    println!("    [{s_status}] {s_slots}");
                }
            }
        }

        // Count attestations
        let att_filter = Filter::new().kind(kinds::ATTESTATION).event(ad.id);
        let atts = client
            .fetch_events(att_filter, Duration::from_secs(5))
            .await
            .unwrap_or_default();
        if !atts.is_empty() {
            println!("  join requests: {}", atts.len());
        }

        // Check for seal
        let seal_filter = Filter::new().kind(kinds::SEAL).event(ad.id);
        let seals = client
            .fetch_events(seal_filter, Duration::from_secs(5))
            .await
            .unwrap_or_default();
        if !seals.is_empty() {
            println!("  SEALED");
        }

        println!();
    }

    Ok(())
}

async fn cmd_join(
    client: &Client,
    keys: &Keys,
    ad_id_hex: &str,
    cln_pubkey: &str,
    cln_endpoint: &str,
    message: &str,
) -> Result<()> {
    let ad_id = EventId::from_hex(ad_id_hex).context("invalid ad event id hex")?;

    // Fetch the advertisement to get the host's pubkey for encryption
    let ad_filter = Filter::new().kind(kinds::ADVERTISEMENT).id(ad_id);
    let ads = client
        .fetch_events(ad_filter, Duration::from_secs(10))
        .await?;
    let ad = ads
        .iter()
        .next()
        .context("advertisement not found on relays")?;
    let host_pubkey = ad.pubkey;

    // Build the attestation payload
    let payload = events::AttestationPayload {
        joiner_cln_pubkey: cln_pubkey.to_string(),
        joiner_cln_endpoint: cln_endpoint.to_string(),
        joiner_nostr_relays: vec!["wss://nos.lol".into()],
        nonce: hex::encode(&Keys::generate().secret_key().as_secret_bytes()[..16]),
        message: message.to_string(),
    };
    let payload_json = serde_json::to_string(&payload)?;

    // Encrypt the payload to the host using NIP-44
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &host_pubkey,
        &payload_json,
        nip44::Version::default(),
    )?;

    let expiry = Timestamp::now().as_secs() + 86400;

    // Build the attestation event with encrypted content
    let builder = EventBuilder::new(kinds::ATTESTATION, encrypted)
        .tag(Tag::event(ad_id))
        .tag(Tag::public_key(host_pubkey))
        .tag(Tag::custom(
            TagKind::custom("scheme"),
            vec!["superscalar/v1".to_string()],
        ))
        .tag(Tag::custom(
            TagKind::custom("expiry"),
            vec![expiry.to_string()],
        ))
        .tag(Tag::expiration(Timestamp::from(expiry)));

    let output = client.send_event_builder(builder).await?;
    println!("join request published (encrypted to host)");
    println!("  event id:    {}", output.id());
    println!("  factory:     {ad_id}");
    println!("  host pubkey: {host_pubkey}");
    Ok(())
}

async fn cmd_show_cohort(client: &Client, keys: &Keys, ad_id_hex: &str) -> Result<()> {
    let ad_id = EventId::from_hex(ad_id_hex).context("invalid ad event id hex")?;

    // Fetch ad
    let ad_filter = Filter::new().kind(kinds::ADVERTISEMENT).id(ad_id);
    let ads = client
        .fetch_events(ad_filter, Duration::from_secs(10))
        .await?;

    if let Some(ad) = ads.iter().next() {
        let name = events::get_d_tag(ad).unwrap_or_else(|| "?".into());
        println!("factory: {name}");
        println!("  id:     {}", ad.id);
        println!("  author: {}", ad.pubkey);
        println!();
    } else {
        println!("advertisement not found");
        return Ok(());
    }

    // Status updates
    let status_filter = Filter::new().kind(kinds::STATUS_UPDATE).event(ad_id);
    let statuses = client
        .fetch_events(status_filter, Duration::from_secs(5))
        .await
        .unwrap_or_default();

    if !statuses.is_empty() {
        println!("status updates:");
        for s in statuses.iter() {
            let slots = events::get_tag_value(s, "slots").unwrap_or_else(|| "?".into());
            let status = events::get_tag_value(s, "status").unwrap_or_else(|| "?".into());
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&s.content) {
                let msg = parsed["message"].as_str().unwrap_or("");
                println!("  [{status}] {slots} — {msg}");
            } else {
                println!("  [{status}] {slots}");
            }
        }
        println!();
    }

    // Attestations
    let att_filter = Filter::new().kind(kinds::ATTESTATION).event(ad_id);
    let atts = client
        .fetch_events(att_filter, Duration::from_secs(5))
        .await
        .unwrap_or_default();

    if !atts.is_empty() {
        println!("join requests ({}):", atts.len());
        for att in atts.iter() {
            print!("  from: {}  ", att.pubkey);
            // Try to decrypt if we're the host
            match nip44::decrypt(keys.secret_key(), &att.pubkey, &att.content) {
                Ok(plaintext) => {
                    if let Ok(payload) =
                        serde_json::from_str::<events::AttestationPayload>(&plaintext)
                    {
                        println!(
                            "cln={} msg=\"{}\"",
                            payload.joiner_cln_pubkey, payload.message
                        );
                    } else {
                        println!("(decrypted but couldn't parse)");
                    }
                }
                Err(_) => println!("(encrypted, not addressed to us)"),
            }
        }
        println!();
    }

    // Seal
    let seal_filter = Filter::new().kind(kinds::SEAL).event(ad_id);
    let seals = client
        .fetch_events(seal_filter, Duration::from_secs(5))
        .await
        .unwrap_or_default();

    if let Some(seal) = seals.iter().next() {
        println!("SEALED by {}", seal.pubkey);
        match nip44::decrypt(keys.secret_key(), &seal.pubkey, &seal.content) {
            Ok(plaintext) => {
                if let Ok(manifest) = serde_json::from_str::<events::SealManifest>(&plaintext) {
                    println!("  members:");
                    for m in &manifest.members {
                        println!(
                            "    slot {} — nostr={} cln={}",
                            m.slot, m.nostr_pubkey, m.cln_pubkey
                        );
                    }
                } else {
                    println!("  (decrypted but couldn't parse manifest)");
                }
            }
            Err(_) => println!("  (encrypted, not addressed to us)"),
        }
    } else {
        println!("not yet sealed");
    }

    Ok(())
}

async fn cmd_review_joins(client: &Client, keys: &Keys, ad_id_hex: &str) -> Result<()> {
    let ad_id = EventId::from_hex(ad_id_hex).context("invalid ad event id hex")?;

    let att_filter = Filter::new().kind(kinds::ATTESTATION).event(ad_id);
    let atts = client
        .fetch_events(att_filter, Duration::from_secs(10))
        .await?;

    if atts.is_empty() {
        println!("no join requests found for {ad_id}");
        return Ok(());
    }

    println!("join requests for {}:\n", ad_id);
    for att in atts.iter() {
        println!("  event:  {}", att.id);
        println!("  from:   {}", att.pubkey);
        match nip44::decrypt(keys.secret_key(), &att.pubkey, &att.content) {
            Ok(plaintext) => {
                if let Ok(payload) = serde_json::from_str::<events::AttestationPayload>(&plaintext)
                {
                    println!("  cln:    {}", payload.joiner_cln_pubkey);
                    println!("  endpt:  {}", payload.joiner_cln_endpoint);
                    println!("  msg:    {}", payload.message);
                } else {
                    println!("  (decrypted but payload didn't parse)");
                }
            }
            Err(_) => println!("  (could not decrypt — are you the host?)"),
        }
        println!();
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_accept(
    client: &Client,
    keys: &Keys,
    ad_id_hex: &str,
    joiner_pubkey_str: &str,
    slot: u32,
    accepted: u32,
    max_members: u32,
) -> Result<()> {
    let ad_id = EventId::from_hex(ad_id_hex).context("invalid ad event id hex")?;
    let joiner_pk = if joiner_pubkey_str.starts_with("npub") {
        PublicKey::from_bech32(joiner_pubkey_str)?
    } else {
        PublicKey::from_hex(joiner_pubkey_str)?
    };

    // Send encrypted acceptance DM to the joiner
    let acceptance = serde_json::json!({
        "type": "acceptance",
        "advertisement_id": ad_id_hex,
        "slot": slot,
        "message": format!("accepted into slot {slot}, factory will seal when all slots are filled"),
    });
    let encrypted = nip44::encrypt(
        keys.secret_key(),
        &joiner_pk,
        acceptance.to_string(),
        nip44::Version::default(),
    )?;

    let dm_builder = EventBuilder::new(Kind::Custom(4), encrypted)
        .tag(Tag::public_key(joiner_pk))
        .tag(Tag::event(ad_id));
    client.send_event_builder(dm_builder).await?;
    println!("acceptance DM sent to {}", joiner_pk);

    // Publish status update
    let status_msg = format!("{accepted} of {max_members} slots filled");
    let builder = events::build_status_update(
        &ad_id,
        "superscalar/v1",
        if accepted >= max_members {
            "full"
        } else {
            "filling"
        },
        accepted,
        max_members,
        &status_msg,
    );
    client.send_event_builder(builder).await?;
    println!("status update published: {accepted}/{max_members}");
    Ok(())
}

async fn cmd_seal(client: &Client, keys: &Keys, ad_id_hex: &str, members_csv: &str) -> Result<()> {
    let ad_id = EventId::from_hex(ad_id_hex).context("invalid ad event id hex")?;

    let member_pubkeys: Vec<PublicKey> = members_csv
        .split(',')
        .map(|s| {
            let s = s.trim();
            if s.starts_with("npub") {
                PublicKey::from_bech32(s).context("invalid npub")
            } else {
                PublicKey::from_hex(s).context("invalid hex pubkey")
            }
        })
        .collect::<Result<Vec<_>>>()?;

    let manifest = events::SealManifest {
        advertisement_id: ad_id_hex.to_string(),
        rules_hash: ad_id_hex.to_string(),
        members: member_pubkeys
            .iter()
            .enumerate()
            .map(|(i, pk)| events::SealMember {
                nostr_pubkey: pk.to_hex(),
                cln_pubkey: "unknown".into(),
                cln_endpoint: "unknown".into(),
                slot: i as u32,
            })
            .collect(),
        sealed_at: Timestamp::now().as_secs(),
    };

    let manifest_json = serde_json::to_string(&manifest)?;

    // Send encrypted seal to each member via NIP-44 DM
    for member_pk in &member_pubkeys {
        let encrypted = nip44::encrypt(
            keys.secret_key(),
            member_pk,
            &manifest_json,
            nip44::Version::default(),
        )?;

        let builder = EventBuilder::new(kinds::SEAL, encrypted)
            .tag(Tag::event(ad_id))
            .tag(Tag::public_key(*member_pk))
            .tag(Tag::custom(
                TagKind::custom("scheme"),
                vec!["superscalar/v1".to_string()],
            ));

        let output = client.send_event_builder(builder).await?;
        println!("seal sent to {}", member_pk);
        println!("  event id: {}", output.id());
    }

    // Publish a public status update marking the factory as sealed
    let builder = events::build_status_update(
        &ad_id,
        "superscalar/v1",
        "sealed",
        member_pubkeys.len() as u32,
        member_pubkeys.len() as u32,
        "factory sealed, ceremony can begin",
    );
    client.send_event_builder(builder).await?;
    println!("\nfactory sealed with {} members", member_pubkeys.len());

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

async fn connect(relays_csv: &str, keys: &Keys) -> Result<Client> {
    let client = Client::new(keys.clone());
    for relay in relays_csv.split(',') {
        let relay = relay.trim();
        if !relay.is_empty() {
            client.add_relay(relay).await?;
        }
    }
    client.connect().await;
    Ok(client)
}
